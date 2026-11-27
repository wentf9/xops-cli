package sftp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/ports"
)

type sftpReply struct {
	pktType byte
	payload []byte
	err     error
}

// Client 实现 ports.RemoteFSPort 的纯 Go SFTP v3 客户端适配器；零值恒失败关闭。
// 所有后台读循环与上游断连监督均受 lifeNursery 托管（0 裸 go），Close 幂等且零泄漏收敛。
//
//xops:opaque
//xops:failclosed
type Client struct {
	rw          io.ReadWriteCloser
	entropy     ports.Entropy
	lifeNursery *conc.Nursery
	maxReadLen  int
	maxWriteLen int

	hasPosixRename bool
	hasHardlink    bool
	hasFsync       bool
	hasLimits      bool

	writeMu sync.Mutex
	nextID  atomic.Uint32

	pendMu   sync.Mutex
	pending  map[uint32]chan sftpReply
	closedCh chan struct{}
	readErr  error

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	valid     bool
}

func newClient(ctx context.Context, rw io.ReadWriteCloser, cfg Config) (*Client, error) {
	exts, err := performHandshake(ctx, rw)
	if err != nil {
		return nil, err
	}
	lifeN, err := conc.NewNursery(context.Background())
	if err != nil {
		return nil, err
	}
	chunk := clampChunkSize(cfg.MaxPacketSize)
	c := &Client{
		rw:             rw,
		entropy:        cfg.Entropy,
		lifeNursery:    lifeN,
		maxReadLen:     chunk,
		maxWriteLen:    chunk,
		hasPosixRename: exts[extPosixRename] == "1",
		hasHardlink:    exts[extHardlink] == "1",
		hasFsync:       exts[extFsync] == "1",
		hasLimits:      exts[extLimits] == "1",
		pending:        make(map[uint32]chan sftpReply),
		closedCh:       make(chan struct{}),
		valid:          true,
	}
	if err := c.startWorkers(cfg.WaitDone); err != nil {
		_ = c.Close()
		return nil, err
	}
	if c.hasLimits && cfg.MaxPacketSize <= 0 {
		if err := c.negotiateServerLimits(ctx); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	return c, nil
}

func (c *Client) startWorkers(waitDone <-chan struct{}) error {
	if err := c.lifeNursery.Go(func(context.Context) error {
		c.readLoop()
		return nil
	}); err != nil {
		return ports.ErrClosed
	}
	if waitDone != nil {
		if err := c.lifeNursery.Go(func(nCtx context.Context) error {
			select {
			case <-waitDone:
				c.failAllPending(ports.ErrClosed)
				_ = c.rw.Close()
			case <-c.closedCh:
			case <-nCtx.Done():
			}
			return nil
		}); err != nil {
			return ports.ErrClosed
		}
	}
	return nil
}

// performHandshake 在启动后台读循环前同步完成 SSH_FXP_INIT -> SSH_FXP_VERSION 协商，
// 并经 chanconn.RunWithAbortWatchdog 保证上下文取消或黑洞对端时立即关闭流解阻。
func performHandshake(ctx context.Context, rw io.ReadWriteCloser) (map[string]string, error) {
	var exts map[string]string
	err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = rw.Close() }, func() error {
		initPkt := make([]byte, 9)
		binary.BigEndian.PutUint32(initPkt[0:4], 5)
		initPkt[4] = sshFXPInit
		binary.BigEndian.PutUint32(initPkt[5:9], sftpProtocolVersion)
		if err := writeFull(rw, initPkt); err != nil {
			return err
		}
		pktType, body, err := readRawPacket(rw)
		if err != nil {
			return err
		}
		if pktType != sshFXPVersion {
			return domi18n.EF(ports.ErrCorruptData, domi18n.KeySFTPUnexpectedPacket, domi18n.Uint64("actual", uint64(pktType)), domi18n.Str("expected", "SSH_FXP_VERSION"))
		}
		parsed, err := decodeVersionPacket(body)
		if err != nil {
			return err
		}
		exts = parsed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return exts, nil
}

func decodeVersionPacket(body []byte) (map[string]string, error) {
	r := wireReader{buf: body}
	ver, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if ver != sftpProtocolVersion {
		return nil, domi18n.EF(ports.ErrUnsupported, domi18n.KeySFTPProtoVersion, domi18n.Uint64("version", uint64(ver)))
	}
	exts := make(map[string]string)
	for r.remaining() > 0 {
		name, err := r.readString()
		if err != nil {
			return nil, err
		}
		data, err := r.readString()
		if err != nil {
			return nil, err
		}
		exts[name] = data
	}
	return exts, nil
}

// negotiateServerLimits 尽力查询 OpenSSH limits@openssh.com 以对齐服务端单包读写上限；
// 若协商期间发生传输/协议损坏或上下文取消（roundTrip 返回非 nil 错误），立即向上返回由调用方关闭 Client（绝不返回已死亡的 Client）；
// 服务端明确以非 EXTENDED_REPLY 响应（如 SSH_FX_OP_UNSUPPORTED）或回复载荷畸形时静默保留安全默认值（32 KiB）。
func (c *Client) negotiateServerLimits(ctx context.Context) error {
	payload := appendString(nil, extLimits)
	pktType, body, err := c.roundTrip(ctx, sshFXPExtended, payload)
	if err != nil {
		return err
	}
	if pktType != sshFXPExtendedReply {
		return nil
	}
	r := wireReader{buf: body}
	_, e1 := r.readUint64() // max-packet-len
	maxRead, e2 := r.readUint64()
	maxWrite, e3 := r.readUint64()
	if e1 != nil || e2 != nil || e3 != nil {
		return nil
	}
	if maxRead > 0 {
		c.maxReadLen = clampChunkSize(int(min(maxRead, uint64(maxChunkBytes))))
	}
	if maxWrite > 0 {
		c.maxWriteLen = clampChunkSize(int(min(maxWrite, uint64(maxChunkBytes))))
	}
	return nil
}

// Close 幂等关闭底层 SFTP 子系统流、唤醒全部在途请求并同步排空后台监督协程（零泄漏）。
func (c *Client) Close() error {
	if c == nil || !c.valid {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.failAllPending(ports.ErrClosed)
		rwErr := c.rw.Close()
		if errors.Is(rwErr, io.EOF) || errors.Is(rwErr, net.ErrClosed) {
			rwErr = nil
		}
		nErr := c.lifeNursery.Close()
		c.closeErr = errors.Join(rwErr, nErr)
	})
	return c.closeErr
}

func (c *Client) checkOpen(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil || !c.valid || c.closed.Load() {
		return ports.ErrClosed
	}
	return nil
}

func (c *Client) readLoop() {
	for {
		pktType, body, err := readRawPacket(c.rw)
		if err != nil {
			c.failAllPending(mapReadLoopErr(err))
			return
		}
		if len(body) < 4 {
			c.failAllPending(domi18n.EF(ports.ErrCorruptData, domi18n.KeySFTPPacketTruncated))
			return
		}
		reqID := binary.BigEndian.Uint32(body[:4])
		c.deliverReply(reqID, sftpReply{pktType: pktType, payload: body[4:]})
	}
}

func mapReadLoopErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return ports.ErrClosed
	}
	return err
}

func (c *Client) deliverReply(reqID uint32, rep sftpReply) {
	c.pendMu.Lock()
	ch, ok := c.pending[reqID]
	if ok {
		delete(c.pending, reqID)
	}
	c.pendMu.Unlock()
	if ok {
		ch <- rep
	}
}

func (c *Client) failAllPending(err error) {
	c.pendMu.Lock()
	if c.readErr == nil {
		c.readErr = err
		close(c.closedCh)
	}
	pending := c.pending
	c.pending = nil
	c.pendMu.Unlock()
	for _, ch := range pending {
		ch <- sftpReply{err: err}
	}
}

func (c *Client) registerPending(reqID uint32) (chan sftpReply, error) {
	c.pendMu.Lock()
	defer c.pendMu.Unlock()
	if c.pending == nil {
		if c.readErr != nil {
			return nil, c.readErr
		}
		return nil, ports.ErrClosed
	}
	ch := make(chan sftpReply, 1)
	c.pending[reqID] = ch
	return ch, nil
}

func (c *Client) unregisterPending(reqID uint32) {
	c.pendMu.Lock()
	if c.pending != nil {
		delete(c.pending, reqID)
	}
	c.pendMu.Unlock()
}

// roundTrip 发送单个带 reqID 的 SFTP 请求并在 ctx / closedCh 监督下等待配对响应。
func (c *Client) roundTrip(ctx context.Context, pktType byte, bodyWithoutID []byte) (byte, []byte, error) {
	if err := c.checkOpen(ctx); err != nil {
		return 0, nil, err
	}
	reqID := c.nextID.Add(1)
	ch, err := c.registerPending(reqID)
	if err != nil {
		return 0, nil, err
	}
	if err := c.writeRequestPacket(ctx, pktType, reqID, bodyWithoutID); err != nil {
		c.unregisterPending(reqID)
		return 0, nil, err
	}
	select {
	case rep := <-ch:
		if rep.err != nil {
			return 0, nil, rep.err
		}
		return rep.pktType, rep.payload, nil
	case <-c.closedCh:
		c.unregisterPending(reqID)
		return 0, nil, c.closedError()
	case <-ctx.Done():
		c.unregisterPending(reqID)
		return 0, nil, ctx.Err()
	}
}

func (c *Client) closedError() error {
	c.pendMu.Lock()
	err := c.readErr
	c.pendMu.Unlock()
	if err != nil {
		return err
	}
	return ports.ErrClosed
}

// writeRequestPacket 串行写入完整帧；若写入期间上下文取消则关闭流避免半帧破坏协议同步。
func (c *Client) writeRequestPacket(ctx context.Context, pktType byte, reqID uint32, bodyWithoutID []byte) error {
	pktLen := 1 + 4 + len(bodyWithoutID)
	frame := make([]byte, 4+pktLen)
	binary.BigEndian.PutUint32(frame[0:4], uint32(pktLen))
	frame[4] = pktType
	binary.BigEndian.PutUint32(frame[5:9], reqID)
	copy(frame[9:], bodyWithoutID)

	return chanconn.RunWithAbortWatchdog(ctx, func() {
		c.failAllPending(ports.ErrClosed)
		_ = c.rw.Close()
	}, func() error {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		if c.closed.Load() {
			return ports.ErrClosed
		}
		return writeFull(c.rw, frame)
	})
}

func readRawPacket(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	pktLen := binary.BigEndian.Uint32(hdr[:])
	if pktLen < 1 || pktLen > maxInboundPacketBytes {
		return 0, nil, domi18n.EF(ports.ErrCorruptData, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "sftp_packet_length"), domi18n.Uint64("value", uint64(pktLen)))
	}
	buf := make([]byte, pktLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (c *Client) expectStatusOK(ctx context.Context, pktType byte, body []byte) error {
	respType, respBody, err := c.roundTrip(ctx, pktType, body)
	if err != nil {
		return err
	}
	if respType != sshFXPStatus {
		return domi18n.EF(ports.ErrCorruptData, domi18n.KeySFTPUnexpectedPacket, domi18n.Uint64("actual", uint64(respType)), domi18n.Str("expected", "SSH_FXP_STATUS"))
	}
	return decodeStatus(respBody)
}

const (
	cleanupTimeoutNormal   = 500 * time.Millisecond
	cleanupTimeoutCanceled = 50 * time.Millisecond
)

// cleanupContext 为延迟释放远端句柄或清理临时文件构造有界上下文，防止黑洞对端导致 defer 永久阻塞。
func cleanupContext(parentCtx context.Context) (context.Context, context.CancelFunc) {
	timeout := cleanupTimeoutNormal
	if parentCtx != nil && parentCtx.Err() != nil {
		timeout = cleanupTimeoutCanceled
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (c *Client) closeHandle(parentCtx context.Context, handle []byte) {
	if len(handle) == 0 || c.closed.Load() {
		return
	}
	cCtx, cancel := cleanupContext(parentCtx)
	defer cancel()
	body := appendBytes(nil, handle)
	_, _, _ = c.roundTrip(cCtx, sshFXPClose, body)
}
