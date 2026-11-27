package osfs

import (
	"context"
	"errors"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/ports"
	"net"
	"os"
	"sync/atomic"
	"time"
)

const defaultSocketProbeTimeout = 2 * time.Second

// SocketProbeStatus 描述 ProbeStaleUnixSocket 的探活分类结果；零值 SocketProbeUnknown 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type SocketProbeStatus uint8

const (
	SocketProbeUnknown   SocketProbeStatus = iota // 探测未完成或异常（零值失败关闭）
	SocketProbeMissing                            // 目标路径不存在
	SocketProbeNotSocket                          // 存在但非本地 AF_UNIX 套接字
	SocketProbeLive                               // 存在且活跃监听进程响应连接
	SocketProbeStale                              // 确认为套接字且连接被明确拒绝（可安全清理）
)

// String 返回 SocketProbeStatus 的可读名称。
func (s SocketProbeStatus) String() string {
	names := [5]string{"unknown", "missing", "not_socket", "live", "stale"}
	return pickIf(int(s) < len(names), names[min(int(s), len(names)-1)], "unknown")
}

// IsValid 报告 s 是否为已判明的有效探测状态（零值 SocketProbeUnknown 返回 false）。
func (s SocketProbeStatus) IsValid() bool { return s >= SocketProbeMissing && s <= SocketProbeStale }

// PeerCred 表示经内核查询到的本地 AF_UNIX 连接对端身份凭据快照；零值恒无效。
//
//xops:opaque
//xops:failclosed
type PeerCred struct {
	uid, gid, pid                 uint32
	hasUID, hasGID, hasPID, valid bool
}

func credUint32(ok bool, v uint32) (uint32, bool) { return pickIf(ok, v, 0), ok }
func (c PeerCred) IsValid() bool                  { return c.valid }
func (c PeerCred) IsZero() bool                   { return !c.valid }
func (c PeerCred) HasUID() bool                   { return c.valid && c.hasUID }
func (c PeerCred) HasGID() bool                   { return c.valid && c.hasGID }
func (c PeerCred) HasPID() bool                   { return c.valid && c.hasPID }
func (c PeerCred) UID() (uint32, bool)            { return credUint32(c.valid && c.hasUID, c.uid) }
func (c PeerCred) GID() (uint32, bool)            { return credUint32(c.valid && c.hasGID, c.gid) }
func (c PeerCred) PID() (uint32, bool)            { return credUint32(c.valid && c.hasPID, c.pid) }
func (c PeerCred) Equal(o PeerCred) bool          { return c.valid && o.valid && c == o }

// QueryUnixPeerCred / VerifyUnixPeerCurrentUser 通过内核套接字选项查询或强校验对端身份（fail-closed）。
func QueryUnixPeerCred(c *net.UnixConn) (PeerCred, error) {
	return runPeerCredControl(c, queryPeerCredFD)
}
func VerifyUnixPeerCurrentUser(c *net.UnixConn) (PeerCred, error) {
	return runPeerCredControl(c, verifyPeerCurrentUserFD)
}

//xops:syncclosure
func runPeerCredControl(conn *net.UnixConn, op func(fd uintptr) (PeerCred, error)) (PeerCred, error) {
	if conn == nil {
		return PeerCred{}, errFieldNil(ports.ErrInvalidArgument, "unix_conn")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return PeerCred{}, wrapOp(ErrUnauthorizedPeer, err, "SyscallConn")
	}
	var cred PeerCred
	var opErr error
	if ctrlErr := rawConn.Control(func(fd uintptr) { cred, opErr = op(fd) }); ctrlErr != nil {
		return PeerCred{}, wrapOp(ErrUnauthorizedPeer, ctrlErr, "RawConn.Control")
	}
	return cred, opErr
}

// SocketSlotOptions 控制 WithSocketSlot 绑定本地 AF_UNIX 套接字时的冲突处置策略。
type SocketSlotOptions struct {
	ReplaceStale bool // 在目录锁内确证为 SocketProbeStale 后允许清理接管
}

// SocketSlot 表示 WithSocketSlot 在同步作用域内借出的独占本地 AF_UNIX 监听槽位（INV-A3）。
//
//xops:opaque
//xops:failclosed
type SocketSlot struct {
	path   ControlSocketPath
	ln     *net.UnixListener
	origID socketFileID
	active atomic.Bool
}

func (s *SocketSlot) IsActive() bool { return s != nil && s.active.Load() && s.ln != nil }
func (s *SocketSlot) Path() ControlSocketPath {
	if s == nil {
		return ControlSocketPath{}
	}
	return s.path
}
func (s *SocketSlot) Listener() net.Listener {
	if s == nil {
		return &borrowedUnixListener{}
	}
	return &borrowedUnixListener{ln: s.ln, active: &s.active}
}

// AcceptVerified 接受本地 AF_UNIX 连接并强制核验对端用户身份（失败立即关连并返回 ErrUnauthorizedPeer）。
func (s *SocketSlot) AcceptVerified() (*net.UnixConn, PeerCred, error) {
	if !s.IsActive() {
		return nil, PeerCred{}, ports.ErrHandleExpired
	}
	return verifyUnixConnPeer(s.ln.AcceptUnix())
}
func verifyUnixConnPeer(conn *net.UnixConn, err error) (*net.UnixConn, PeerCred, error) {
	if err != nil {
		return nil, PeerCred{}, mapOSError(err)
	}
	cred, err := VerifyUnixPeerCurrentUser(conn)
	if err != nil {
		_ = conn.Close()
		return nil, PeerCred{}, err
	}
	return conn, cred, nil
}
func validateSocketCtxPath(ctx context.Context, path ControlSocketPath) error {
	switch {
	case ctx == nil:
		return ports.ErrNilContext
	case !path.IsValid():
		return errField(ErrInvalidControlPath, "control_socket_path")
	default:
		return ctx.Err()
	}
}

// WithSocketSlot 在目录锁保护下独占绑定本地 AF_UNIX 套接字并在同步闭包内借出 SocketSlot；
// 退出时无条件按 INV-A3 固定顺序「加目录锁 -> 身份校验 -> unlink -> close -> 解锁」释放。
//
//xops:syncclosure
//xops:borrowed
func WithSocketSlot(ctx context.Context, path ControlSocketPath, opts SocketSlotOptions, fn func(slot *SocketSlot) error) (retErr error) {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if err := validateSocketCtxPath(ctx, path); err != nil {
		return err
	}
	var slot *SocketSlot
	if err := withSocketDirLockOS(ctx, path.Dir(), true, func() error {
		if err := prepareSocketSlotLocked(ctx, path, opts.ReplaceStale); err != nil {
			return err
		}
		ln, origID, err := listenSocketLockedOS(ctx, path)
		if err == nil {
			slot = &SocketSlot{path: path, ln: ln, origID: origID}
		}
		return err
	}); err != nil {
		return err
	}
	slot.active.Store(true)
	defer func() {
		slot.active.Store(false)
		retErr = errors.Join(retErr, releaseSocketSlot(slot.path, slot.origID, slot.ln))
	}()
	return fn(slot)
}
func releaseSocketSlot(path ControlSocketPath, origID socketFileID, uln *net.UnixListener) error {
	var unlinkErr, closeErr error
	closed := false
	lockErr := withSocketDirLockOS(context.Background(), path.Dir(), false, func() error {
		unlinkErr = unlinkSameSocket(path.NativePath(), origID)
		closeErr, closed = closeUnixListenerSafe(uln), true
		if unlinkErr != nil && isSocketUnlinkRetryableOS(unlinkErr) {
			unlinkErr = unlinkSameSocket(path.NativePath(), origID)
		}
		return nil
	})
	if !closed {
		closeErr = closeUnixListenerSafe(uln)
	}
	if errors.Is(lockErr, os.ErrNotExist) || errors.Is(lockErr, ports.ErrNotFound) {
		lockErr = nil
	}
	return errors.Join(lockErr, unlinkErr, closeErr)
}

// ProbeStaleUnixSocket 对本地 AF_UNIX 套接字执行 fail-closed 存活/陈旧探测。
func ProbeStaleUnixSocket(ctx context.Context, path ControlSocketPath) (SocketProbeStatus, error) {
	if err := validateSocketCtxPath(ctx, path); err != nil {
		return SocketProbeUnknown, err
	}
	origID, status, err := inspectSocketEntryOS(path.NativePath())
	if err != nil || status != SocketProbeUnknown {
		return status, err
	}
	probeCtx, cancel := ctx, func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		probeCtx, cancel = context.WithTimeout(ctx, defaultSocketProbeTimeout)
	}
	defer cancel()
	var dialer net.Dialer
	conn, dialErr := dialer.DialUnix(probeCtx, "unix", nil, &net.UnixAddr{Net: "unix", Name: path.NativePath()})
	switch {
	case dialErr == nil:
		_ = conn.Close()
		return SocketProbeLive, nil
	case errors.Is(dialErr, os.ErrNotExist):
		return SocketProbeMissing, nil
	case !isConnRefusedOS(dialErr):
		return SocketProbeUnknown, dialErr
	}
	currID, status, err := inspectSocketEntryOS(path.NativePath())
	if err != nil || status != SocketProbeUnknown {
		return status, err
	}
	return pickIf(sameSocketFileID(origID, currID), SocketProbeStale, SocketProbeUnknown), nil
}

// PruneStaleUnixSocket 在目录锁内复核并安全清理已确证过期的本地 AF_UNIX 套接字；父目录缺失时零副作用返回 Missing。
func PruneStaleUnixSocket(ctx context.Context, path ControlSocketPath) (SocketProbeStatus, error) {
	if err := validateSocketCtxPath(ctx, path); err != nil {
		return SocketProbeUnknown, err
	}
	if _, preStatus, preErr := inspectSocketEntryOS(path.NativePath()); preErr == nil && preStatus == SocketProbeMissing {
		return SocketProbeMissing, nil
	}
	status := SocketProbeUnknown
	err := withSocketDirLockOS(ctx, path.Dir(), false, func() (pErr error) {
		status, pErr = pruneLockedSocketEntry(ctx, path)
		return pErr
	})
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, ports.ErrNotFound) {
		return SocketProbeMissing, nil
	}
	return status, err
}

// DialUnixVerified 连接至经安全核验的本地 AF_UNIX 控制套接字并强制核验对端用户身份（fail-closed）。
func DialUnixVerified(ctx context.Context, path ControlSocketPath) (*net.UnixConn, PeerCred, error) {
	if err := validateSocketCtxPath(ctx, path); err != nil {
		return nil, PeerCred{}, err
	}
	if err := verifySocketTargetBeforeDialOS(path.NativePath()); err != nil {
		return nil, PeerCred{}, err
	}
	var dialer net.Dialer
	return verifyUnixConnPeer(dialer.DialUnix(ctx, "unix", nil, &net.UnixAddr{Net: "unix", Name: path.NativePath()}))
}
func prepareSocketSlotLocked(ctx context.Context, path ControlSocketPath, replaceStale bool) error {
	origID, status, err := inspectSocketEntryOS(path.NativePath())
	if err != nil || status == SocketProbeMissing {
		return err
	}
	if status == SocketProbeNotSocket {
		return domi18n.EF(ErrNotSocket, domi18n.KeyOSFSNotUnixSocket, domi18n.BoundStr("path", path.NativePath()))
	}
	if !replaceStale {
		return domi18n.EF(ErrSlotOccupied, domi18n.KeyOSFSSlotOccupiedAt, domi18n.BoundStr("path", path.NativePath()))
	}
	probed, pErr := ProbeStaleUnixSocket(ctx, path)
	if errors.Is(pErr, context.Canceled) || errors.Is(pErr, context.DeadlineExceeded) {
		return pErr
	}
	if pErr != nil || probed != SocketProbeStale {
		return domi18n.WrapS(ErrSlotOccupied, pErr, domi18n.KeyOSFSStaleProbeFailed, domi18n.BoundStr("path", path.NativePath()), domi18n.Str("status", probed.String()))
	}
	return unlinkSameSocket(path.NativePath(), origID)
}
func listenUnixNoAutoUnlink(ctx context.Context, addr string) (*net.UnixListener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", addr)
	if err != nil {
		return nil, pickIf(isAddrInUseOS(err) || errors.Is(err, os.ErrExist), wrapS(ErrSlotOccupied, err), mapOSError(err))
	}
	uln, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, errField(ErrNotSocket, "unix_listener")
	}
	uln.SetUnlinkOnClose(false)
	return uln, nil
}
func pruneLockedSocketEntry(ctx context.Context, path ControlSocketPath) (SocketProbeStatus, error) {
	if origID, st, err := inspectSocketEntryOS(path.NativePath()); err != nil || st != SocketProbeUnknown {
		return st, err
	} else if probed, pErr := ProbeStaleUnixSocket(ctx, path); pErr != nil || probed != SocketProbeStale {
		return probed, pErr
	} else if uErr := unlinkSameSocket(path.NativePath(), origID); uErr != nil {
		return SocketProbeUnknown, uErr
	}
	return SocketProbeStale, nil
}
func unlinkSameSocket(target string, origID socketFileID) error {
	if target == "" {
		return nil
	}
	if currID, status, err := inspectSocketEntryOS(target); err != nil || status != SocketProbeUnknown || !sameSocketFileID(origID, currID) {
		return err
	}
	err := os.Remove(target)
	return pickIf[error](err == nil || errors.Is(err, os.ErrNotExist), nil, mapOSError(err))
}
func cleanupSocketBind(uln *net.UnixListener, addr string, err error) error {
	_ = uln.Close()
	_ = os.Remove(addr)
	return err
}
func closeUnixListenerSafe(uln *net.UnixListener) error {
	if uln == nil {
		return nil
	}
	err := uln.Close()
	return pickIf[error](errors.Is(err, net.ErrClosed), nil, err)
}

type borrowedUnixListener struct {
	ln     *net.UnixListener
	active *atomic.Bool
}

func (b *borrowedUnixListener) isActive() bool {
	return b != nil && b.active != nil && b.active.Load() && b.ln != nil
}
func (b *borrowedUnixListener) Accept() (net.Conn, error) {
	if !b.isActive() {
		return nil, ports.ErrHandleExpired
	}
	// 与 AcceptVerified 同源 fail-closed 核验对端用户凭证，确保 net.Listener 视图绝无未授权接入旁路。
	conn, _, err := verifyUnixConnPeer(b.ln.AcceptUnix())
	if err != nil {
		return nil, err
	}
	return conn, nil
}
func (b *borrowedUnixListener) Close() error {
	if !b.isActive() {
		return ports.ErrHandleExpired
	}
	return b.ln.Close()
}
func (b *borrowedUnixListener) Addr() net.Addr {
	if b == nil || b.ln == nil {
		return &net.UnixAddr{Net: "unix"}
	}
	return b.ln.Addr()
}
