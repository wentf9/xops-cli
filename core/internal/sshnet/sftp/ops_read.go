package sftp

import (
	"context"
	"fmt"
	"io"
	"math"
	"slices"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// RealPath 经 SSH_FXP_REALPATH 解析远端规范路径并返回已校验的 pathalg.RemotePath。
func (c *Client) RealPath(ctx context.Context, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	if err := c.checkPathOp(ctx, p); err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	entry, err := c.singleNameOp(ctx, sshFXPRealpath, p.String())
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	return pathalg.ParseRemotePath(entry.filename)
}

// Stat 经 SSH_FXP_STAT（跟随符号链接）查询远端对象元信息快照。
func (c *Client) Stat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	return c.statPath(ctx, sshFXPStat, p)
}

// Lstat 经 SSH_FXP_LSTAT（不跟随符号链接）查询远端对象元信息快照。
func (c *Client) Lstat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	return c.statPath(ctx, sshFXPLstat, p)
}

func (c *Client) statPath(ctx context.Context, pktType byte, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	if err := c.checkPathOp(ctx, p); err != nil {
		return zeroVal[ports.RemoteFileStat](), err
	}
	attrs, err := c.attrsOp(ctx, pktType, appendString(nil, p.String()))
	if err != nil {
		return zeroVal[ports.RemoteFileStat](), err
	}
	return attrsToRemoteStat(p, attrs)
}

// ReadLink 经 SSH_FXP_READLINK 读取远端符号链接原始目标串；对非符号链接返回 ErrInvalidArgument。
func (c *Client) ReadLink(ctx context.Context, p pathalg.RemotePath) (string, error) {
	if err := c.checkPathOp(ctx, p); err != nil {
		return "", err
	}
	entry, err := c.singleNameOp(ctx, sshFXPReadlink, p.String())
	if err != nil {
		if isStatusCode(err, sshFXFailure) {
			if st, sErr := c.Lstat(ctx, p); sErr == nil && !st.IsSymlink() {
				return "", fmt.Errorf("%w: %q 不是符号链接", ports.ErrInvalidArgument, p.String())
			}
		}
		return "", err
	}
	return entry.filename, nil
}

// ReadDir 枚举远端目录直接子节点（过滤 "."/".." 并经 pathalg.RemoteName 严格校验，INV-B1）。
func (c *Client) ReadDir(ctx context.Context, dir pathalg.RemotePath) ([]ports.RemoteDirEntry, error) {
	if err := c.checkPathOp(ctx, dir); err != nil {
		return nil, err
	}
	handle, err := c.openDirHandle(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer c.closeHandle(ctx, handle)

	var out []ports.RemoteDirEntry
	for {
		batch, eof, err := c.readDirBatch(ctx, handle)
		if err != nil {
			return nil, err
		}
		if eof {
			break
		}
		if len(batch) == 0 {
			return nil, fmt.Errorf("%w: SSH_FXP_READDIR 返回空目录批次", ports.ErrCorruptData)
		}
		out, err = appendValidatedDirEntries(out, batch)
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(a, b ports.RemoteDirEntry) int { return a.Name().Compare(b.Name()) })
	return out, nil
}

func (c *Client) openDirHandle(ctx context.Context, dir pathalg.RemotePath) ([]byte, error) {
	respType, respBody, err := c.roundTrip(ctx, sshFXPOpendir, appendString(nil, dir.String()))
	if err != nil {
		return nil, err
	}
	if respType == sshFXPStatus {
		stErr := decodeStatus(respBody)
		if isStatusCode(stErr, sshFXFailure) {
			if st, sErr := c.Stat(ctx, dir); sErr == nil && !st.IsDir() {
				return nil, fmt.Errorf("%w: %q 不是目录", ports.ErrInvalidArgument, dir.String())
			}
		}
		return nil, stErr
	}
	if respType != sshFXPHandle {
		return nil, fmt.Errorf("%w: SSH_FXP_OPENDIR 期望 HANDLE，收到 %d", ports.ErrCorruptData, respType)
	}
	r := wireReader{buf: respBody}
	return r.readBytes()
}

func (c *Client) readDirBatch(ctx context.Context, handle []byte) ([]wireNameEntry, bool, error) {
	respType, respBody, err := c.roundTrip(ctx, sshFXPReaddir, appendBytes(nil, handle))
	if err != nil {
		return nil, false, err
	}
	if respType == sshFXPStatus {
		stErr := decodeStatus(respBody)
		if isStatusCode(stErr, sshFXEOF) {
			return nil, true, nil
		}
		return nil, false, stErr
	}
	if respType != sshFXPName {
		return nil, false, fmt.Errorf("%w: SSH_FXP_READDIR 期望 NAME/STATUS，收到 %d", ports.ErrCorruptData, respType)
	}
	entries, err := decodeNameList(respBody)
	return entries, false, err
}

func appendValidatedDirEntries(dst []ports.RemoteDirEntry, batch []wireNameEntry) ([]ports.RemoteDirEntry, error) {
	for _, item := range batch {
		if item.filename == "." || item.filename == ".." {
			continue
		}
		if len(dst) >= maxReadDirEntries {
			return nil, fmt.Errorf("%w: 远端目录条目数超过上限 %d", ports.ErrLimitExceeded, maxReadDirEntries)
		}
		rn, err := pathalg.ParseRemoteName(item.filename)
		if err != nil {
			return nil, fmt.Errorf("%w: 远端目录项名 %q 非法: %w", ports.ErrInvalidArgument, item.filename, err)
		}
		ent, err := wireEntryToRemoteDirEntry(rn, item.attrs)
		if err != nil {
			return nil, err
		}
		dst = append(dst, ent)
	}
	return dst, nil
}

func wireEntryToRemoteDirEntry(rn pathalg.RemoteName, a wireAttrs) (ports.RemoteDirEntry, error) {
	if a.size > math.MaxInt64 {
		return zeroVal[ports.RemoteDirEntry](), fmt.Errorf("%w: 远端目录项大小溢出 int64", ports.ErrLimitExceeded)
	}
	ft, fm := posixModeToRemote(a)
	return ports.NewRemoteDirEntry(ports.RemoteDirEntrySpec{
		Name:     rn,
		FileType: ft,
		Size:     int64(a.size),
		Mode:     fm,
		ModTime:  attrsModTime(a),
	})
}

// WithReadFile 在 limits 字节上限内非截断打开远端常规文件，经 SSH_FXP_FSTAT 校验类型与大小后
// 在同步作用域闭包内借出带运行时失效哨兵的有界流读取器。
//
//xops:syncclosure
//xops:borrowed
func (c *Client) WithReadFile(ctx context.Context, p pathalg.RemotePath, limits ports.ReadLimits, fn func(r io.Reader, size int64) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if err := c.checkOpen(ctx); err != nil {
		return err
	}
	if !limits.IsValid() {
		return ports.ErrInvalidReadLimits
	}
	if !p.IsValid() {
		return fmt.Errorf("%w: 无效远端路径", ports.ErrInvalidArgument)
	}
	handle, st, err := c.openRegularForRead(ctx, p)
	if err != nil {
		return err
	}
	defer c.closeHandle(ctx, handle)

	if st.Size() > limits.MaxBytes() {
		return fmt.Errorf("%w: 远端文件大小 %d 超出上限 %d", ports.ErrLimitExceeded, st.Size(), limits.MaxBytes())
	}
	sr := &sftpScopedReader{
		client:   c,
		ctx:      ctx,
		handle:   handle,
		maxBytes: limits.MaxBytes(),
	}
	defer sr.expired.Store(true)
	return fn(sr, st.Size())
}

// ReadChunk 从远端常规文件 p 的 offset 处读取至多 length 字节写入 dst；
// 读满返回 (length, nil)，遇 EOF 返回 (实际字节数, io.EOF)。
func (c *Client) ReadChunk(ctx context.Context, p pathalg.RemotePath, offset int64, dst io.Writer, length int64) (int64, error) {
	if err := c.checkPathOp(ctx, p); err != nil {
		return 0, err
	}
	if offset < 0 || length < 0 || dst == nil {
		return 0, fmt.Errorf("%w: ReadChunk 参数非法", ports.ErrInvalidArgument)
	}
	handle, _, err := c.openRegularForRead(ctx, p)
	if err != nil {
		return 0, err
	}
	defer c.closeHandle(ctx, handle)
	if length == 0 {
		return 0, nil
	}
	return c.streamReadChunk(ctx, handle, uint64(offset), dst, length)
}

func (c *Client) streamReadChunk(ctx context.Context, handle []byte, off uint64, dst io.Writer, length int64) (int64, error) {
	var total int64
	for total < length {
		want := min(int64(c.maxReadLen), length-total)
		chunk, eof, err := c.readHandleAt(ctx, handle, off+uint64(total), uint32(want))
		if err != nil {
			return total, err
		}
		if int64(len(chunk)) > want {
			return total, fmt.Errorf("%w: SSH_FXP_DATA 长度 %d 超过请求上限 %d", ports.ErrCorruptData, len(chunk), want)
		}
		written, wErr := writeChunkExact(dst, chunk)
		total += written
		if wErr != nil {
			return total, wErr
		}
		if eof || len(chunk) == 0 {
			return total, io.EOF
		}
	}
	return total, nil
}

func writeChunkExact(dst io.Writer, chunk []byte) (int64, error) {
	if len(chunk) == 0 {
		return 0, nil
	}
	n, err := dst.Write(chunk)
	if err != nil {
		return int64(n), err
	}
	if n != len(chunk) {
		return int64(n), io.ErrShortWrite
	}
	return int64(n), nil
}

// openRegularForRead 先经 SSH_FXP_STAT 预检拦截目录与 FIFO/设备（避免阻塞单线程 sftp-server），
// 再以只读非截断标志打开并立即执行 SSH_FXP_FSTAT 二次核验（防御 TOCTOU）。
func (c *Client) openRegularForRead(ctx context.Context, p pathalg.RemotePath) ([]byte, ports.RemoteFileStat, error) {
	preStat, err := c.Stat(ctx, p)
	if err != nil {
		return nil, zeroVal[ports.RemoteFileStat](), err
	}
	if preStat.IsDir() {
		return nil, zeroVal[ports.RemoteFileStat](), ports.ErrRemoteIsDir
	}
	if !preStat.IsRegular() {
		return nil, zeroVal[ports.RemoteFileStat](), ports.ErrNotRegularFile
	}
	handle, err := c.openHandle(ctx, p.String(), sshFXFRead, wireAttrs{})
	if err != nil {
		return nil, zeroVal[ports.RemoteFileStat](), err
	}
	attrs, err := c.fstatHandle(ctx, handle)
	if err != nil {
		c.closeHandle(ctx, handle)
		return nil, zeroVal[ports.RemoteFileStat](), err
	}
	st, err := attrsToRemoteStat(p, attrs)
	if err != nil {
		c.closeHandle(ctx, handle)
		return nil, zeroVal[ports.RemoteFileStat](), err
	}
	if st.IsDir() {
		c.closeHandle(ctx, handle)
		return nil, zeroVal[ports.RemoteFileStat](), ports.ErrRemoteIsDir
	}
	if !st.IsRegular() {
		c.closeHandle(ctx, handle)
		return nil, zeroVal[ports.RemoteFileStat](), ports.ErrNotRegularFile
	}
	return handle, st, nil
}

type sftpScopedReader struct {
	client    *Client
	ctx       context.Context
	handle    []byte
	offset    uint64
	readSoFar int64
	maxBytes  int64
	buf       []byte
	eof       bool
	expired   atomic.Bool
}

func (sr *sftpScopedReader) Read(p []byte) (int, error) {
	if sr == nil || sr.expired.Load() {
		return 0, ports.ErrHandleExpired
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(sr.buf) > 0 {
		n := copy(p, sr.buf)
		sr.buf = sr.buf[n:]
		return n, nil
	}
	if sr.eof {
		return 0, io.EOF
	}
	remBudget := sr.maxBytes - sr.readSoFar
	// 多探读 1 字节以捕获读取期间远端文件并发增长超出 limits.MaxBytes() 的情形。
	want := min(int64(sr.client.maxReadLen), remBudget+1)
	chunk, eof, err := sr.client.readHandleAt(sr.ctx, sr.handle, sr.offset, uint32(want))
	if err != nil {
		return 0, err
	}
	if eof || len(chunk) == 0 {
		sr.eof = true
		return 0, io.EOF
	}
	sr.offset += uint64(len(chunk))
	if sr.readSoFar+int64(len(chunk)) > sr.maxBytes {
		return 0, fmt.Errorf("%w: 远端流读取期间超出 ReadLimits 上限 %d", ports.ErrLimitExceeded, sr.maxBytes)
	}
	sr.readSoFar += int64(len(chunk))
	n := copy(p, chunk)
	if n < len(chunk) {
		sr.buf = chunk[n:]
	}
	return n, nil
}

func (c *Client) checkPathOp(ctx context.Context, p pathalg.RemotePath) error {
	if err := c.checkOpen(ctx); err != nil {
		return err
	}
	if !p.IsValid() {
		return fmt.Errorf("%w: 无效远端路径", ports.ErrInvalidArgument)
	}
	return nil
}

func (c *Client) singleNameOp(ctx context.Context, pktType byte, rawPath string) (wireNameEntry, error) {
	respType, respBody, err := c.roundTrip(ctx, pktType, appendString(nil, rawPath))
	if err != nil {
		return wireNameEntry{}, err
	}
	if respType == sshFXPStatus {
		return wireNameEntry{}, decodeStatus(respBody)
	}
	if respType != sshFXPName {
		return wireNameEntry{}, fmt.Errorf("%w: SFTP 期望 NAME，收到类型 %d", ports.ErrCorruptData, respType)
	}
	entries, err := decodeNameList(respBody)
	if err != nil {
		return wireNameEntry{}, err
	}
	if len(entries) == 0 {
		return wireNameEntry{}, fmt.Errorf("%w: SFTP NAME 响应为空", ports.ErrCorruptData)
	}
	return entries[0], nil
}

func (c *Client) attrsOp(ctx context.Context, pktType byte, body []byte) (wireAttrs, error) {
	respType, respBody, err := c.roundTrip(ctx, pktType, body)
	if err != nil {
		return wireAttrs{}, err
	}
	if respType == sshFXPStatus {
		return wireAttrs{}, decodeStatus(respBody)
	}
	if respType != sshFXPAttrs {
		return wireAttrs{}, fmt.Errorf("%w: SFTP 期望 ATTRS，收到类型 %d", ports.ErrCorruptData, respType)
	}
	r := wireReader{buf: respBody}
	return decodeAttrs(&r)
}

func (c *Client) openHandle(ctx context.Context, rawPath string, pflags uint32, attrs wireAttrs) ([]byte, error) {
	body := appendString(nil, rawPath)
	body = appendUint32(body, pflags)
	body = appendAttrs(body, attrs)
	respType, respBody, err := c.roundTrip(ctx, sshFXPOpen, body)
	if err != nil {
		return nil, err
	}
	if respType == sshFXPStatus {
		return nil, decodeStatus(respBody)
	}
	if respType != sshFXPHandle {
		return nil, fmt.Errorf("%w: SSH_FXP_OPEN 期望 HANDLE，收到类型 %d", ports.ErrCorruptData, respType)
	}
	r := wireReader{buf: respBody}
	return r.readBytes()
}

func (c *Client) fstatHandle(ctx context.Context, handle []byte) (wireAttrs, error) {
	return c.attrsOp(ctx, sshFXPFstat, appendBytes(nil, handle))
}

func (c *Client) readHandleAt(ctx context.Context, handle []byte, offset uint64, length uint32) ([]byte, bool, error) {
	body := appendBytes(nil, handle)
	body = appendUint64(body, offset)
	body = appendUint32(body, length)
	respType, respBody, err := c.roundTrip(ctx, sshFXPRead, body)
	if err != nil {
		return nil, false, err
	}
	if respType == sshFXPStatus {
		stErr := decodeStatus(respBody)
		if isStatusCode(stErr, sshFXEOF) {
			return nil, true, nil
		}
		return nil, false, stErr
	}
	if respType != sshFXPData {
		return nil, false, fmt.Errorf("%w: SSH_FXP_READ 期望 DATA/STATUS，收到类型 %d", ports.ErrCorruptData, respType)
	}
	r := wireReader{buf: respBody}
	data, err := r.readBytes()
	return data, false, err
}
