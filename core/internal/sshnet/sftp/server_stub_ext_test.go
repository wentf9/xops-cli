package sftp_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/sftp"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期契约断言：确保 sftp.Client 严格满足 ports.RemoteFSPort。
var _ ports.RemoteFSPort = (*sftp.Client)(nil)

func TestSFTP_FactorySignatureContract(t *testing.T) {
	var fn dial.RemoteFSFactory = sftp.Open
	if fn == nil {
		t.Fatal("sftp.Open 不能为 nil")
	}
}

// SFTP v3 测试服务端协议常量（独立定义于外置测试包以端到端校验线缆编解码）。
const (
	fxpInit          byte = 1
	fxpVersion       byte = 2
	fxpOpen          byte = 3
	fxpClose         byte = 4
	fxpRead          byte = 5
	fxpWrite         byte = 6
	fxpLstat         byte = 7
	fxpFstat         byte = 8
	fxpSetstat       byte = 9
	fxpFsetstat      byte = 10
	fxpOpendir       byte = 11
	fxpReaddir       byte = 12
	fxpRemove        byte = 13
	fxpMkdir         byte = 14
	fxpRmdir         byte = 15
	fxpRealpath      byte = 16
	fxpStat          byte = 17
	fxpRename        byte = 18
	fxpReadlink      byte = 19
	fxpStatus        byte = 101
	fxpHandle        byte = 102
	fxpData          byte = 103
	fxpName          byte = 104
	fxpAttrs         byte = 105
	fxpExtended      byte = 200
	fxpExtendedReply byte = 201

	fxOK          uint32 = 0
	fxEOF         uint32 = 1
	fxNoSuchFile  uint32 = 2
	fxPermDenied  uint32 = 3
	fxFailure     uint32 = 4
	fxUnsupported uint32 = 8

	fxfWrite uint32 = 0x02
	fxfCreat uint32 = 0x08
	fxfTrunc uint32 = 0x10
	fxfExcl  uint32 = 0x20
)

type memSFTPNode struct {
	kind   ports.RemoteFileType
	perm   uint32
	data   []byte
	target string
	atime  uint32
	mtime  uint32
	dev    uint64
	ino    uint64
}

type memSFTPHandle struct {
	path     string
	node     *memSFTPNode
	isDir    bool
	dirRead  bool
	writable bool
}

type stubSFTPServerOpts struct {
	emitDevIno              bool
	disablePosix            bool
	disableHardlnk          bool
	disableLimits           bool
	blackholeAfter          int
	growOnSecondRd          bool
	swapTargetOnTmp         string
	protoVersion            uint32
	failHardlinkUnsupported bool
	emptyReadDirOnce        bool
	oversizedRead           bool
}

// stubSFTPServer 实现进程内纯内存 POSIX SFTP v3 服务端桩，用于完整验证线缆协议、FSTAT 锚定、
// 原子重命名、扩展协商与黑洞取消场景（0 外部二进制依赖、0 path/filepath 依赖）。
type stubSFTPServer struct {
	opts      stubSFTPServerOpts
	mu        sync.Mutex
	nextIno   uint64
	nextHnd   uint64
	nodes     map[string]*memSFTPNode
	handles   map[string]*memSFTPHandle
	reqSeen   int
	truncOp   bool
	openPaths []string
}

func newStubSFTPServer(opts stubSFTPServerOpts) *stubSFTPServer {
	now := uint32(time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC).Unix())
	return &stubSFTPServer{
		opts:    opts,
		nextIno: 10,
		nodes: map[string]*memSFTPNode{
			"/": {kind: ports.RemoteFileDir, perm: 0o040755, atime: now, mtime: now, dev: 7, ino: 1},
		},
		handles: make(map[string]*memSFTPHandle),
	}
}

func (s *stubSFTPServer) putSymlink(linkPath, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextIno++
	now := uint32(time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC).Unix())
	s.nodes[path.Clean(linkPath)] = &memSFTPNode{
		kind: ports.RemoteFileSymlink, perm: 0o120777, target: target, atime: now, mtime: now, dev: 7, ino: s.nextIno,
	}
}

func (s *stubSFTPServer) putRegularFile(filePath string, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextIno++
	now := uint32(time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC).Unix())
	s.nodes[path.Clean(filePath)] = &memSFTPNode{
		kind: ports.RemoteFileRegular, perm: 0o100644, data: append([]byte(nil), content...),
		atime: now, mtime: now, dev: 7, ino: s.nextIno,
	}
}

func (s *stubSFTPServer) putFIFO(fifoPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextIno++
	now := uint32(time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC).Unix())
	s.nodes[path.Clean(fifoPath)] = &memSFTPNode{
		kind: ports.RemoteFileOther, perm: 0o010600,
		atime: now, mtime: now, dev: 7, ino: s.nextIno,
	}
}

func (s *stubSFTPServer) openedPath(target string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.openPaths, path.Clean(target))
}

func (s *stubSFTPServer) sawTruncOpen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.truncOp
}

func (s *stubSFTPServer) serve(rw io.ReadWriteCloser) {
	defer func() { _ = rw.Close() }()
	pktType, body, err := readTestPkt(rw)
	if err != nil || pktType != fxpInit || len(body) < 4 {
		return
	}
	if err := s.writeVersion(rw); err != nil {
		return
	}
	for {
		pktType, body, err := readTestPkt(rw)
		if err != nil {
			return
		}
		if len(body) < 4 {
			return
		}
		s.mu.Lock()
		s.reqSeen++
		shouldHang := s.opts.blackholeAfter > 0 && s.reqSeen >= s.opts.blackholeAfter
		s.mu.Unlock()
		if shouldHang {
			// 黑洞对端：读尽后续数据但绝不回包，直至调用方关闭流。
			_, _ = io.Copy(io.Discard, rw)
			return
		}
		reqID := binary.BigEndian.Uint32(body[:4])
		respType, respBody := s.dispatch(pktType, reqID, body[4:])
		if err := writeTestPkt(rw, respType, respBody); err != nil {
			return
		}
	}
}

func (s *stubSFTPServer) writeVersion(w io.Writer) error {
	ver := s.opts.protoVersion
	if ver == 0 {
		ver = 3
	}
	var b []byte
	b = binary.BigEndian.AppendUint32(b, ver)
	if !s.opts.disablePosix {
		b = appendTestStr(appendTestStr(b, "posix-rename@openssh.com"), "1")
	}
	if !s.opts.disableHardlnk {
		b = appendTestStr(appendTestStr(b, "hardlink@openssh.com"), "1")
	}
	b = appendTestStr(appendTestStr(b, "fsync@openssh.com"), "1")
	if !s.opts.disableLimits {
		b = appendTestStr(appendTestStr(b, "limits@openssh.com"), "1")
	}
	return writeTestPkt(w, fxpVersion, b)
}

func (s *stubSFTPServer) dispatch(pktType byte, reqID uint32, body []byte) (byte, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch pktType {
	case fxpRealpath:
		return s.handleRealpath(reqID, body)
	case fxpStat:
		return s.handleStat(reqID, body, true)
	case fxpLstat:
		return s.handleStat(reqID, body, false)
	case fxpFstat:
		return s.handleFstat(reqID, body)
	case fxpReadlink:
		return s.handleReadlink(reqID, body)
	case fxpOpendir:
		return s.handleOpendir(reqID, body)
	case fxpReaddir:
		return s.handleReaddir(reqID, body)
	case fxpOpen:
		return s.handleOpen(reqID, body)
	case fxpClose:
		return s.handleClose(reqID, body)
	case fxpRead:
		return s.handleRead(reqID, body)
	case fxpWrite:
		return s.handleWrite(reqID, body)
	case fxpSetstat:
		return s.handleSetstat(reqID, body)
	case fxpFsetstat:
		return s.handleFsetstat(reqID, body)
	case fxpMkdir:
		return s.handleMkdir(reqID, body)
	case fxpRemove:
		return s.handleRemove(reqID, body)
	case fxpRmdir:
		return s.handleRmdir(reqID, body)
	case fxpRename:
		return s.handleRename(reqID, body, false)
	case fxpExtended:
		return s.handleExtended(reqID, body)
	default:
		return buildStatusPkt(reqID, fxUnsupported, "unsupported")
	}
}

func (s *stubSFTPServer) resolveNode(raw string, followLeaf bool) (string, *memSFTPNode) {
	clean := path.Clean("/" + strings.TrimPrefix(raw, "/"))
	nd := s.nodes[clean]
	if nd == nil || !followLeaf {
		return clean, nd
	}
	for hops := 0; hops < 16 && nd != nil && nd.kind == ports.RemoteFileSymlink; hops++ {
		if strings.HasPrefix(nd.target, "/") {
			clean = path.Clean(nd.target)
		} else {
			clean = path.Clean(path.Join(path.Dir(clean), nd.target))
		}
		nd = s.nodes[clean]
	}
	return clean, nd
}

func (s *stubSFTPServer) handleRealpath(reqID uint32, body []byte) (byte, []byte) {
	p, _, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad path")
	}
	clean, nd := s.resolveNode(p, true)
	if nd == nil {
		return buildStatusPkt(reqID, fxNoSuchFile, "no such file")
	}
	return buildSingleNamePkt(reqID, clean, s.encodeNodeAttrs(nd))
}

func (s *stubSFTPServer) handleStat(reqID uint32, body []byte, follow bool) (byte, []byte) {
	p, _, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad path")
	}
	_, nd := s.resolveNode(p, follow)
	if nd == nil {
		return buildStatusPkt(reqID, fxNoSuchFile, "not found")
	}
	return fxpAttrs, append(binary.BigEndian.AppendUint32(nil, reqID), s.encodeNodeAttrs(nd)...)
}

func (s *stubSFTPServer) handleFstat(reqID uint32, body []byte) (byte, []byte) {
	hid, _, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad handle")
	}
	h := s.handles[hid]
	if h == nil || h.node == nil {
		return buildStatusPkt(reqID, fxFailure, "unknown handle")
	}
	return fxpAttrs, append(binary.BigEndian.AppendUint32(nil, reqID), s.encodeNodeAttrs(h.node)...)
}

func (s *stubSFTPServer) handleReadlink(reqID uint32, body []byte) (byte, []byte) {
	p, _, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad path")
	}
	_, nd := s.resolveNode(p, false)
	if nd == nil {
		return buildStatusPkt(reqID, fxNoSuchFile, "not found")
	}
	if nd.kind != ports.RemoteFileSymlink {
		return buildStatusPkt(reqID, fxFailure, "not symlink")
	}
	return buildSingleNamePkt(reqID, nd.target, s.encodeNodeAttrs(nd))
}

func (s *stubSFTPServer) handleOpendir(reqID uint32, body []byte) (byte, []byte) {
	p, _, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad path")
	}
	clean, nd := s.resolveNode(p, true)
	if nd == nil {
		return buildStatusPkt(reqID, fxNoSuchFile, "not found")
	}
	if nd.kind != ports.RemoteFileDir {
		return buildStatusPkt(reqID, fxFailure, "not a dir")
	}
	s.nextHnd++
	hid := "d" + strconv.FormatUint(s.nextHnd, 10)
	s.handles[hid] = &memSFTPHandle{path: clean, node: nd, isDir: true}
	return fxpHandle, appendTestStr(binary.BigEndian.AppendUint32(nil, reqID), hid)
}

func (s *stubSFTPServer) handleReaddir(reqID uint32, body []byte) (byte, []byte) {
	hid, _, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad handle")
	}
	h := s.handles[hid]
	if h == nil || !h.isDir {
		return buildStatusPkt(reqID, fxFailure, "invalid dir handle")
	}
	if h.dirRead {
		return buildStatusPkt(reqID, fxEOF, "eof")
	}
	if s.opts.emptyReadDirOnce {
		out := binary.BigEndian.AppendUint32(nil, reqID)
		out = binary.BigEndian.AppendUint32(out, 0)
		return fxpName, out
	}
	h.dirRead = true
	var names []string
	for k := range s.nodes {
		if k != "/" && path.Dir(k) == h.path {
			names = append(names, path.Base(k))
		}
	}
	slices.Sort(names)
	out := binary.BigEndian.AppendUint32(nil, reqID)
	out = binary.BigEndian.AppendUint32(out, uint32(len(names)+2))
	// 故意夹杂 "." 与 ".." 以检验客户端正确过滤。
	out = appendTestStr(appendTestStr(out, "."), ".")
	out = append(out, s.encodeNodeAttrs(h.node)...)
	out = appendTestStr(appendTestStr(out, ".."), "..")
	out = append(out, s.encodeNodeAttrs(h.node)...)
	for _, nm := range names {
		nd := s.nodes[path.Join(h.path, nm)]
		out = appendTestStr(appendTestStr(out, nm), nm)
		out = append(out, s.encodeNodeAttrs(nd)...)
	}
	return fxpName, out
}

func (s *stubSFTPServer) handleOpen(reqID uint32, body []byte) (byte, []byte) {
	p, rest, ok := readTestStr(body)
	if !ok || len(rest) < 8 {
		return buildStatusPkt(reqID, fxFailure, "bad open")
	}
	pflags := binary.BigEndian.Uint32(rest[:4])
	if pflags&fxfTrunc != 0 {
		s.truncOp = true
	}
	perm := parseTestPermAttr(rest[4:], 0o644)
	clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
	s.openPaths = append(s.openPaths, clean)
	parent := path.Dir(clean)
	if pnd := s.nodes[parent]; pnd == nil || pnd.kind != ports.RemoteFileDir {
		return buildStatusPkt(reqID, fxNoSuchFile, "parent missing")
	}
	_, nd := s.resolveNode(clean, true)
	if nd != nil && pflags&fxfCreat != 0 && pflags&fxfExcl != 0 {
		return buildStatusPkt(reqID, fxFailure, "already exists")
	}
	if nd == nil {
		if pflags&fxfCreat == 0 {
			return buildStatusPkt(reqID, fxNoSuchFile, "not found")
		}
		s.nextIno++
		now := uint32(time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC).Unix())
		nd = &memSFTPNode{kind: ports.RemoteFileRegular, perm: 0o100000 | (perm & 0o777), atime: now, mtime: now, dev: 7, ino: s.nextIno}
		s.nodes[clean] = nd
		s.maybeSwapTargetOnTmp(pflags, now)
	}
	if nd.kind == ports.RemoteFileDir {
		return buildStatusPkt(reqID, fxFailure, "is a directory")
	}
	s.nextHnd++
	hid := "f" + strconv.FormatUint(s.nextHnd, 10)
	s.handles[hid] = &memSFTPHandle{path: clean, node: nd, writable: pflags&fxfWrite != 0}
	return fxpHandle, appendTestStr(binary.BigEndian.AppendUint32(nil, reqID), hid)
}

func (s *stubSFTPServer) maybeSwapTargetOnTmp(pflags, now uint32) {
	if s.opts.swapTargetOnTmp == "" || pflags&fxfExcl == 0 {
		return
	}
	orig := s.nodes[s.opts.swapTargetOnTmp]
	if orig == nil {
		return
	}
	s.nextIno++
	s.nodes[s.opts.swapTargetOnTmp] = &memSFTPNode{
		kind: orig.kind, perm: orig.perm, data: []byte("swapped-by-peer"),
		atime: now, mtime: now, dev: orig.dev, ino: s.nextIno,
	}
}

func (s *stubSFTPServer) handleClose(reqID uint32, body []byte) (byte, []byte) {
	hid, _, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad handle")
	}
	delete(s.handles, hid)
	return buildStatusPkt(reqID, fxOK, "")
}

func (s *stubSFTPServer) handleRead(reqID uint32, body []byte) (byte, []byte) {
	hid, rest, ok := readTestStr(body)
	if !ok || len(rest) < 12 {
		return buildStatusPkt(reqID, fxFailure, "bad read")
	}
	h := s.handles[hid]
	if h == nil || h.isDir {
		return buildStatusPkt(reqID, fxFailure, "bad handle")
	}
	off := binary.BigEndian.Uint64(rest[:8])
	ln := binary.BigEndian.Uint32(rest[8:12])
	if s.opts.growOnSecondRd && off > 0 {
		h.node.data = append(h.node.data, bytes.Repeat([]byte("Z"), 64)...)
	}
	if off >= uint64(len(h.node.data)) {
		return buildStatusPkt(reqID, fxEOF, "eof")
	}
	end := min(off+uint64(ln), uint64(len(h.node.data)))
	chunk := h.node.data[off:end]
	if s.opts.oversizedRead {
		chunk = bytes.Repeat([]byte("Z"), int(ln)+8)
	}
	out := binary.BigEndian.AppendUint32(nil, reqID)
	out = appendTestBytes(out, chunk)
	return fxpData, out
}

func (s *stubSFTPServer) handleWrite(reqID uint32, body []byte) (byte, []byte) {
	hid, rest, ok := readTestStr(body)
	if !ok || len(rest) < 12 {
		return buildStatusPkt(reqID, fxFailure, "bad write")
	}
	h := s.handles[hid]
	if h == nil || h.isDir || !h.writable {
		return buildStatusPkt(reqID, fxPermDenied, "not writable")
	}
	off := binary.BigEndian.Uint64(rest[:8])
	data, _, ok := readTestBytes(rest[8:])
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad data")
	}
	need := int(off) + len(data)
	if need > len(h.node.data) {
		grown := make([]byte, need)
		copy(grown, h.node.data)
		h.node.data = grown
	}
	copy(h.node.data[off:], data)
	return buildStatusPkt(reqID, fxOK, "")
}

func (s *stubSFTPServer) handleSetstat(reqID uint32, body []byte) (byte, []byte) {
	p, rest, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad path")
	}
	_, nd := s.resolveNode(p, true)
	if nd == nil {
		return buildStatusPkt(reqID, fxNoSuchFile, "not found")
	}
	applyTestSetstat(nd, rest)
	return buildStatusPkt(reqID, fxOK, "")
}

func (s *stubSFTPServer) handleFsetstat(reqID uint32, body []byte) (byte, []byte) {
	hid, rest, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad handle")
	}
	h := s.handles[hid]
	if h == nil {
		return buildStatusPkt(reqID, fxFailure, "unknown handle")
	}
	applyTestSetstat(h.node, rest)
	return buildStatusPkt(reqID, fxOK, "")
}

func (s *stubSFTPServer) handleMkdir(reqID uint32, body []byte) (byte, []byte) {
	p, rest, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad path")
	}
	clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
	if _, exists := s.nodes[clean]; exists {
		return buildStatusPkt(reqID, fxFailure, "exists")
	}
	parent := path.Dir(clean)
	if pnd := s.nodes[parent]; pnd == nil || pnd.kind != ports.RemoteFileDir {
		return buildStatusPkt(reqID, fxNoSuchFile, "parent missing")
	}
	perm := parseTestPermAttr(rest, 0o755)
	s.nextIno++
	now := uint32(time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC).Unix())
	s.nodes[clean] = &memSFTPNode{kind: ports.RemoteFileDir, perm: 0o040000 | (perm & 0o777), atime: now, mtime: now, dev: 7, ino: s.nextIno}
	return buildStatusPkt(reqID, fxOK, "")
}

func (s *stubSFTPServer) handleRemove(reqID uint32, body []byte) (byte, []byte) {
	p, _, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad path")
	}
	clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
	nd := s.nodes[clean]
	if nd == nil {
		return buildStatusPkt(reqID, fxNoSuchFile, "not found")
	}
	if nd.kind == ports.RemoteFileDir {
		return buildStatusPkt(reqID, fxFailure, "is directory")
	}
	delete(s.nodes, clean)
	return buildStatusPkt(reqID, fxOK, "")
}

func (s *stubSFTPServer) handleRmdir(reqID uint32, body []byte) (byte, []byte) {
	p, _, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad path")
	}
	clean := path.Clean("/" + strings.TrimPrefix(p, "/"))
	nd := s.nodes[clean]
	if nd == nil {
		return buildStatusPkt(reqID, fxNoSuchFile, "not found")
	}
	if nd.kind != ports.RemoteFileDir {
		return buildStatusPkt(reqID, fxFailure, "not dir")
	}
	for k := range s.nodes {
		if strings.HasPrefix(k, clean+"/") {
			return buildStatusPkt(reqID, fxFailure, "dir not empty")
		}
	}
	delete(s.nodes, clean)
	return buildStatusPkt(reqID, fxOK, "")
}

func (s *stubSFTPServer) handleRename(reqID uint32, body []byte, allowOverwrite bool) (byte, []byte) {
	oldRaw, rest, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad old")
	}
	newRaw, _, ok := readTestStr(rest)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad new")
	}
	oldC := path.Clean("/" + strings.TrimPrefix(oldRaw, "/"))
	newC := path.Clean("/" + strings.TrimPrefix(newRaw, "/"))
	src := s.nodes[oldC]
	if src == nil {
		return buildStatusPkt(reqID, fxNoSuchFile, "src missing")
	}
	if !allowOverwrite && s.nodes[newC] != nil {
		return buildStatusPkt(reqID, fxFailure, "target exists")
	}
	delete(s.nodes, oldC)
	s.nodes[newC] = src
	return buildStatusPkt(reqID, fxOK, "")
}

func (s *stubSFTPServer) handleExtended(reqID uint32, body []byte) (byte, []byte) {
	extName, rest, ok := readTestStr(body)
	if !ok {
		return buildStatusPkt(reqID, fxFailure, "bad ext")
	}
	switch extName {
	case "posix-rename@openssh.com":
		return s.handleRename(reqID, rest, true)
	case "hardlink@openssh.com":
		if s.opts.failHardlinkUnsupported {
			return buildStatusPkt(reqID, fxUnsupported, "link unsupported on mount")
		}
		oldRaw, r2, ok1 := readTestStr(rest)
		newRaw, _, ok2 := readTestStr(r2)
		if !ok1 || !ok2 {
			return buildStatusPkt(reqID, fxFailure, "bad hardlink")
		}
		oldC := path.Clean("/" + strings.TrimPrefix(oldRaw, "/"))
		newC := path.Clean("/" + strings.TrimPrefix(newRaw, "/"))
		src := s.nodes[oldC]
		if src == nil {
			return buildStatusPkt(reqID, fxNoSuchFile, "src missing")
		}
		if s.nodes[newC] != nil {
			return buildStatusPkt(reqID, fxFailure, "exists")
		}
		s.nodes[newC] = src
		return buildStatusPkt(reqID, fxOK, "")
	case "fsync@openssh.com":
		return buildStatusPkt(reqID, fxOK, "")
	case "limits@openssh.com":
		out := binary.BigEndian.AppendUint32(nil, reqID)
		out = binary.BigEndian.AppendUint64(out, 256*1024)
		out = binary.BigEndian.AppendUint64(out, 64*1024)
		out = binary.BigEndian.AppendUint64(out, 64*1024)
		out = binary.BigEndian.AppendUint64(out, 1024)
		return fxpExtendedReply, out
	default:
		return buildStatusPkt(reqID, fxUnsupported, "unknown ext")
	}
}

func (s *stubSFTPServer) encodeNodeAttrs(nd *memSFTPNode) []byte {
	flags := uint32(0x01 | 0x04 | 0x08)
	if s.opts.emitDevIno {
		flags |= 0x80000000
	}
	var out []byte
	out = binary.BigEndian.AppendUint32(out, flags)
	out = binary.BigEndian.AppendUint64(out, uint64(len(nd.data)))
	out = binary.BigEndian.AppendUint32(out, nd.perm)
	out = binary.BigEndian.AppendUint32(out, nd.atime)
	out = binary.BigEndian.AppendUint32(out, nd.mtime)
	if s.opts.emitDevIno {
		out = binary.BigEndian.AppendUint32(out, 2)
		out = appendTestStr(out, "stat-dev@xops.dev")
		out = appendTestStr(out, strconv.FormatUint(nd.dev, 10))
		out = appendTestStr(out, "stat-ino@xops.dev")
		out = appendTestStr(out, strconv.FormatUint(nd.ino, 10))
	}
	return out
}

func parseTestPermAttr(attrs []byte, fallback uint32) uint32 {
	if len(attrs) < 4 {
		return fallback
	}
	flags := binary.BigEndian.Uint32(attrs[:4])
	off := 4
	if flags&0x01 != 0 {
		off += 8
	}
	if flags&0x02 != 0 {
		off += 8
	}
	if flags&0x04 != 0 && off+4 <= len(attrs) {
		return binary.BigEndian.Uint32(attrs[off : off+4])
	}
	return fallback
}

func applyTestSetstat(nd *memSFTPNode, attrs []byte) {
	if len(attrs) < 4 {
		return
	}
	flags := binary.BigEndian.Uint32(attrs[:4])
	off := 4
	if flags&0x01 != 0 && off+8 <= len(attrs) {
		sz := int(binary.BigEndian.Uint64(attrs[off : off+8]))
		if sz < len(nd.data) {
			nd.data = nd.data[:sz]
		}
		off += 8
	}
	if flags&0x02 != 0 {
		off += 8
	}
	if flags&0x04 != 0 && off+4 <= len(attrs) {
		p := binary.BigEndian.Uint32(attrs[off : off+4])
		nd.perm = (nd.perm & 0o170000) | (p & 0o777)
		off += 4
	}
	if flags&0x08 != 0 && off+8 <= len(attrs) {
		nd.atime = binary.BigEndian.Uint32(attrs[off : off+4])
		nd.mtime = binary.BigEndian.Uint32(attrs[off+4 : off+8])
	}
}

func readTestPkt(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 1 || n > 4*1024*1024 {
		return 0, nil, fmt.Errorf("bad len %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}

func writeTestPkt(w io.Writer, pktType byte, body []byte) error {
	frame := make([]byte, 5+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+len(body)))
	frame[4] = pktType
	copy(frame[5:], body)
	_, err := w.Write(frame)
	return err
}

func buildStatusPkt(reqID, code uint32, msg string) (byte, []byte) {
	out := binary.BigEndian.AppendUint32(nil, reqID)
	out = binary.BigEndian.AppendUint32(out, code)
	out = appendTestStr(out, msg)
	out = appendTestStr(out, "en")
	return fxpStatus, out
}

func buildSingleNamePkt(reqID uint32, name string, attrs []byte) (byte, []byte) {
	out := binary.BigEndian.AppendUint32(nil, reqID)
	out = binary.BigEndian.AppendUint32(out, 1)
	out = appendTestStr(out, name)
	out = appendTestStr(out, name)
	out = append(out, attrs...)
	return fxpName, out
}

func appendTestStr(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

func appendTestBytes(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}

func readTestBytes(src []byte) ([]byte, []byte, bool) {
	if len(src) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(src[:4])
	if uint64(n) > uint64(len(src)-4) {
		return nil, nil, false
	}
	return src[4 : 4+n], src[4+n:], true
}

func readTestStr(src []byte) (string, []byte, bool) {
	b, rest, ok := readTestBytes(src)
	return string(b), rest, ok
}

// syncCloseRWC 确保客户端关闭连接时同步等待进程内回环 SFTP 服务端协程收敛，杜绝 goleak 竞态。
type syncCloseRWC struct {
	io.ReadWriteCloser
	done    <-chan struct{}
	nursery *concNurseryCloser
	once    sync.Once
	err     error
}

type concNurseryCloser struct {
	closeFn func() error
}

func (c *syncCloseRWC) Close() error {
	c.once.Do(func() {
		c.err = c.ReadWriteCloser.Close()
		<-c.done
		_ = c.nursery.closeFn()
	})
	return c.err
}

func mustParseRemotePath(t *testing.T, raw string) pathalg.RemotePath {
	t.Helper()
	rp, err := pathalg.ParseRemotePath(raw)
	if err != nil {
		t.Fatalf("ParseRemotePath(%q): %v", raw, err)
	}
	return rp
}

// errReader 用于测试原子写中途读错时自动清理临时文件。
type errReader struct {
	prefix []byte
	sent   bool
	err    error
}

func (e *errReader) Read(p []byte) (int, error) {
	if !e.sent && len(e.prefix) > 0 {
		e.sent = true
		return copy(p, e.prefix), nil
	}
	return 0, errors.Join(e.err)
}
