package main_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
)

// fullE2ESSHServer 是扩展版回环 SSH 服务端测试桩：支持公钥认证、exec、direct-tcpip 隧道回显与纯内存 SFTP v3 子系统。
type fullE2ESSHServer struct {
	ln             net.Listener
	nursery        *conc.Nursery
	hostSigner     ssh.Signer
	authorizedPubs []ssh.PublicKey
	sftp           *e2eSFTPStore

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	dialCount atomic.Int32
	fwdCount  atomic.Int32
	sftpCount atomic.Int32
	closeOnce sync.Once
}

func startFullE2ESSHServer(t *testing.T, authorizedPubs ...ssh.PublicKey) *fullE2ESSHServer {
	t.Helper()
	hostSigner, _ := generateE2EEd25519Key(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听 127.0.0.1:0 失败: %v", err)
	}
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("NewNursery 失败: %v", err)
	}
	srv := &fullE2ESSHServer{
		ln:             ln,
		nursery:        n,
		hostSigner:     hostSigner,
		authorizedPubs: authorizedPubs,
		sftp:           newE2ESFTPStore(),
		conns:          make(map[net.Conn]struct{}),
	}
	if err := n.Go(func(context.Context) error {
		srv.acceptLoop()
		return nil
	}); err != nil {
		_ = ln.Close()
		_ = n.Close()
		t.Fatalf("启动服务端 accept 循环失败: %v", err)
	}
	return srv
}

func (s *fullE2ESSHServer) portString(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return port
}

func (s *fullE2ESSHServer) Close() {
	s.closeOnce.Do(func() {
		_ = s.ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		_ = s.nursery.Close()
	})
}

func (s *fullE2ESSHServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.dialCount.Add(1)
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		if err := s.nursery.Go(func(context.Context) error {
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			s.serveConn(conn)
			return nil
		}); err != nil {
			_ = conn.Close()
			return
		}
	}
}

func (s *fullE2ESSHServer) serveConn(raw net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			want := key.Marshal()
			for _, pub := range s.authorizedPubs {
				if string(pub.Marshal()) == string(want) {
					return &ssh.Permissions{}, nil
				}
			}
			return nil, errors.New("unauthorized key")
		},
	}
	cfg.AddHostKey(s.hostSigner)
	sConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		for newCh := range chans {
			switch newCh.ChannelType() {
			case "session":
				ch, sReqs, aErr := newCh.Accept()
				if aErr != nil {
					continue
				}
				_ = n.Go(func(context.Context) error {
					s.handleSession(ch, sReqs)
					return nil
				})
			case "direct-tcpip":
				_ = n.Go(func(context.Context) error {
					s.handleDirectTCPIP(newCh)
					return nil
				})
			default:
				_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
			}
		}
		return nil
	})
}

func (s *fullE2ESSHServer) handleDirectTCPIP(newCh ssh.NewChannel) {
	var msg struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &msg); err != nil {
		_ = newCh.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()
	s.fwdCount.Add(1)
	target := net.JoinHostPort(msg.Host, strconv.FormatUint(uint64(msg.Port), 10))
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
		line, rErr := bufio.NewReader(ch).ReadString('\n')
		if rErr != nil && line == "" {
			return nil
		}
		_, _ = io.WriteString(ch, "fwd["+target+"]:"+line)
		return nil
	})
}

func (s *fullE2ESSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			switch req.Type {
			case "env", "pty-req":
				replySSHReq(req, true)
			case "exec":
				var p struct{ Command string }
				_ = ssh.Unmarshal(req.Payload, &p)
				replySSHReq(req, true)
				_ = n.Go(func(context.Context) error {
					defer func() { _ = ch.Close() }()
					_, _ = io.WriteString(ch, "exec:"+p.Command+"\n")
					sendExitStatus(ch, 0)
					return nil
				})
			case "subsystem":
				var p struct{ Name string }
				if ssh.Unmarshal(req.Payload, &p) != nil || p.Name != "sftp" {
					replySSHReq(req, false)
					continue
				}
				replySSHReq(req, true)
				s.sftpCount.Add(1)
				_ = n.Go(func(context.Context) error {
					s.sftp.serve(ch)
					return nil
				})
			default:
				replySSHReq(req, false)
			}
		}
		return nil
	})
}

// 以下为纯内存 SFTP v3 服务端桩（支持 INIT/OPEN/READ/WRITE/CLOSE/STAT/LSTAT/FSTAT/OPENDIR/READDIR/MKDIR/REMOVE/RENAME/REALPATH 与 posix-rename）。
const (
	fxpInit          byte   = 1
	fxpVersion       byte   = 2
	fxpOpen          byte   = 3
	fxpClose         byte   = 4
	fxpRead          byte   = 5
	fxpWrite         byte   = 6
	fxpLstat         byte   = 7
	fxpFstat         byte   = 8
	fxpSetstat       byte   = 9
	fxpFsetstat      byte   = 10
	fxpOpendir       byte   = 11
	fxpReaddir       byte   = 12
	fxpRemove        byte   = 13
	fxpMkdir         byte   = 14
	fxpRealpath      byte   = 16
	fxpStat          byte   = 17
	fxpRename        byte   = 18
	fxpStatus        byte   = 101
	fxpHandle        byte   = 102
	fxpData          byte   = 103
	fxpName          byte   = 104
	fxpAttrs         byte   = 105
	fxpExtended      byte   = 200
	fxpExtendedReply byte   = 201
	fxOK             uint32 = 0
	fxEOF            uint32 = 1
	fxNoSuchFile     uint32 = 2
	fxFailure        uint32 = 4
	fxUnsupported    uint32 = 8
)

type e2eSFTPNode struct {
	isDir bool
	perm  uint32
	data  []byte
	ino   uint64
}

type e2eSFTPHandle struct {
	node    *e2eSFTPNode
	dirPath string
	dirSent bool
}

type e2eSFTPStore struct {
	mu      sync.Mutex
	nextIno uint64
	nextHnd uint64
	nodes   map[string]*e2eSFTPNode
	handles map[string]*e2eSFTPHandle
}

func newE2ESFTPStore() *e2eSFTPStore {
	return &e2eSFTPStore{
		nextIno: 100,
		nodes:   map[string]*e2eSFTPNode{"/": {isDir: true, perm: 0o040755, ino: 1}},
		handles: map[string]*e2eSFTPHandle{},
	}
}

func (st *e2eSFTPStore) serve(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	pt, _, err := readE2ESFTPPkt(ch)
	if err != nil || pt != fxpInit {
		return
	}
	if err := writeE2ESFTPVersion(ch); err != nil {
		return
	}
	for {
		pktType, body, rErr := readE2ESFTPPkt(ch)
		if rErr != nil || len(body) < 4 {
			return
		}
		reqID := binary.BigEndian.Uint32(body[:4])
		rt, rb := st.dispatch(pktType, reqID, body[4:])
		if wErr := writeE2ESFTPPkt(ch, rt, rb); wErr != nil {
			return
		}
	}
}

func (st *e2eSFTPStore) dispatch(pt byte, reqID uint32, body []byte) (byte, []byte) {
	st.mu.Lock()
	defer st.mu.Unlock()
	switch pt {
	case fxpRealpath:
		raw, _ := readE2ESFTPStr(body, 0)
		cleaned := cleanE2ERemotePath(raw)
		return fxpName, encodeE2ESFTPName(reqID, cleaned, &e2eSFTPNode{isDir: true, perm: 0o040755, ino: 1})
	case fxpStat, fxpLstat:
		return st.handleStat(reqID, body)
	case fxpFstat:
		return st.handleFstat(reqID, body)
	case fxpOpen:
		return st.handleOpen(reqID, body)
	case fxpRead:
		return st.handleRead(reqID, body)
	case fxpWrite:
		return st.handleWrite(reqID, body)
	case fxpOpendir:
		return st.handleOpendir(reqID, body)
	case fxpReaddir:
		return st.handleReaddir(reqID, body)
	case fxpClose:
		h, _ := readE2ESFTPStr(body, 0)
		delete(st.handles, h)
		return e2eSFTPStatusPkt(reqID, fxOK, "")
	case fxpMkdir:
		return st.handleMkdir(reqID, body)
	case fxpRemove:
		raw, _ := readE2ESFTPStr(body, 0)
		delete(st.nodes, cleanE2ERemotePath(raw))
		return e2eSFTPStatusPkt(reqID, fxOK, "")
	case fxpRename:
		return st.handleRename(reqID, body, false)
	case fxpSetstat, fxpFsetstat:
		return e2eSFTPStatusPkt(reqID, fxOK, "")
	case fxpExtended:
		return st.handleExtended(reqID, body)
	default:
		return e2eSFTPStatusPkt(reqID, fxUnsupported, "unsupported")
	}
}

func (st *e2eSFTPStore) handleStat(reqID uint32, body []byte) (byte, []byte) {
	raw, _ := readE2ESFTPStr(body, 0)
	nd := st.nodes[cleanE2ERemotePath(raw)]
	if nd == nil {
		return e2eSFTPStatusPkt(reqID, fxNoSuchFile, "not found")
	}
	return fxpAttrs, append(binary.BigEndian.AppendUint32(nil, reqID), encodeE2ESFTPAttrs(nd)...)
}

func (st *e2eSFTPStore) handleFstat(reqID uint32, body []byte) (byte, []byte) {
	hid, _ := readE2ESFTPStr(body, 0)
	h := st.handles[hid]
	if h == nil || h.node == nil {
		return e2eSFTPStatusPkt(reqID, fxFailure, "bad handle")
	}
	return fxpAttrs, append(binary.BigEndian.AppendUint32(nil, reqID), encodeE2ESFTPAttrs(h.node)...)
}

func (st *e2eSFTPStore) handleOpen(reqID uint32, body []byte) (byte, []byte) {
	raw, off := readE2ESFTPStr(body, 0)
	if off+4 > len(body) {
		return e2eSFTPStatusPkt(reqID, fxFailure, "bad open")
	}
	pflags := binary.BigEndian.Uint32(body[off : off+4])
	p := cleanE2ERemotePath(raw)
	nd := st.nodes[p]
	if nd == nil {
		if pflags&0x08 == 0 {
			return e2eSFTPStatusPkt(reqID, fxNoSuchFile, "not found")
		}
		st.nextIno++
		nd = &e2eSFTPNode{perm: 0o100644, ino: st.nextIno}
		st.nodes[p] = nd
	} else if pflags&0x20 != 0 {
		return e2eSFTPStatusPkt(reqID, fxFailure, "already exists")
	}
	if pflags&0x10 != 0 {
		nd.data = nil
	}
	st.nextHnd++
	hid := fmt.Sprintf("f%d", st.nextHnd)
	st.handles[hid] = &e2eSFTPHandle{node: nd}
	return fxpHandle, appendE2ESFTPStr(binary.BigEndian.AppendUint32(nil, reqID), hid)
}

func (st *e2eSFTPStore) handleOpendir(reqID uint32, body []byte) (byte, []byte) {
	raw, _ := readE2ESFTPStr(body, 0)
	p := cleanE2ERemotePath(raw)
	nd := st.nodes[p]
	if nd == nil || !nd.isDir {
		return e2eSFTPStatusPkt(reqID, fxNoSuchFile, "not a dir")
	}
	st.nextHnd++
	hid := fmt.Sprintf("d%d", st.nextHnd)
	st.handles[hid] = &e2eSFTPHandle{node: nd, dirPath: p}
	return fxpHandle, appendE2ESFTPStr(binary.BigEndian.AppendUint32(nil, reqID), hid)
}

func (st *e2eSFTPStore) handleReaddir(reqID uint32, body []byte) (byte, []byte) {
	hid, _ := readE2ESFTPStr(body, 0)
	h := st.handles[hid]
	if h == nil || h.dirPath == "" {
		return e2eSFTPStatusPkt(reqID, fxFailure, "bad dir handle")
	}
	if h.dirSent {
		return e2eSFTPStatusPkt(reqID, fxEOF, "eof")
	}
	h.dirSent = true
	var names []string
	for p := range st.nodes {
		if p == h.dirPath {
			continue
		}
		if path.Dir(p) == h.dirPath {
			names = append(names, path.Base(p))
		}
	}
	sort.Strings(names)
	b := binary.BigEndian.AppendUint32(nil, reqID)
	b = binary.BigEndian.AppendUint32(b, uint32(len(names)))
	for _, name := range names {
		full := path.Join(h.dirPath, name)
		b = appendE2ESFTPStr(b, name)
		b = appendE2ESFTPStr(b, name)
		b = append(b, encodeE2ESFTPAttrs(st.nodes[full])...)
	}
	return fxpName, b
}

func (st *e2eSFTPStore) handleRead(reqID uint32, body []byte) (byte, []byte) {
	hid, off := readE2ESFTPStr(body, 0)
	h := st.handles[hid]
	if h == nil || h.node == nil || off+12 > len(body) {
		return e2eSFTPStatusPkt(reqID, fxFailure, "bad read")
	}
	pos := binary.BigEndian.Uint64(body[off : off+8])
	want := binary.BigEndian.Uint32(body[off+8 : off+12])
	if pos >= uint64(len(h.node.data)) {
		return e2eSFTPStatusPkt(reqID, fxEOF, "eof")
	}
	end := min(pos+uint64(want), uint64(len(h.node.data)))
	chunk := h.node.data[pos:end]
	out := binary.BigEndian.AppendUint32(nil, reqID)
	out = binary.BigEndian.AppendUint32(out, uint32(len(chunk)))
	return fxpData, append(out, chunk...)
}

func (st *e2eSFTPStore) handleWrite(reqID uint32, body []byte) (byte, []byte) {
	hid, off := readE2ESFTPStr(body, 0)
	h := st.handles[hid]
	if h == nil || h.node == nil || off+12 > len(body) {
		return e2eSFTPStatusPkt(reqID, fxFailure, "bad write")
	}
	pos := binary.BigEndian.Uint64(body[off : off+8])
	dlen := binary.BigEndian.Uint32(body[off+8 : off+12])
	dataStart := off + 12
	if dataStart+int(dlen) > len(body) {
		return e2eSFTPStatusPkt(reqID, fxFailure, "short write")
	}
	end := int(pos) + int(dlen)
	if end > len(h.node.data) {
		grown := make([]byte, end)
		copy(grown, h.node.data)
		h.node.data = grown
	}
	copy(h.node.data[int(pos):end], body[dataStart:dataStart+int(dlen)])
	return e2eSFTPStatusPkt(reqID, fxOK, "")
}

func (st *e2eSFTPStore) handleMkdir(reqID uint32, body []byte) (byte, []byte) {
	raw, _ := readE2ESFTPStr(body, 0)
	p := cleanE2ERemotePath(raw)
	if st.nodes[p] != nil {
		return e2eSFTPStatusPkt(reqID, fxFailure, "exists")
	}
	st.nextIno++
	st.nodes[p] = &e2eSFTPNode{isDir: true, perm: 0o040755, ino: st.nextIno}
	return e2eSFTPStatusPkt(reqID, fxOK, "")
}

func (st *e2eSFTPStore) handleRename(reqID uint32, body []byte, overwrite bool) (byte, []byte) {
	oldRaw, off := readE2ESFTPStr(body, 0)
	newRaw, _ := readE2ESFTPStr(body, off)
	oldP, newP := cleanE2ERemotePath(oldRaw), cleanE2ERemotePath(newRaw)
	src := st.nodes[oldP]
	if src == nil {
		return e2eSFTPStatusPkt(reqID, fxNoSuchFile, "missing src")
	}
	if !overwrite && st.nodes[newP] != nil {
		return e2eSFTPStatusPkt(reqID, fxFailure, "target exists")
	}
	st.nodes[newP] = src
	delete(st.nodes, oldP)
	return e2eSFTPStatusPkt(reqID, fxOK, "")
}

func (st *e2eSFTPStore) handleExtended(reqID uint32, body []byte) (byte, []byte) {
	ext, off := readE2ESFTPStr(body, 0)
	switch ext {
	case "posix-rename@openssh.com":
		return st.handleRename(reqID, body[off:], true)
	case "fsync@openssh.com":
		return e2eSFTPStatusPkt(reqID, fxOK, "")
	case "limits@openssh.com":
		out := binary.BigEndian.AppendUint32(nil, reqID)
		out = binary.BigEndian.AppendUint64(out, 256*1024)
		out = binary.BigEndian.AppendUint64(out, 64*1024)
		out = binary.BigEndian.AppendUint64(out, 64*1024)
		out = binary.BigEndian.AppendUint64(out, 1024)
		return fxpExtendedReply, out
	default:
		return e2eSFTPStatusPkt(reqID, fxUnsupported, "unknown ext")
	}
}

func cleanE2ERemotePath(raw string) string { return path.Clean("/" + strings.TrimPrefix(raw, "/")) }

func readE2ESFTPPkt(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 1 || n > 4*1024*1024 {
		return 0, nil, errors.New("bad sftp length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}

func writeE2ESFTPPkt(w io.Writer, pt byte, body []byte) error {
	frame := make([]byte, 5+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+len(body)))
	frame[4] = pt
	copy(frame[5:], body)
	_, err := w.Write(frame)
	return err
}

func writeE2ESFTPVersion(w io.Writer) error {
	b := binary.BigEndian.AppendUint32(nil, 3)
	for _, ext := range []string{"posix-rename@openssh.com", "fsync@openssh.com", "limits@openssh.com"} {
		b = appendE2ESFTPStr(appendE2ESFTPStr(b, ext), "1")
	}
	return writeE2ESFTPPkt(w, fxpVersion, b)
}

func e2eSFTPStatusPkt(reqID, code uint32, msg string) (byte, []byte) {
	b := binary.BigEndian.AppendUint32(nil, reqID)
	b = binary.BigEndian.AppendUint32(b, code)
	b = appendE2ESFTPStr(b, msg)
	b = appendE2ESFTPStr(b, "en")
	return fxpStatus, b
}

func encodeE2ESFTPAttrs(nd *e2eSFTPNode) []byte {
	flags := uint32(0x01 | 0x04 | 0x80000000)
	b := binary.BigEndian.AppendUint32(nil, flags)
	b = binary.BigEndian.AppendUint64(b, uint64(len(nd.data)))
	b = binary.BigEndian.AppendUint32(b, nd.perm)
	b = binary.BigEndian.AppendUint32(b, 2)
	b = appendE2ESFTPStr(b, "stat-dev@xops.dev")
	b = appendE2ESFTPStr(b, "7")
	b = appendE2ESFTPStr(b, "stat-ino@xops.dev")
	b = appendE2ESFTPStr(b, strconv.FormatUint(nd.ino, 10))
	return b
}

func encodeE2ESFTPName(reqID uint32, name string, nd *e2eSFTPNode) []byte {
	b := binary.BigEndian.AppendUint32(nil, reqID)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = appendE2ESFTPStr(b, name)
	b = appendE2ESFTPStr(b, name)
	return append(b, encodeE2ESFTPAttrs(nd)...)
}

func appendE2ESFTPStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func readE2ESFTPStr(b []byte, off int) (string, int) {
	if off+4 > len(b) {
		return "", len(b)
	}
	n := int(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4
	if off+n > len(b) {
		return "", len(b)
	}
	return string(b[off : off+n]), off + n
}
