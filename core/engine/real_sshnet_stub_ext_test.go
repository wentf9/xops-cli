package engine_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/engine"
)

// realSSHNetStub 实现面向全真实 sshnet/* 端到端回环集成测试的进程内 SSH 服务端：
// 支持 Ed25519 公钥认证、普通 exec、两阶段 POSIX Shell 探针、随机 -p 提权握手、
// 含 OpenSSH 扩展的纯内存 SFTP v3 子系统与 direct-tcpip 隧道回显；零后台协程泄漏。
type realSSHNetStub struct {
	hostSigner     ssh.Signer
	authorizedPubs []ssh.PublicKey
	sudoPassword   string
	sftp           *loopbackSFTPStore

	dialCount  atomic.Int32
	execCount  atomic.Int32
	probeCount atomic.Int32
	privCount  atomic.Int32
	sftpCount  atomic.Int32
	fwdCount   atomic.Int32
}

func newRealSSHNetStub(t *testing.T, sudoPassword string, authorizedPubs ...ssh.PublicKey) *realSSHNetStub {
	t.Helper()
	hostSigner, _ := generateEd25519TestSigner(t)
	return &realSSHNetStub{
		hostSigner:     hostSigner,
		authorizedPubs: authorizedPubs,
		sudoPassword:   sudoPassword,
		sftp:           newLoopbackSFTPStore(),
	}
}

func (s *realSSHNetStub) dialFunc() engine.DialContextFunc {
	return func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		return s.dialOnDemand(ctx)
	}
}

func (s *realSSHNetStub) dialOnDemand(ctx context.Context) (net.Conn, error) {
	s.dialCount.Add(1)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srvNursery, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	done := make(chan struct{})
	if gErr := srvNursery.Go(func(context.Context) error {
		defer close(done)
		defer func() { _ = ln.Close() }()
		srvConn, aErr := ln.Accept()
		_ = ln.Close()
		if aErr != nil {
			return nil
		}
		s.serveConn(srvConn)
		return nil
	}); gErr != nil {
		_ = ln.Close()
		_ = srvNursery.Close()
		return nil, gErr
	}
	var nd net.Dialer
	cliConn, dErr := nd.DialContext(ctx, "tcp", ln.Addr().String())
	if dErr != nil {
		_ = ln.Close()
		<-done
		_ = srvNursery.Close()
		return nil, dErr
	}
	return &syncCloseNetConn{Conn: cliConn, done: done, nursery: srvNursery}, nil
}

func (s *realSSHNetStub) buildServerConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			presented := key.Marshal()
			for _, allowed := range s.authorizedPubs {
				if bytes.Equal(presented, allowed.Marshal()) {
					return &ssh.Permissions{}, nil
				}
			}
			return nil, errors.New("unauthorized public key")
		},
	}
	cfg.AddHostKey(s.hostSigner)
	return cfg
}

func (s *realSSHNetStub) serveConn(raw net.Conn) {
	defer func() { _ = raw.Close() }()
	sConn, chans, reqs, err := ssh.NewServerConn(raw, s.buildServerConfig())
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()

	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			for req := range reqs {
				if req.WantReply {
					_ = req.Reply(req.Type == "keepalive@openssh.com", nil)
				}
			}
			return nil
		}); gErr != nil {
			return gErr
		}
		for newCh := range chans {
			ch := newCh
			if gErr := n.Go(func(context.Context) error {
				s.handleChannel(ch)
				return nil
			}); gErr != nil {
				_ = ch.Reject(ssh.ResourceShortage, "nursery stopped")
			}
		}
		return nil
	})
}

func (s *realSSHNetStub) handleChannel(newCh ssh.NewChannel) {
	switch newCh.ChannelType() {
	case "session":
		ch, reqs, err := newCh.Accept()
		if err != nil {
			return
		}
		s.handleSession(ch, reqs)
	case "direct-tcpip":
		s.handleDirectTCPIPEcho(newCh)
	default:
		_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel")
	}
}

func (s *realSSHNetStub) handleDirectTCPIPEcho(newCh ssh.NewChannel) {
	var msg struct {
		Host       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newCh.ExtraData(), &msg); err != nil {
		_ = newCh.Reject(ssh.Prohibited, "bad direct-tcpip payload")
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

func (s *realSSHNetStub) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			s.dispatchSessionReq(n, ch, req)
		}
		return nil
	})
}

func (s *realSSHNetStub) dispatchSessionReq(n *conc.Nursery, ch ssh.Channel, req *ssh.Request) {
	switch req.Type {
	case "env":
		replyReq(req, true)
	case "exec":
		var p struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &p)
		replyReq(req, true)
		_ = n.Go(func(context.Context) error {
			s.runExec(ch, p.Command)
			return nil
		})
	case "subsystem":
		var p struct{ Name string }
		if ssh.Unmarshal(req.Payload, &p) != nil || p.Name != "sftp" {
			replyReq(req, false)
			return
		}
		replyReq(req, true)
		s.sftpCount.Add(1)
		_ = n.Go(func(context.Context) error {
			s.sftp.serve(ch)
			return nil
		})
	default:
		replyReq(req, false)
	}
}

func (s *realSSHNetStub) runExec(ch ssh.Channel, cmd string) {
	defer func() { _ = ch.Close() }()
	switch {
	case strings.Contains(cmd, "__XOPS_DIALECT_POSIX__"):
		s.probeCount.Add(1)
		_, _ = io.WriteString(ch, "__XOPS_DIALECT_POSIX__:Linux:/bin/bash\n")
		sendChannelExitStatus(ch, 0)
	case strings.Contains(cmd, "__XOPS_INTERP_END__"):
		s.probeCount.Add(1)
		_, _ = io.WriteString(ch, "__XOPS_INTERP__:bash\n__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n")
		sendChannelExitStatus(ch, 0)
	case strings.Contains(cmd, "sudo -S -p "):
		s.privCount.Add(1)
		s.runSudoExec(ch, cmd)
	default:
		s.execCount.Add(1)
		_, _ = io.WriteString(ch, "real-exec:"+cmd+"\n")
		sendChannelExitStatus(ch, 0)
	}
}

func (s *realSSHNetStub) runSudoExec(ch ssh.Channel, cmd string) {
	promptTok, ok1 := extractBracketToken(cmd, "[xops-priv-prompt-")
	readyTok, ok2 := extractBracketToken(cmd, "[xops-priv-ready-")
	if !ok1 || !ok2 {
		_, _ = io.WriteString(ch.Stderr(), "missing sudo handshake tokens\n")
		sendChannelExitStatus(ch, 1)
		return
	}
	_, _ = io.WriteString(ch.Stderr(), promptTok)
	line, err := bufio.NewReader(ch).ReadString('\n')
	if err != nil || strings.TrimRight(line, "\r\n") != s.sudoPassword {
		_, _ = io.WriteString(ch.Stderr(), "Sorry, try again.\n")
		sendChannelExitStatus(ch, 1)
		return
	}
	_, _ = io.WriteString(ch.Stderr(), readyTok)
	_, _ = io.WriteString(ch, "uid=0(root)\n")
	sendChannelExitStatus(ch, 0)
}

func extractBracketToken(s, prefix string) (string, bool) {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return "", false
	}
	rest := s[idx:]
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return "", false
	}
	return rest[:end+1], true
}

// 以下为纯内存 POSIX SFTP v3 测试服务端实现（仅依赖标准库 path，0 path/filepath 依赖），
// 支持 real sshnet/sftp 所需的 INIT/VERSION、LSTAT/STAT/FSTAT(含 dev/ino 锚点)、OPEN/READ/WRITE/CLOSE、
// MKDIR/REMOVE/RENAME/REALPATH/SETSTAT 及 posix-rename/hardlink/fsync/limits OpenSSH 扩展。
const (
	e2eFXPInit          byte = 1
	e2eFXPVersion       byte = 2
	e2eFXPOpen          byte = 3
	e2eFXPClose         byte = 4
	e2eFXPRead          byte = 5
	e2eFXPWrite         byte = 6
	e2eFXPLstat         byte = 7
	e2eFXPFstat         byte = 8
	e2eFXPSetstat       byte = 9
	e2eFXPFsetstat      byte = 10
	e2eFXPRemove        byte = 13
	e2eFXPMkdir         byte = 14
	e2eFXPRealpath      byte = 16
	e2eFXPStat          byte = 17
	e2eFXPRename        byte = 18
	e2eFXPStatus        byte = 101
	e2eFXPHandle        byte = 102
	e2eFXPData          byte = 103
	e2eFXPName          byte = 104
	e2eFXPAttrs         byte = 105
	e2eFXPExtended      byte = 200
	e2eFXPExtendedReply byte = 201

	e2eFXOK          uint32 = 0
	e2eFXEOF         uint32 = 1
	e2eFXNoSuchFile  uint32 = 2
	e2eFXFailure     uint32 = 4
	e2eFXUnsupported uint32 = 8
)

type loopbackSFTPNode struct {
	isDir bool
	perm  uint32
	data  []byte
	ino   uint64
}

type loopbackSFTPHandle struct {
	node *loopbackSFTPNode
}

type loopbackSFTPStore struct {
	mu      sync.Mutex
	nextIno uint64
	nextHnd uint64
	nodes   map[string]*loopbackSFTPNode
	handles map[string]*loopbackSFTPHandle
}

func newLoopbackSFTPStore() *loopbackSFTPStore {
	return &loopbackSFTPStore{
		nextIno: 100,
		nodes:   map[string]*loopbackSFTPNode{"/": {isDir: true, perm: 0o040755, ino: 1}},
		handles: map[string]*loopbackSFTPHandle{},
	}
}

func (st *loopbackSFTPStore) serve(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	pktType, _, err := readSFTPPkt(ch)
	if err != nil || pktType != e2eFXPInit {
		return
	}
	if err := writeSFTPVersion(ch); err != nil {
		return
	}
	for {
		pt, body, rErr := readSFTPPkt(ch)
		if rErr != nil || len(body) < 4 {
			return
		}
		reqID := binary.BigEndian.Uint32(body[:4])
		rt, rb := st.dispatch(pt, reqID, body[4:])
		if wErr := writeSFTPPkt(ch, rt, rb); wErr != nil {
			return
		}
	}
}

func (st *loopbackSFTPStore) dispatch(pt byte, reqID uint32, body []byte) (byte, []byte) {
	st.mu.Lock()
	defer st.mu.Unlock()
	switch pt {
	case e2eFXPRealpath:
		raw, _ := readSFTPStr(body, 0)
		cleaned := cleanPosixPath(raw)
		return e2eFXPName, encodeSFTPName(reqID, cleaned, &loopbackSFTPNode{isDir: true, perm: 0o040755, ino: 1})
	case e2eFXPStat, e2eFXPLstat:
		return st.handleStat(reqID, body)
	case e2eFXPFstat:
		return st.handleFstat(reqID, body)
	case e2eFXPOpen:
		return st.handleOpen(reqID, body)
	case e2eFXPRead:
		return st.handleRead(reqID, body)
	case e2eFXPWrite:
		return st.handleWrite(reqID, body)
	case e2eFXPClose:
		h, _ := readSFTPStr(body, 0)
		delete(st.handles, h)
		return sftpStatusPkt(reqID, e2eFXOK, "")
	case e2eFXPMkdir:
		return st.handleMkdir(reqID, body)
	case e2eFXPRemove:
		raw, _ := readSFTPStr(body, 0)
		delete(st.nodes, cleanPosixPath(raw))
		return sftpStatusPkt(reqID, e2eFXOK, "")
	case e2eFXPRename:
		return st.handleRename(reqID, body, false)
	case e2eFXPSetstat, e2eFXPFsetstat:
		return sftpStatusPkt(reqID, e2eFXOK, "")
	case e2eFXPExtended:
		return st.handleExtended(reqID, body)
	default:
		return sftpStatusPkt(reqID, e2eFXUnsupported, "unsupported")
	}
}

func (st *loopbackSFTPStore) handleStat(reqID uint32, body []byte) (byte, []byte) {
	raw, _ := readSFTPStr(body, 0)
	nd := st.nodes[cleanPosixPath(raw)]
	if nd == nil {
		return sftpStatusPkt(reqID, e2eFXNoSuchFile, "not found")
	}
	return e2eFXPAttrs, append(binary.BigEndian.AppendUint32(nil, reqID), encodeSFTPAttrs(nd)...)
}

func (st *loopbackSFTPStore) handleFstat(reqID uint32, body []byte) (byte, []byte) {
	hid, _ := readSFTPStr(body, 0)
	h := st.handles[hid]
	if h == nil || h.node == nil {
		return sftpStatusPkt(reqID, e2eFXFailure, "bad handle")
	}
	return e2eFXPAttrs, append(binary.BigEndian.AppendUint32(nil, reqID), encodeSFTPAttrs(h.node)...)
}

func (st *loopbackSFTPStore) handleOpen(reqID uint32, body []byte) (byte, []byte) {
	raw, off := readSFTPStr(body, 0)
	if off+4 > len(body) {
		return sftpStatusPkt(reqID, e2eFXFailure, "bad open")
	}
	pflags := binary.BigEndian.Uint32(body[off : off+4])
	p := cleanPosixPath(raw)
	nd := st.nodes[p]
	if nd == nil {
		if pflags&0x08 == 0 {
			return sftpStatusPkt(reqID, e2eFXNoSuchFile, "not found")
		}
		st.nextIno++
		nd = &loopbackSFTPNode{perm: 0o100644, ino: st.nextIno}
		st.nodes[p] = nd
	} else if pflags&0x20 != 0 {
		return sftpStatusPkt(reqID, e2eFXFailure, "already exists")
	}
	if pflags&0x10 != 0 {
		nd.data = nil
	}
	st.nextHnd++
	hid := fmt.Sprintf("h%d", st.nextHnd)
	st.handles[hid] = &loopbackSFTPHandle{node: nd}
	return e2eFXPHandle, appendSFTPStr(binary.BigEndian.AppendUint32(nil, reqID), hid)
}

func (st *loopbackSFTPStore) handleRead(reqID uint32, body []byte) (byte, []byte) {
	hid, off := readSFTPStr(body, 0)
	h := st.handles[hid]
	if h == nil || off+12 > len(body) {
		return sftpStatusPkt(reqID, e2eFXFailure, "bad read")
	}
	pos := binary.BigEndian.Uint64(body[off : off+8])
	want := binary.BigEndian.Uint32(body[off+8 : off+12])
	if pos >= uint64(len(h.node.data)) {
		return sftpStatusPkt(reqID, e2eFXEOF, "eof")
	}
	end := min(pos+uint64(want), uint64(len(h.node.data)))
	chunk := h.node.data[pos:end]
	out := binary.BigEndian.AppendUint32(nil, reqID)
	out = binary.BigEndian.AppendUint32(out, uint32(len(chunk)))
	return e2eFXPData, append(out, chunk...)
}

func (st *loopbackSFTPStore) handleWrite(reqID uint32, body []byte) (byte, []byte) {
	hid, off := readSFTPStr(body, 0)
	h := st.handles[hid]
	if h == nil || off+12 > len(body) {
		return sftpStatusPkt(reqID, e2eFXFailure, "bad write")
	}
	pos := binary.BigEndian.Uint64(body[off : off+8])
	dlen := binary.BigEndian.Uint32(body[off+8 : off+12])
	dataStart := off + 12
	if dataStart+int(dlen) > len(body) {
		return sftpStatusPkt(reqID, e2eFXFailure, "short write")
	}
	end := int(pos) + int(dlen)
	if end > len(h.node.data) {
		grown := make([]byte, end)
		copy(grown, h.node.data)
		h.node.data = grown
	}
	copy(h.node.data[int(pos):end], body[dataStart:dataStart+int(dlen)])
	return sftpStatusPkt(reqID, e2eFXOK, "")
}

func (st *loopbackSFTPStore) handleMkdir(reqID uint32, body []byte) (byte, []byte) {
	raw, _ := readSFTPStr(body, 0)
	p := cleanPosixPath(raw)
	if st.nodes[p] != nil {
		return sftpStatusPkt(reqID, e2eFXFailure, "exists")
	}
	st.nextIno++
	st.nodes[p] = &loopbackSFTPNode{isDir: true, perm: 0o040755, ino: st.nextIno}
	return sftpStatusPkt(reqID, e2eFXOK, "")
}

func (st *loopbackSFTPStore) handleRename(reqID uint32, body []byte, overwrite bool) (byte, []byte) {
	oldRaw, off := readSFTPStr(body, 0)
	newRaw, _ := readSFTPStr(body, off)
	oldP, newP := cleanPosixPath(oldRaw), cleanPosixPath(newRaw)
	src := st.nodes[oldP]
	if src == nil {
		return sftpStatusPkt(reqID, e2eFXNoSuchFile, "missing src")
	}
	if !overwrite && st.nodes[newP] != nil {
		return sftpStatusPkt(reqID, e2eFXFailure, "target exists")
	}
	st.nodes[newP] = src
	delete(st.nodes, oldP)
	return sftpStatusPkt(reqID, e2eFXOK, "")
}

func (st *loopbackSFTPStore) handleExtended(reqID uint32, body []byte) (byte, []byte) {
	ext, off := readSFTPStr(body, 0)
	switch ext {
	case "posix-rename@openssh.com":
		return st.handleRename(reqID, body[off:], true)
	case "hardlink@openssh.com":
		oldRaw, off2 := readSFTPStr(body[off:], 0)
		newRaw, _ := readSFTPStr(body[off:], off2)
		oldP, newP := cleanPosixPath(oldRaw), cleanPosixPath(newRaw)
		src := st.nodes[oldP]
		if src == nil || st.nodes[newP] != nil {
			return sftpStatusPkt(reqID, e2eFXFailure, "hardlink failed")
		}
		st.nodes[newP] = src
		return sftpStatusPkt(reqID, e2eFXOK, "")
	case "fsync@openssh.com":
		return sftpStatusPkt(reqID, e2eFXOK, "")
	case "limits@openssh.com":
		out := binary.BigEndian.AppendUint32(nil, reqID)
		out = binary.BigEndian.AppendUint64(out, 256*1024)
		out = binary.BigEndian.AppendUint64(out, 64*1024)
		out = binary.BigEndian.AppendUint64(out, 64*1024)
		out = binary.BigEndian.AppendUint64(out, 1024)
		return e2eFXPExtendedReply, out
	default:
		return sftpStatusPkt(reqID, e2eFXUnsupported, "unknown ext")
	}
}

func cleanPosixPath(raw string) string { return path.Clean("/" + strings.TrimPrefix(raw, "/")) }

func readSFTPPkt(r io.Reader) (byte, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 1 || n > 4*1024*1024 {
		return 0, nil, errors.New("bad sftp packet length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return buf[0], buf[1:], nil
}

func writeSFTPPkt(w io.Writer, pktType byte, body []byte) error {
	frame := make([]byte, 5+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(1+len(body)))
	frame[4] = pktType
	copy(frame[5:], body)
	_, err := w.Write(frame)
	return err
}

func writeSFTPVersion(w io.Writer) error {
	b := binary.BigEndian.AppendUint32(nil, 3)
	for _, ext := range []string{"posix-rename@openssh.com", "hardlink@openssh.com", "fsync@openssh.com", "limits@openssh.com"} {
		b = appendSFTPStr(appendSFTPStr(b, ext), "1")
	}
	return writeSFTPPkt(w, e2eFXPVersion, b)
}

func sftpStatusPkt(reqID, code uint32, msg string) (byte, []byte) {
	b := binary.BigEndian.AppendUint32(nil, reqID)
	b = binary.BigEndian.AppendUint32(b, code)
	b = appendSFTPStr(b, msg)
	b = appendSFTPStr(b, "en")
	return e2eFXPStatus, b
}

func encodeSFTPAttrs(nd *loopbackSFTPNode) []byte {
	flags := uint32(0x01 | 0x04 | 0x80000000)
	b := binary.BigEndian.AppendUint32(nil, flags)
	b = binary.BigEndian.AppendUint64(b, uint64(len(nd.data)))
	b = binary.BigEndian.AppendUint32(b, nd.perm)
	b = binary.BigEndian.AppendUint32(b, 2)
	b = appendSFTPStr(b, "stat-dev@xops.dev")
	b = appendSFTPStr(b, "7")
	b = appendSFTPStr(b, "stat-ino@xops.dev")
	b = appendSFTPStr(b, strconv.FormatUint(nd.ino, 10))
	return b
}

func encodeSFTPName(reqID uint32, name string, nd *loopbackSFTPNode) []byte {
	b := binary.BigEndian.AppendUint32(nil, reqID)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = appendSFTPStr(b, name)
	b = appendSFTPStr(b, name)
	return append(b, encodeSFTPAttrs(nd)...)
}

func appendSFTPStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func readSFTPStr(b []byte, off int) (string, int) {
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
