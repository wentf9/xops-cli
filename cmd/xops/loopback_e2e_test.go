package main_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	jsonv2 "encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

// e2eSSHServer 是在本机 127.0.0.1:0 监听的进程内真实 SSH 服务端测试桩，
// 所有连接处理与会话协程均受 core/conc.Nursery 监督（0 裸 go、0 time.Sleep、0 外部主机）。
type e2eSSHServer struct {
	ln             net.Listener
	nursery        *conc.Nursery
	hostSigner     ssh.Signer
	authorizedPubs []ssh.PublicKey

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	seenUsers []string
	dialCount atomic.Int32
	closeOnce sync.Once
}

func startE2ESSHServer(t *testing.T, authorizedPubs ...ssh.PublicKey) *e2eSSHServer {
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
	srv := &e2eSSHServer{
		ln:             ln,
		nursery:        n,
		hostSigner:     hostSigner,
		authorizedPubs: authorizedPubs,
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

func (s *e2eSSHServer) portString(t *testing.T) string {
	t.Helper()
	_, port, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		t.Fatalf("解析回环监听地址失败: %v", err)
	}
	return port
}

func (s *e2eSSHServer) Close() {
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

func (s *e2eSSHServer) usersSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seenUsers...)
}

func (s *e2eSSHServer) dialsSnapshot() int32 {
	return s.dialCount.Load()
}

func (s *e2eSSHServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.dialCount.Add(1)
		s.trackConn(conn, true)
		if gErr := s.nursery.Go(func(context.Context) error {
			defer s.trackConn(conn, false)
			s.serveConn(conn)
			return nil
		}); gErr != nil {
			s.trackConn(conn, false)
			_ = conn.Close()
			return
		}
	}
}

func (s *e2eSSHServer) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

func (s *e2eSSHServer) buildServerConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			presented := key.Marshal()
			for _, allowed := range s.authorizedPubs {
				if bytes.Equal(presented, allowed.Marshal()) {
					s.mu.Lock()
					s.seenUsers = append(s.seenUsers, meta.User())
					s.mu.Unlock()
					return &ssh.Permissions{}, nil
				}
			}
			return nil, errors.New("unauthorized public key")
		},
	}
	cfg.AddHostKey(s.hostSigner)
	return cfg
}

func (s *e2eSSHServer) serveConn(raw net.Conn) {
	defer func() { _ = raw.Close() }()
	sConn, chans, reqs, err := ssh.NewServerConn(raw, s.buildServerConfig())
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	user := sConn.User()

	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			ssh.DiscardRequests(reqs)
			return nil
		}); gErr != nil {
			return gErr
		}
		for newCh := range chans {
			ch := newCh
			if gErr := n.Go(func(context.Context) error {
				s.handleChannel(ch, user)
				return nil
			}); gErr != nil {
				_ = ch.Reject(ssh.ResourceShortage, "nursery stopped")
			}
		}
		return nil
	})
}

func (s *e2eSSHServer) handleChannel(newCh ssh.NewChannel, user string) {
	if newCh.ChannelType() != "session" {
		_ = newCh.Reject(ssh.UnknownChannelType, "unsupported channel")
		return
	}
	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer func() { _ = ch.Close() }()

	envMap := make(map[string]string)
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			s.dispatchSessionReq(n, ch, req, user, envMap)
		}
		return nil
	})
}

func (s *e2eSSHServer) dispatchSessionReq(n *conc.Nursery, ch ssh.Channel, req *ssh.Request, user string, envMap map[string]string) {
	switch req.Type {
	case "env":
		var p struct{ Name, Value string }
		if ssh.Unmarshal(req.Payload, &p) == nil {
			envMap[p.Name] = p.Value
		}
		replySSHReq(req, true)
	case "pty-req":
		replySSHReq(req, true)
	case "exec":
		var p struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &p)
		replySSHReq(req, true)
		val := envMap["XOPS_E2E_ENV"]
		_ = n.Go(func(context.Context) error {
			runStubExec(ch, user, val, p.Command)
			return nil
		})
	case "shell":
		replySSHReq(req, true)
		_ = n.Go(func(context.Context) error {
			runStubShell(ch)
			return nil
		})
	default:
		replySSHReq(req, false)
	}
}

func runStubExec(ch ssh.Channel, user, envVal, cmd string) {
	defer func() { _ = ch.Close() }()
	switch cmd {
	case "show-env":
		_, _ = io.WriteString(ch, "user="+user+"\nXOPS_E2E_ENV="+envVal+"\n")
		sendExitStatus(ch, 0)
	case "fail-42":
		_, _ = io.WriteString(ch, "out:fail-42\n")
		_, _ = io.WriteString(ch.Stderr(), "err:boom-42\n")
		sendExitStatus(ch, 42)
	default:
		_, _ = io.WriteString(ch, "exec:"+cmd+"\n")
		sendExitStatus(ch, 0)
	}
}

func runStubShell(ch ssh.Channel) {
	defer func() { _ = ch.Close() }()
	_, _ = io.WriteString(ch, "shell-ready\n")
	sc := bufio.NewScanner(ch)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "exit" {
			break
		}
		_, _ = io.WriteString(ch, "echo:"+line+"\n")
	}
	sendExitStatus(ch, 0)
}

func replySSHReq(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func sendExitStatus(ch ssh.Channel, code uint32) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], code)
	_, _ = ch.SendRequest("exit-status", false, payload[:])
}

func generateE2EEd25519Key(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey 失败: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey 失败: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKey 失败: %v", err)
	}
	return signer, pem.EncodeToMemory(block)
}

func buildCompiledXops(t *testing.T, ldflags string) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "xops")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	args := []string{"build"}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", binPath, ".")
	cmd := exec.Command("go", args...)
	cmd.Env = mergeEnv(os.Environ(), map[string]string{"CGO_ENABLED": "0"})
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("编译真实 xops 二进制失败: %v\n%s", err, string(out))
	}
	return binPath
}

func mergeEnv(base []string, overrides map[string]string) []string {
	out := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		skip := false
		for okKey := range overrides {
			if strings.EqualFold(k, okKey) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, kv)
		}
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

type isolatedTestEnv struct {
	homeDir  pathalg.LocalDir
	sshDir   pathalg.LocalDir
	xopsHome pathalg.LocalDir
	env      []string
}

// newIsolatedOwnerOnlyEnv 经 osfs.EnsureRoot(..., 0o700) 在临时目录创建隔离 HOME / .ssh / XOPS_HOME，
// 确保在原生 Windows 11 上具备 Owner-Only DACL，与 Linux/macOS/FreeBSD 全平台一致。
func newIsolatedOwnerOnlyEnv(t *testing.T) isolatedTestEnv {
	t.Helper()
	rootFS := osfs.NewScopedRootFS()
	tmpDir, err := pathalg.ParseLocalDir(t.TempDir())
	if err != nil {
		t.Fatalf("ParseLocalDir(TempDir) 失败: %v", err)
	}
	homeDir, err := tmpDir.JoinComponent("home")
	if err != nil {
		t.Fatalf("JoinComponent(home) 失败: %v", err)
	}
	sshDir, err := homeDir.JoinComponent(".ssh")
	if err != nil {
		t.Fatalf("JoinComponent(.ssh) 失败: %v", err)
	}
	xopsHome, err := tmpDir.JoinComponent("xops-home")
	if err != nil {
		t.Fatalf("JoinComponent(xops-home) 失败: %v", err)
	}
	for _, d := range []pathalg.LocalDir{homeDir, sshDir, xopsHome} {
		if err := rootFS.EnsureRoot(d, 0o700); err != nil {
			t.Fatalf("EnsureRoot(%s, 0700) 失败: %v", d, err)
		}
	}
	nativeHome := filepath.FromSlash(homeDir.String())
	nativeXops := filepath.FromSlash(xopsHome.String())
	env := mergeEnv(os.Environ(), map[string]string{
		"HOME":         nativeHome,
		"USERPROFILE":  nativeHome,
		"XOPS_HOME":    nativeXops,
		"XOPS_E2E_ENV": "hello-v2",
		"XOPS_LANG":    "en",
	})
	return isolatedTestEnv{
		homeDir:  homeDir,
		sshDir:   sshDir,
		xopsHome: xopsHome,
		env:      env,
	}
}

func runCompiledXops(binPath string, env []string, stdin io.Reader, args ...string) (stdout, stderr string, exitCode int, err error) {
	cmd := exec.Command(binPath, args...)
	cmd.Env = env
	cmd.Stdin = stdin
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	if runErr == nil {
		return outBuf.String(), errBuf.String(), 0, nil
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
		return outBuf.String(), errBuf.String(), exitErr.ExitCode(), nil
	}
	return outBuf.String(), errBuf.String(), -1, runErr
}

func writeRootFile(t *testing.T, dir pathalg.LocalDir, name string, data []byte) string {
	t.Helper()
	rootFS := osfs.NewScopedRootFS()
	dest, err := pathalg.ParseLocalRootedDest(name)
	if err != nil {
		t.Fatalf("ParseLocalRootedDest(%s) 失败: %v", name, err)
	}
	err = rootFS.WithRoot(dir, func(root ports.RootHandle) error {
		return root.AtomicReplace(dest, 0o600, func(w io.Writer) error {
			_, wErr := w.Write(data)
			return wErr
		})
	})
	if err != nil {
		t.Fatalf("写入沙箱文件 %s 失败: %v", name, err)
	}
	joined, err := dir.JoinComponent(name)
	if err != nil {
		t.Fatalf("JoinComponent(%s) 失败: %v", name, err)
	}
	return filepath.FromSlash(joined.String())
}

func TestE2E_CompiledBinaryVersionAndFallback(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1. 验证经 -ldflags 注入的构建元信息，并确认 xops version 绝不触碰或创建 XOPS_HOME。
	ldflags := "-X 'main.buildVersion=v2.5.0-e2e' -X 'main.buildCommit=deadbeef' -X 'main.buildTime=2026-11-25T10:20:30Z'"
	binWithLD := buildCompiledXops(t, ldflags)
	unusedXopsHome := filepath.Join(t.TempDir(), "never-created-xops-home")
	env := mergeEnv(os.Environ(), map[string]string{
		"XOPS_HOME": unusedXopsHome,
		"XOPS_LANG": "en",
	})

	stdout, stderr, code, err := runCompiledXops(binWithLD, env, nil, "version")
	if err != nil || code != 0 {
		t.Fatalf("xops version 失败: code=%d err=%v stderr=%q", code, err, stderr)
	}
	for _, want := range []string{"xops version v2.5.0-e2e", "commit: deadbeef", "built:  2026-11-25T10:20:30Z", "go:     go"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("xops version 输出缺少 %q，实际=%q", want, stdout)
		}
	}
	if _, statErr := os.Stat(unusedXopsHome); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("xops version 绝不应创建 XOPS_HOME，statErr=%v", statErr)
	}

	// 2. 验证未传 -ldflags 时的 runtime/debug.ReadBuildInfo() 回退路径。
	binFallback := buildCompiledXops(t, "")
	fbOut, fbErr, fbCode, err := runCompiledXops(binFallback, env, nil, "version")
	if err != nil || fbCode != 0 {
		t.Fatalf("无 ldflags xops version 失败: code=%d err=%v stderr=%q", fbCode, err, fbErr)
	}
	for _, want := range []string{"xops version ", "commit: ", "built:  ", "go:     go"} {
		if !strings.Contains(fbOut, want) {
			t.Fatalf("无 ldflags xops version 输出缺少 %q，实际=%q", want, fbOut)
		}
	}
}

func TestE2E_CompiledBinarySSHExecFlagsAuditAndShell(t *testing.T) {
	defer goleak.VerifyNone(t)

	binPath := buildCompiledXops(t, "-X 'main.buildVersion=v2.5.0-e2e'")
	clientSigner, keyPEM := generateE2EEd25519Key(t)
	srv := startE2ESSHServer(t, clientSigner.PublicKey())
	defer srv.Close()

	iso := newIsolatedOwnerOnlyEnv(t)
	keyPath := writeRootFile(t, iso.sshDir, "id_e2e", keyPEM)
	portStr := srv.portString(t)

	// 场景 1：单命令执行 + OpenSSH 标志（-p/-l/-i/-o）+ SendEnv + accept-new 写入隔离 known_hosts。
	stdout, stderr, code, err := runCompiledXops(
		binPath, iso.env, nil,
		"ssh",
		"-p", portStr,
		"-l", "deploy",
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "SendEnv=XOPS_E2E_ENV",
		"127.0.0.1",
		"show-env",
	)
	if err != nil || code != 0 || stderr != "" {
		t.Fatalf("场景 1 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	if stdout != "user=deploy\nXOPS_E2E_ENV=hello-v2\n" {
		t.Fatalf("场景 1 输出失配: %q", stdout)
	}

	// 场景 2：非零远端退出码（42）+ stdout/stderr 精确分离 + StrictHostKeyChecking=yes 复验已落盘主机公钥。
	stdout2, stderr2, code2, err := runCompiledXops(
		binPath, iso.env, nil,
		"ssh",
		"-p", portStr,
		"-l", "deploy",
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"127.0.0.1",
		"fail-42",
	)
	if err != nil || code2 != 42 {
		t.Fatalf("场景 2 退出码应为 42: code=%d err=%v stdout=%q stderr=%q", code2, err, stdout2, stderr2)
	}
	if stdout2 != "out:fail-42\n" || stderr2 != "err:boom-42\n" {
		t.Fatalf("场景 2 流输出失配: stdout=%q stderr=%q", stdout2, stderr2)
	}

	// 场景 3：-F <configfile> 显式 OpenSSH 虚拟主机配置覆写端到端链路。
	cfgText := "Host loopback-alias\n" +
		"  HostName 127.0.0.1\n" +
		"  Port " + portStr + "\n" +
		"  User cfguser\n" +
		"  IdentityFile \"" + filepath.ToSlash(keyPath) + "\"\n" +
		"  IdentitiesOnly yes\n" +
		"  StrictHostKeyChecking yes\n"
	cfgPath := writeRootFile(t, iso.homeDir, "custom_ssh_config", []byte(cfgText))
	stdout3, stderr3, code3, err := runCompiledXops(
		binPath, iso.env, nil,
		"ssh", "-F", cfgPath, "loopback-alias", "echo", "hello", "world",
	)
	if err != nil || code3 != 0 || stderr3 != "" || stdout3 != "exec:echo hello world\n" {
		t.Fatalf("场景 3 (-F 虚拟主机) 失败: code=%d err=%v stdout=%q stderr=%q", code3, err, stdout3, stderr3)
	}

	// 场景 4：管道/交互式 Shell 往返（-T 禁用 PTY，确定性 stdin/stdout 往返与正常退出 0）。
	stdout4, stderr4, code4, err := runCompiledXops(
		binPath, iso.env, strings.NewReader("ping-one\nping-two\nexit\n"),
		"ssh",
		"-T",
		"-p", portStr,
		"-l", "deploy",
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"127.0.0.1",
	)
	if err != nil || code4 != 0 || stderr4 != "" {
		t.Fatalf("场景 4 (Shell 往返) 失败: code=%d err=%v stdout=%q stderr=%q", code4, err, stdout4, stderr4)
	}
	if stdout4 != "shell-ready\necho:ping-one\necho:ping-two\n" {
		t.Fatalf("场景 4 Shell 输出失配: %q", stdout4)
	}

	// 验证真实服务端收到了所有 4 次认证用户，且审计日志完整闭合（Authorized+Finalized）与 run/*.lock 干净排空。
	if users := srv.usersSnapshot(); len(users) != 4 || users[2] != "cfguser" {
		t.Fatalf("服务端认证用户序列异常: %v", users)
	}
	assertAuditLogAndCleanLocks(t, iso.xopsHome, 4)
}

func assertAuditLogAndCleanLocks(t *testing.T, xopsHome pathalg.LocalDir, wantOps int) {
	t.Helper()
	entries := readValidAuditEntries(t, xopsHome)
	authCount := make(map[security.OperationID]int)
	finCount := make(map[security.OperationID]int)
	for _, entry := range entries {
		switch entry.Phase() {
		case ports.AuditPhaseAuthorized:
			authCount[entry.OperationID()]++
		case ports.AuditPhaseFinalized:
			finCount[entry.OperationID()]++
		}
	}
	if len(authCount) != wantOps || len(finCount) != wantOps || len(entries) != wantOps*2 {
		t.Fatalf("审计记录数异常: total=%d auth=%d fin=%d wantOps=%d", len(entries), len(authCount), len(finCount), wantOps)
	}
	for opID := range authCount {
		if authCount[opID] != 1 || finCount[opID] != 1 {
			t.Fatalf("操作 %s 审计阶段未严格成对闭合: auth=%d fin=%d", opID, authCount[opID], finCount[opID])
		}
	}
	assertNoRemainingLocks(t, xopsHome)
}

func readValidAuditEntries(t *testing.T, xopsHome pathalg.LocalDir) []ports.AuditEntry {
	t.Helper()
	auditPath := filepath.Join(filepath.FromSlash(xopsHome.String()), "audit.jsonl")
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("读取 audit.jsonl 失败: %v", err)
	}
	var out []ports.AuditEntry
	lineNo := 0
	for line := range bytes.SplitSeq(raw, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		lineNo++
		var entry ports.AuditEntry
		if err := jsonv2.Unmarshal(trimmed, &entry); err != nil {
			t.Fatalf("解析第 %d 行审计记录失败: %v (raw=%q)", lineNo, err, string(trimmed))
		}
		if !entry.IsValid() {
			t.Fatalf("第 %d 行审计记录无效", lineNo)
		}
		out = append(out, entry)
	}
	return out
}

func assertNoRemainingLocks(t *testing.T, xopsHome pathalg.LocalDir) {
	t.Helper()
	runDir := filepath.Join(filepath.FromSlash(xopsHome.String()), "run")
	entries, err := os.ReadDir(runDir)
	if err != nil {
		t.Fatalf("读取 run 目录失败: %v", err)
	}
	for _, de := range entries {
		if strings.HasSuffix(de.Name(), ".lock") {
			t.Fatalf("检测到未排空残留锁文件: %s (共 %s 项)", de.Name(), strconv.Itoa(len(entries)))
		}
	}
}

func TestE2E_CompiledBinaryReconcilesCrashedAuditLock(t *testing.T) {
	defer goleak.VerifyNone(t)

	binPath := buildCompiledXops(t, "-X 'main.buildVersion=v2.5.0-e2e'")
	clientSigner, keyPEM := generateE2EEd25519Key(t)
	srv := startE2ESSHServer(t, clientSigner.PublicKey())
	defer srv.Close()

	iso := newIsolatedOwnerOnlyEnv(t)
	keyPath := writeRootFile(t, iso.sshDir, "id_e2e", keyPEM)
	deadOpID := seedCrashedProcessAuditState(t, iso.xopsHome)

	stdout, stderr, code, err := runCompiledXops(
		binPath, iso.env, nil,
		"ssh",
		"-p", srv.portString(t),
		"-l", "deploy",
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"127.0.0.1",
		"echo", "after-crash",
	)
	if err != nil || code != 0 || stderr != "" || stdout != "exec:echo after-crash\n" {
		t.Fatalf("崩溃对账后执行 ssh 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	assertCrashedOpReconciled(t, iso.xopsHome, deadOpID)
}

func seedCrashedProcessAuditState(t *testing.T, xopsHome pathalg.LocalDir) security.OperationID {
	t.Helper()
	deadProcID, err := ports.NewProcessInstanceIDFrom(rand.Reader)
	if err != nil {
		t.Fatalf("NewProcessInstanceIDFrom 失败: %v", err)
	}
	traceID, err := security.NewTraceIDFrom(rand.Reader)
	if err != nil {
		t.Fatalf("NewTraceIDFrom 失败: %v", err)
	}
	opID, err := security.NewOperationIDFrom(rand.Reader)
	if err != nil {
		t.Fatalf("NewOperationIDFrom 失败: %v", err)
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute,
		Tool:       "ssh",
		Action:     "exec",
		NodeID:     "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("NewOperationBinding 失败: %v", err)
	}
	authEntry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID:   deadProcID,
		TraceID:     traceID,
		OperationID: opID,
		Phase:       ports.AuditPhaseAuthorized,
		Outcome:     ports.AuditOutcomePending,
		Risk:        security.RiskModerate,
		Decision:    security.DecisionKindAllow,
		Binding:     binding,
		Timestamp:   time.Now().UTC().Add(-time.Minute).Round(0),
	})
	if err != nil {
		t.Fatalf("NewAuditEntry 失败: %v", err)
	}
	rawJSON, err := authEntry.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON 失败: %v", err)
	}
	rootFS := osfs.NewScopedRootFS()
	runDirDest, _ := pathalg.ParseLocalRootedDest("run")
	lockDest, _ := runDirDest.JoinComponent(deadProcID.String() + ".lock")
	auditDest, _ := pathalg.ParseLocalRootedDest("audit.jsonl")
	err = rootFS.WithRoot(xopsHome, func(root ports.RootHandle) error {
		if mErr := root.MkdirAll(runDirDest, 0o700); mErr != nil {
			return mErr
		}
		if aErr := root.AppendLine(auditDest, 0o600, rawJSON); aErr != nil {
			return aErr
		}
		return root.AtomicReplace(lockDest, 0o600, func(w io.Writer) error {
			_, wErr := io.WriteString(w, "+"+opID.String()+"\n")
			return wErr
		})
	})
	if err != nil {
		t.Fatalf("预置崩溃进程审计与锁状态失败: %v", err)
	}
	return opID
}

func assertCrashedOpReconciled(t *testing.T, xopsHome pathalg.LocalDir, deadOpID security.OperationID) {
	t.Helper()
	entries := readValidAuditEntries(t, xopsHome)
	foundAborted := false
	for _, entry := range entries {
		if entry.OperationID() == deadOpID &&
			entry.Phase() == ports.AuditPhaseFinalized &&
			entry.Outcome() == ports.AuditOutcomeAbortedByCrash {
			foundAborted = true
		}
	}
	if !foundAborted {
		t.Fatalf("未在 audit.jsonl 中发现崩溃操作 %s 补写的 AbortedByCrash 记录（总记录=%d）", deadOpID, len(entries))
	}
	assertNoRemainingLocks(t, xopsHome)
}

func TestE2E_CompiledBinaryConfigFileFlagFailClosedAndNone(t *testing.T) {
	defer goleak.VerifyNone(t)

	binPath := buildCompiledXops(t, "-X 'main.buildVersion=v2.5.0-e2e'")
	clientSigner, keyPEM := generateE2EEd25519Key(t)
	srv := startE2ESSHServer(t, clientSigner.PublicKey())
	defer srv.Close()

	iso := newIsolatedOwnerOnlyEnv(t)
	keyPath := writeRootFile(t, iso.sshDir, "id_e2e", keyPEM)
	portStr := srv.portString(t)

	// 1. 显式 -F <不存在文件> 必须严格失败关闭：退出码 255、stderr 提及配置路径、0 次 SSH 拨号、0 审计落盘。
	missingCfg := filepath.Join(filepath.FromSlash(iso.homeDir.String()), "missing_strict.cfg")
	stdout, stderr, code, err := runCompiledXops(
		binPath, iso.env, nil,
		"ssh",
		"-F", missingCfg,
		"-p", portStr,
		"-l", "deploy",
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"127.0.0.1",
		"echo", "should-not-run",
	)
	if err != nil || code != 255 || stdout != "" {
		t.Fatalf("缺失显式 -F 必须返回退出码 255 且无 stdout: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	if !strings.Contains(stderr, "missing_strict.cfg") {
		t.Fatalf("缺失显式 -F stderr 应包含配置路径，实际=%q", stderr)
	}
	if dials := srv.dialsSnapshot(); dials != 0 {
		t.Fatalf("缺失显式 -F 禁止建立任何 SSH 连接，实际拨号=%d", dials)
	}
	auditPath := filepath.Join(filepath.FromSlash(iso.xopsHome.String()), "audit.jsonl")
	if _, statErr := os.Stat(auditPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("缺失显式 -F 应在初始化 AuditSink/Engine 前即拒绝，statErr=%v", statErr)
	}

	// 2. 在默认 ~/.ssh/config 写入非法指令，再以 `-F none` 显式禁用加载，证明完全未读取默认配置且正常执行。
	poisonCfg := "Host *\n  BrokenUnclosedQuote \"never-closed\n"
	writeRootFile(t, iso.sshDir, "config", []byte(poisonCfg))
	stdout2, stderr2, code2, err := runCompiledXops(
		binPath, iso.env, nil,
		"ssh",
		"-F", "none",
		"-p", portStr,
		"-l", "deploy",
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "SendEnv=XOPS_E2E_ENV",
		"127.0.0.1",
		"show-env",
	)
	if err != nil || code2 != 0 || stderr2 != "" || stdout2 != "user=deploy\nXOPS_E2E_ENV=hello-v2\n" {
		t.Fatalf("-F none 禁用配置执行失败: code=%d err=%v stdout=%q stderr=%q", code2, err, stdout2, stderr2)
	}
	if dials := srv.dialsSnapshot(); dials != 1 {
		t.Fatalf("-F none 应精确拨号 1 次，实际=%d", dials)
	}
	assertAuditLogAndCleanLocks(t, iso.xopsHome, 1)
}
