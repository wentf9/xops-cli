package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	spVaultHelperModeEnv = "XOPS_TEST_SP_VAULT_MODE"
	spVaultHelperFileEnv = "XOPS_TEST_SP_VAULT_FILE"
)

// spExecRecord 记录回环 SSH 服务端收到的单次 exec 请求报文（命令载荷、SendEnv 映射与 PTY 标志）。
type spExecRecord struct {
	Command string
	Env     map[string]string
	HasPTY  bool
}

// spSSHServer 是面向 Shell/提权回归套件的进程内真实回环 SSH 服务端（127.0.0.1:0）；
// 全协程受 core/conc.Nursery 监督（0 裸 go、0 time.Sleep、0 外部主机依赖）。
type spSSHServer struct {
	ln       net.Listener
	port     string
	nursery  *conc.Nursery
	ctx      context.Context
	cancel   context.CancelFunc
	hostKey  ssh.Signer
	allowPub ssh.PublicKey
	handler  func(ctx context.Context, ch ssh.Channel, rec spExecRecord)

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	records   []spExecRecord
	dials     atomic.Int32
	closeOnce sync.Once
}

func startSPSSHServer(
	t *testing.T,
	allowPub ssh.PublicKey,
	handler func(ctx context.Context, ch ssh.Channel, rec spExecRecord),
) *spSSHServer {
	t.Helper()
	hostKey, _ := generateGracefulEd25519Key(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听 127.0.0.1:0 失败: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("解析回环端口失败: %v", err)
	}
	srvCtx, cancel := context.WithCancel(context.Background())
	n, err := conc.NewNursery(srvCtx)
	if err != nil {
		cancel()
		_ = ln.Close()
		t.Fatalf("NewNursery 失败: %v", err)
	}
	srv := &spSSHServer{
		ln:       ln,
		port:     port,
		nursery:  n,
		ctx:      srvCtx,
		cancel:   cancel,
		hostKey:  hostKey,
		allowPub: allowPub,
		handler:  handler,
		conns:    make(map[net.Conn]struct{}),
	}
	if err := n.Go(func(context.Context) error {
		srv.acceptLoop()
		return nil
	}); err != nil {
		cancel()
		_ = ln.Close()
		_ = n.Close()
		t.Fatalf("启动回环服务端 accept 循环失败: %v", err)
	}
	return srv
}

func (s *spSSHServer) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		_ = s.nursery.Close()
	})
}

func (s *spSSHServer) snapshotRecords() []spExecRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.records)
}

func (s *spSSHServer) dialsCount() int32 { return s.dials.Load() }

func (s *spSSHServer) acceptLoop() {
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.dials.Add(1)
		s.trackConn(raw, true)
		if gErr := s.nursery.Go(func(context.Context) error {
			defer s.trackConn(raw, false)
			s.serveConn(raw)
			return nil
		}); gErr != nil {
			s.trackConn(raw, false)
			_ = raw.Close()
			return
		}
	}
}

func (s *spSSHServer) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

func (s *spSSHServer) serveConn(raw net.Conn) {
	defer func() { _ = raw.Close() }()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), s.allowPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unauthorized public key")
		},
	}
	cfg.AddHostKey(s.hostKey)
	sConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		_ = n.Go(func(context.Context) error { ssh.DiscardRequests(reqs); return nil })
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

func (s *spSSHServer) handleChannel(newCh ssh.NewChannel) {
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
	hasPTY := false
	_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for req := range reqs {
			s.dispatchSessionReq(n, ch, req, envMap, &hasPTY)
		}
		return nil
	})
}

func (s *spSSHServer) dispatchSessionReq(
	n *conc.Nursery,
	ch ssh.Channel,
	req *ssh.Request,
	envMap map[string]string,
	hasPTY *bool,
) {
	switch req.Type {
	case "env":
		var p struct{ Name, Value string }
		if ssh.Unmarshal(req.Payload, &p) == nil {
			envMap[p.Name] = p.Value
		}
		spReplySSHReq(req, true)
	case "pty-req":
		*hasPTY = true
		spReplySSHReq(req, true)
	case "exec":
		var p struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &p)
		spReplySSHReq(req, true)
		rec := spExecRecord{Command: p.Command, Env: cloneStringMap(envMap), HasPTY: *hasPTY}
		s.mu.Lock()
		s.records = append(s.records, rec)
		s.mu.Unlock()
		_ = n.Go(func(context.Context) error {
			defer func() { _ = ch.Close() }()
			s.handler(s.ctx, ch, rec)
			return nil
		})
	default:
		spReplySSHReq(req, false)
	}
}

func spReplySSHReq(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func spSendExitStatus(ch ssh.Channel, code uint32) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], code)
	_, _ = ch.SendRequest("exit-status", false, payload[:])
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// spWriteTestKey 将临时测试私钥按 0600 权限写入隔离 .ssh 目录，保证全平台（含 Windows DACL）一致。
func spWriteTestKey(t *testing.T, homeDir pathalg.LocalDir, name string, keyPEM []byte) string {
	t.Helper()
	sshDir, err := homeDir.JoinComponent(".ssh")
	if err != nil {
		t.Fatalf("JoinComponent(.ssh): %v", err)
	}
	rootFS := osfs.NewScopedRootFS()
	if err := rootFS.EnsureRoot(sshDir, 0o700); err != nil {
		t.Fatalf("EnsureRoot(.ssh): %v", err)
	}
	dest, err := pathalg.ParseLocalRootedDest(name)
	if err != nil {
		t.Fatalf("ParseLocalRootedDest(%s): %v", name, err)
	}
	if err := rootFS.WithRoot(sshDir, func(root ports.RootHandle) error {
		return root.AtomicReplace(dest, 0o600, func(w io.Writer) error {
			_, wErr := w.Write(keyPEM)
			return wErr
		})
	}); err != nil {
		t.Fatalf("写入测试私钥 %s 失败: %v", name, err)
	}
	keyDir, err := sshDir.JoinComponent(name)
	if err != nil {
		t.Fatalf("JoinComponent(%s): %v", name, err)
	}
	return filepath.FromSlash(keyDir.String())
}

// spPrivEmulationCfg 控制回环 SSH 提权仿真服务端的 sudo/su 协议行为，
// 覆盖标准 sudo -p 随机令牌、sudo-rs 封套与掩码回显、su 质询、错误口令拒绝与就绪后阻塞/断连。
type spPrivEmulationCfg struct {
	expectedPass   string
	sudoRSStyle    bool
	hangAfterReady bool
	dropAfterReady bool
	exitCode       uint32

	mu           sync.Mutex
	promptNonces []string
	execCount    atomic.Int32
}

func (c *spPrivEmulationCfg) snapshotNonces() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.promptNonces)
}

func (c *spPrivEmulationCfg) recordNonce(tok string) {
	c.mu.Lock()
	c.promptNonces = append(c.promptNonces, tok)
	c.mu.Unlock()
}

func newSPPrivEmulationHandler(cfg *spPrivEmulationCfg) func(context.Context, ssh.Channel, spExecRecord) {
	return func(ctx context.Context, ch ssh.Channel, rec spExecRecord) {
		ctrlW := io.Writer(ch.Stderr())
		if rec.HasPTY {
			ctrlW = ch
		}
		switch {
		case strings.HasPrefix(rec.Command, "LC_ALL=C sudo "):
			emulateSudoSession(ctx, cfg, ch, ctrlW, rec.Command)
		case strings.HasPrefix(rec.Command, "LC_ALL=C su "):
			emulateSuSession(ctx, cfg, ch, ctrlW, rec.Command)
		default:
			_, _ = io.WriteString(ch.Stderr(), "unexpected non-privilege command\n")
			spSendExitStatus(ch, 99)
		}
	}
}

func emulateSudoSession(ctx context.Context, cfg *spPrivEmulationCfg, ch ssh.Channel, ctrlW io.Writer, cmd string) {
	promptTok := extractBracketToken(cmd, "[xops-priv-prompt-")
	readyTok := extractBracketToken(cmd, "[xops-priv-ready-")
	if promptTok == "" || readyTok == "" {
		_, _ = io.WriteString(ch.Stderr(), "missing priv handshake tokens\n")
		spSendExitStatus(ch, 2)
		return
	}
	cfg.recordNonce(promptTok)
	if cfg.sudoRSStyle {
		_, _ = io.WriteString(ctrlW, "[sudo: "+promptTok+"] password: ")
	} else {
		_, _ = io.WriteString(ctrlW, promptTok)
	}
	pass, rErr := readPassLine(ch)
	if cfg.sudoRSStyle {
		_, _ = io.WriteString(ctrlW, "***\r\n")
	}
	if rErr != nil || pass != cfg.expectedPass {
		_, _ = io.WriteString(ctrlW, "Sorry, try again.\n"+promptTok)
		spSendExitStatus(ch, 1)
		return
	}
	finishElevatedSession(ctx, cfg, ch, ctrlW, readyTok, "uid=0(root) method=sudo\n")
}

func emulateSuSession(ctx context.Context, cfg *spPrivEmulationCfg, ch ssh.Channel, ctrlW io.Writer, cmd string) {
	readyTok := extractBracketToken(cmd, "[xops-priv-ready-")
	if readyTok == "" {
		_, _ = io.WriteString(ch.Stderr(), "missing ready token\n")
		spSendExitStatus(ch, 2)
		return
	}
	_, _ = io.WriteString(ctrlW, "Password: ")
	pass, rErr := readPassLine(ch)
	if rErr != nil || pass != cfg.expectedPass {
		_, _ = io.WriteString(ctrlW, "su: Authentication failure\n")
		spSendExitStatus(ch, 1)
		return
	}
	finishElevatedSession(ctx, cfg, ch, ctrlW, readyTok, "uid=0(root) method=su\n")
}

func finishElevatedSession(
	ctx context.Context,
	cfg *spPrivEmulationCfg,
	ch ssh.Channel,
	ctrlW io.Writer,
	readyTok string,
	body string,
) {
	cfg.execCount.Add(1)
	_, _ = io.WriteString(ctrlW, readyTok)
	if cfg.dropAfterReady {
		// 模拟远端命令已启动（就绪帧已发出）但未发 exit-status 即断连的场景。
		return
	}
	if cfg.hangAfterReady {
		// 发出确定性标记后阻塞至服务端上下文结束或客户端关闭通道，用于零 sleep 验证就绪后取消 -> OutcomeUnknown。
		_, _ = io.WriteString(ch, "post-ready-started\n")
		waitChannelOrCtx(ctx, ch)
		return
	}
	_, _ = io.WriteString(ch, body)
	spSendExitStatus(ch, cfg.exitCode)
}

func waitChannelOrCtx(ctx context.Context, ch ssh.Channel) {
	// 注意：客户端在观测到 readyTok 后若无 postStdin 会立即发送 CHANNEL_EOF，
	// 因此服务端不可因 stdin EOF 提前返回，必须阻塞至 ctx.Done()（由客户端断开或服务端关闭触发）。
	<-ctx.Done()
	_ = ch.Close()
}

func readPassLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func extractBracketToken(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	rest := s[idx:]
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return ""
	}
	return rest[:end+1]
}

// spVaultHelperReq / spVaultHelperResp 对应 internal/host/vault/helper 的 v2 JSON 协议。
type spVaultHelperReq struct {
	ProtocolVersion int    `json:"protocol_version"`
	NonInteractive  bool   `json:"non_interactive"`
	Action          string `json:"action"`
	Store           string `json:"store"`
	Item            string `json:"item"`
}

type spVaultHelperResp struct {
	SecretB64 *string `json:"secret_b64,omitzero"`
	Code      string  `json:"code,omitzero"`
}

// TestShellPrivVaultHelperSubprocess 为跨平台（Linux/Windows/macOS/FreeBSD）external_helper
// 凭据库提供自托管测试子进程入口；未设置环境变量时立即返回无副作用。
func TestShellPrivVaultHelperSubprocess(t *testing.T) {
	if os.Getenv(spVaultHelperModeEnv) != "serve" {
		return
	}
	rawIn, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(4)
	}
	var req spVaultHelperReq
	if err := jsonv2.Unmarshal(rawIn, &req); err != nil || req.ProtocolVersion != 2 || req.Action != "get" {
		writeSPHelperJSONExit(spVaultHelperResp{Code: "invalid"}, 1)
	}
	data, err := os.ReadFile(os.Getenv(spVaultHelperFileEnv))
	if err != nil {
		writeSPHelperJSONExit(spVaultHelperResp{Code: "unavailable"}, 1)
	}
	var table map[string]string
	if err := jsonv2.Unmarshal(data, &table); err != nil {
		writeSPHelperJSONExit(spVaultHelperResp{Code: "unavailable"}, 1)
	}
	b64Val, ok := table[req.Store+"/"+req.Item]
	if !ok {
		writeSPHelperJSONExit(spVaultHelperResp{Code: "not-found"}, 1)
	}
	writeSPHelperJSONExit(spVaultHelperResp{SecretB64: &b64Val}, 0)
}

func writeSPHelperJSONExit(resp spVaultHelperResp, code int) {
	b, _ := jsonv2.Marshal(resp)
	_, _ = os.Stdout.Write(b)
	os.Exit(code)
}

// spSetupExternalHelperVault 在隔离 xopsHome 下写入配置了 external_helper 凭据库的 config.yaml，
// 并生成只读明文映射文件（以 Base64 落盘于独立临时目录），返回该映射文件路径 vaultFilePath。
func spSetupExternalHelperVault(t *testing.T, xopsHome pathalg.LocalDir, secrets map[string]string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	encoded := make(map[string]string, len(secrets))
	for k, v := range secrets {
		encoded[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	rawMap, err := jsonv2.Marshal(encoded)
	if err != nil {
		t.Fatalf("Marshal secrets table: %v", err)
	}
	vaultFile := filepath.Join(t.TempDir(), "sp-vault-secrets.json")
	if err := os.WriteFile(vaultFile, rawMap, 0o600); err != nil {
		t.Fatalf("WriteFile(sp-vault-secrets.json): %v", err)
	}
	// 使用 YAML 单引号包裹可执行路径，确保 Windows 反斜杠路径不被转义破坏。
	yamlExe := "'" + strings.ReplaceAll(exe, "'", "''") + "'"
	cfgYAML := "version: 2\n" +
		"vault:\n" +
		"  default_store: extvault\n" +
		"  stores:\n" +
		"    extvault:\n" +
		"      kind: external_helper\n" +
		"      command: " + yamlExe + "\n" +
		"      args:\n" +
		"        - '-test.run=^TestShellPrivVaultHelperSubprocess$'\n" +
		"      timeout: 5s\n"
	rootFS := osfs.NewScopedRootFS()
	cfgDest, _ := pathalg.ParseLocalRootedDest("config.yaml")
	if err := rootFS.WithRoot(xopsHome, func(root ports.RootHandle) error {
		return root.AtomicReplace(cfgDest, 0o600, func(w io.Writer) error {
			_, wErr := io.WriteString(w, cfgYAML)
			return wErr
		})
	}); err != nil {
		t.Fatalf("写入 external_helper config.yaml 失败: %v", err)
	}
	return vaultFile
}

// assertSecretNeverLeaked 严格断言提权明文口令绝不出现在 stdout、stderr 或 audit.jsonl 任何字节中，
// 同时验证 ~/.xops/run 下零残留进程锁文件。
func assertSecretNeverLeaked(t *testing.T, secretPlain, stdout, stderr string, xopsHome pathalg.LocalDir) {
	t.Helper()
	if strings.Contains(stdout, secretPlain) {
		t.Fatalf("安全违规：stdout 泄露了明文提权口令！stdout=%q", stdout)
	}
	if strings.Contains(stderr, secretPlain) {
		t.Fatalf("安全违规：stderr 泄露了明文提权口令！stderr=%q", stderr)
	}
	auditPath := filepath.Join(filepath.FromSlash(xopsHome.String()), "audit.jsonl")
	raw, err := os.ReadFile(auditPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("读取 audit.jsonl 失败: %v", err)
	}
	if bytes.Contains(raw, []byte(secretPlain)) {
		t.Fatalf("安全违规：audit.jsonl 泄露了明文提权口令！audit=%q", string(raw))
	}
	assertZeroRemainingLocks(t, xopsHome)
}
