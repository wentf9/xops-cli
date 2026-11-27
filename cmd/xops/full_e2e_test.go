package main_test

import (
	"bufio"
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
)

func shortE2EMuxSocketPath(t *testing.T, name string) string {
	t.Helper()
	parent := os.TempDir()
	if runtime.GOOS != "windows" && len(parent) >= 40 {
		parent = "/tmp"
	}
	dir, err := os.MkdirTemp(parent, "xm-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func reserveFreeLoopbackAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen 127.0.0.1:0: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func stopChildGracefully(cmd *exec.Cmd, cancel context.CancelFunc) {
	if runtime.GOOS != "windows" && cmd.Process != nil {
		_ = cmd.Process.Signal(os.Interrupt)
		return
	}
	cancel()
}

// TestE2E_CompiledBinarySCPAndSFTP 验证真实编译二进制的 scp 上传/下载、sftp 单步命令与交互式 sftpshell 闭环。
func TestE2E_CompiledBinarySCPAndSFTP(t *testing.T) {
	defer goleak.VerifyNone(t)
	binPath := buildCompiledXops(t, "-X 'main.buildVersion=v2.5.0-full'")
	clientSigner, keyPEM := generateE2EEd25519Key(t)
	srv := startFullE2ESSHServer(t, clientSigner.PublicKey())
	defer srv.Close()

	iso := newIsolatedOwnerOnlyEnv(t)
	keyPath := writeRootFile(t, iso.sshDir, "id_sftp", keyPEM)
	portStr := srv.portString(t)

	// 1. sftp write + read + stat + ls 单步命令。
	stdout, stderr, code, err := runCompiledXops(
		binPath, iso.env, strings.NewReader("hello-sftp-v2"),
		"sftp", "write", "-F", "none", "-p", portStr, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"--create-parents", "127.0.0.1", "/srv/hello.txt",
	)
	if err != nil || code != 0 {
		t.Fatalf("sftp write 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	stdout, stderr, code, err = runCompiledXops(
		binPath, iso.env, nil,
		"sftp", "read", "-F", "none", "-p", portStr, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
		"127.0.0.1", "/srv/hello.txt",
	)
	if err != nil || code != 0 || stdout != "hello-sftp-v2" {
		t.Fatalf("sftp read 失配: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}

	// 2. 交互式 SFTP Shell（RunSFTPShell + ScopedRootFS LocalFS 适配器）。
	shellIn := strings.NewReader("pwd\nls /srv\ncat /srv/hello.txt\nlpwd\nlls\nexit\n")
	stdout, stderr, code, err = runCompiledXops(
		binPath, iso.env, shellIn,
		"sftp", "-F", "none", "-p", portStr, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
		"127.0.0.1",
	)
	if err != nil || code != 0 || !strings.Contains(stdout, "hello.txt") || !strings.Contains(stdout, "hello-sftp-v2") {
		t.Fatalf("交互式 sftp shell 失配: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}

	// 3. scp 上传与下载（覆盖 OperatorReadFS + ScopedRootFS + ResolveWorkDir）。
	xferDir := filepath.Join(filepath.FromSlash(iso.homeDir.String()), "xfer")
	if err := os.MkdirAll(xferDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(xfer): %v", err)
	}
	srcLocal := filepath.Join(xferDir, "up.txt")
	if err := os.WriteFile(srcLocal, []byte("scp-e2e-payload-9876"), 0o600); err != nil {
		t.Fatalf("WriteFile(up.txt): %v", err)
	}
	stdout, stderr, code, err = runCompiledXops(
		binPath, iso.env, nil,
		"scp", "-F", "none", "-P", portStr, "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
		"--symlink-policy", "follow_operator_source",
		srcLocal, "deploy@127.0.0.1:/srv/up.txt",
	)
	if err != nil || code != 0 {
		t.Fatalf("scp 上传失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	stdout, stderr, code, err = runCompiledXops(
		binPath, iso.env, nil,
		"scp", "-F", "none", "-P", portStr, "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
		"--local-root", xferDir,
		"deploy@127.0.0.1:/srv/up.txt", "down.txt",
	)
	if err != nil || code != 0 {
		t.Fatalf("scp 下载失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	gotDL, err := os.ReadFile(filepath.Join(xferDir, "down.txt"))
	if err != nil || string(gotDL) != "scp-e2e-payload-9876" {
		t.Fatalf("scp 下载内容失配: got=%q err=%v", string(gotDL), err)
	}
	assertNoRemainingLocks(t, iso.xopsHome)
}

// TestE2E_CompiledBinaryTunnelLocalForward 验证真实编译二进制 `xops tunnel -L` 回环隧道转发与优雅停机。
func TestE2E_CompiledBinaryTunnelLocalForward(t *testing.T) {
	defer goleak.VerifyNone(t)
	binPath := buildCompiledXops(t, "-X 'main.buildVersion=v2.5.0-full'")
	clientSigner, keyPEM := generateE2EEd25519Key(t)
	srv := startFullE2ESSHServer(t, clientSigner.PublicKey())
	defer srv.Close()

	iso := newIsolatedOwnerOnlyEnv(t)
	keyPath := writeRootFile(t, iso.sshDir, "id_tun", keyPEM)
	portStr := srv.portString(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath,
		"tunnel", "--json", "-F", "none", "-p", portStr, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-L", "127.0.0.1:0:10.99.0.1:8080", "127.0.0.1",
	)
	cmd.Env = iso.env
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start tunnel: %v", err)
	}

	line, err := bufio.NewReader(stdoutPipe).ReadBytes('\n')
	if err != nil {
		stopChildGracefully(cmd, cancel)
		_ = cmd.Wait()
		t.Fatalf("读取 tunnel 就绪 JSON 失败: %v stderr=%q", err, stderrBuf.String())
	}
	var ready struct {
		OK       bool `json:"ok"`
		Forwards []struct {
			BindAddr string `json:"bind_addr"`
		} `json:"forwards"`
	}
	if err := jsonv2.Unmarshal(line, &ready); err != nil || !ready.OK || len(ready.Forwards) != 1 || ready.Forwards[0].BindAddr == "" {
		stopChildGracefully(cmd, cancel)
		_ = cmd.Wait()
		t.Fatalf("tunnel 就绪 JSON 异常: raw=%q err=%v", string(line), err)
	}

	var nd net.Dialer
	conn, err := nd.DialContext(ctx, "tcp", ready.Forwards[0].BindAddr)
	if err != nil {
		stopChildGracefully(cmd, cancel)
		_ = cmd.Wait()
		t.Fatalf("拨号本地隧道端口失败: %v", err)
	}
	_, _ = io.WriteString(conn, "ping-tunnel\n")
	reply, rErr := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	stopChildGracefully(cmd, cancel)
	waitErr := cmd.Wait()
	if rErr != nil || reply != "fwd[10.99.0.1:8080]:ping-tunnel\n" {
		t.Fatalf("隧道回显失配: reply=%q err=%v stderr=%q", reply, rErr, stderrBuf.String())
	}
	if runtime.GOOS != "windows" && waitErr != nil {
		t.Fatalf("tunnel 收到 SIGINT 期望退出码 0，实际=%v stderr=%q", waitErr, stderrBuf.String())
	}
	assertNoRemainingLocks(t, iso.xopsHome)
}

// TestE2E_CompiledBinaryMuxDaemonReuseAndFinitePersist 验证真实编译二进制 `xops mux daemon`、
// `mux check`、零新拨号透明复用、`mux exit` 以及有限时长 ControlPersist 自动空闲回收。
func TestE2E_CompiledBinaryMuxDaemonReuseAndFinitePersist(t *testing.T) {
	defer goleak.VerifyNone(t)
	binPath := buildCompiledXops(t, "-X 'main.buildVersion=v2.5.0-full'")
	clientSigner, keyPEM := generateE2EEd25519Key(t)
	srv := startFullE2ESSHServer(t, clientSigner.PublicKey())
	defer srv.Close()

	iso := newIsolatedOwnerOnlyEnv(t)
	keyPath := writeRootFile(t, iso.sshDir, "id_mux", keyPEM)
	portStr := srv.portString(t)
	sockPath := shortE2EMuxSocketPath(t, "cm.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	daemonCmd := exec.CommandContext(ctx, binPath,
		"mux", "daemon", "-F", "none", "-p", portStr, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-o", "ControlPersist=30s", "-S", sockPath, "127.0.0.1",
	)
	daemonCmd.Env = iso.env
	outPipe, err := daemonCmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var daemonErr bytes.Buffer
	daemonCmd.Stderr = &daemonErr
	if err := daemonCmd.Start(); err != nil {
		t.Fatalf("Start mux daemon: %v", err)
	}
	banner, err := bufio.NewReader(outPipe).ReadString('\n')
	if err != nil || !strings.Contains(banner, "mux daemon ready (master)") {
		stopChildGracefully(daemonCmd, cancel)
		_ = daemonCmd.Wait()
		t.Fatalf("mux daemon 未输出就绪横幅: banner=%q err=%v stderr=%q", banner, err, daemonErr.String())
	}

	// 1. mux check 报告存活。
	stdout, stderr, code, err := runCompiledXops(
		binPath, iso.env, nil,
		"mux", "check", "-F", "none", "-p", portStr, "-l", "deploy", "-S", sockPath, "127.0.0.1",
	)
	if err != nil || code != 0 || !strings.Contains(stdout, "master running") {
		stopChildGracefully(daemonCmd, cancel)
		_ = daemonCmd.Wait()
		t.Fatalf("mux check 失配: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}

	// 2. ssh 透明复用活跃 ControlMaster，零新增底层 SSH 拨号。
	dialsBefore := srv.dialCount.Load()
	stdout, stderr, code, err = runCompiledXops(
		binPath, iso.env, nil,
		"ssh", "-F", "none", "-p", portStr, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "ControlMaster=auto", "-o", "ControlPath="+sockPath,
		"127.0.0.1", "via-mux-daemon",
	)
	if err != nil || code != 0 || stdout != "exec:via-mux-daemon\n" {
		stopChildGracefully(daemonCmd, cancel)
		_ = daemonCmd.Wait()
		t.Fatalf("mux 复用 ssh 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	if srv.dialCount.Load() != dialsBefore {
		stopChildGracefully(daemonCmd, cancel)
		_ = daemonCmd.Wait()
		t.Fatalf("mux 复用期间不应触发新 SSH 拨号: before=%d after=%d", dialsBefore, srv.dialCount.Load())
	}

	// 3. mux exit 优雅终止守护进程并验证退出码 0。
	stdout, stderr, code, err = runCompiledXops(
		binPath, iso.env, nil,
		"mux", "exit", "-F", "none", "-p", portStr, "-l", "deploy", "-S", sockPath, "127.0.0.1",
	)
	if err != nil || code != 0 {
		stopChildGracefully(daemonCmd, cancel)
		_ = daemonCmd.Wait()
		t.Fatalf("mux exit 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	if err := daemonCmd.Wait(); err != nil {
		t.Fatalf("mux daemon 收到 -O exit 后期望退出码 0，实际=%v stderr=%q", err, daemonErr.String())
	}

	// 4. 有限时长 ControlPersist=1s：启动后不发 exit，等待自动空闲回收并以退出码 0 收敛。
	idleSock := shortE2EMuxSocketPath(t, "cm-idle.sock")
	idleCtx, idleCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer idleCancel()
	idleCmd := exec.CommandContext(idleCtx, binPath,
		"mux", "daemon", "-F", "none", "-p", portStr, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
		"-o", "ControlPersist=1s", "-S", idleSock, "127.0.0.1",
	)
	idleCmd.Env = iso.env
	var idleOut, idleErr bytes.Buffer
	idleCmd.Stdout = &idleOut
	idleCmd.Stderr = &idleErr
	if err := idleCmd.Run(); err != nil {
		t.Fatalf("有限 ControlPersist=1s 守护进程空闲回收应退出码 0，实际=%v stdout=%q stderr=%q", err, idleOut.String(), idleErr.String())
	}
	if !strings.Contains(idleOut.String(), "persist=1s") {
		t.Fatalf("有限 ControlPersist 守护进程输出应包含 persist=1s，实际=%q", idleOut.String())
	}
	assertNoRemainingLocks(t, iso.xopsHome)
}

// TestE2E_CompiledBinaryMCPStdioAndHTTP 验证真实编译二进制 `xops mcp` 的 stdio 与 Streamable HTTP 双传输闭环。
func TestE2E_CompiledBinaryMCPStdioAndHTTP(t *testing.T) {
	defer goleak.VerifyNone(t)
	binPath := buildCompiledXops(t, "-X 'main.buildVersion=v2.5.0-full'")
	iso := newIsolatedOwnerOnlyEnv(t)

	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e","version":"1.0"}}}` + "\n"
	assertMCPStdioLoopback(t, binPath, iso.env, initReq)
	assertMCPHTTPLoopback(t, binPath, iso.env, initReq)
	assertNoRemainingLocks(t, iso.xopsHome)
}

func assertMCPStdioLoopback(t *testing.T, binPath string, env []string, initReq string) {
	t.Helper()
	listReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n"
	stdout, stderr, code, err := runCompiledXops(
		binPath, env, strings.NewReader(initReq+listReq),
		"mcp", "--transport", "stdio",
	)
	if err != nil || code != 0 {
		t.Fatalf("mcp stdio 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	if !strings.Contains(stderr, "xops-mcp: ready transport=stdio") {
		t.Fatalf("mcp stdio stderr 应输出就绪摘要，实际=%q", stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"protocolVersion"`) || !strings.Contains(lines[1], `"tools"`) {
		t.Fatalf("mcp stdio JSON-RPC 响应失配: stdout=%q", stdout)
	}
}

func assertMCPHTTPLoopback(t *testing.T, binPath string, env []string, initReq string) {
	t.Helper()
	listenAddr := reserveFreeLoopbackAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	httpCmd := exec.CommandContext(ctx, binPath, "mcp", "--transport", "http", "--listen", listenAddr)
	httpCmd.Env = env
	errPipe, err := httpCmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	if err := httpCmd.Start(); err != nil {
		t.Fatalf("Start mcp http: %v", err)
	}

	readyLine, err := bufio.NewReader(errPipe).ReadString('\n')
	if err != nil || !strings.Contains(readyLine, "xops-mcp: ready transport=http") {
		stopChildGracefully(httpCmd, cancel)
		_ = httpCmd.Wait()
		t.Fatalf("mcp http 未就绪: line=%q err=%v", readyLine, err)
	}

	statusCode, respBody, reqErr := postMCPHTTPWithRetry(ctx, "http://"+listenAddr+"/mcp", initReq)
	stopChildGracefully(httpCmd, cancel)
	waitErr := httpCmd.Wait()
	if reqErr != nil || statusCode != http.StatusOK || !strings.Contains(string(respBody), `"protocolVersion"`) {
		t.Fatalf("mcp http POST /mcp 失败: status=%d body=%q reqErr=%v waitErr=%v", statusCode, string(respBody), reqErr, waitErr)
	}
	if runtime.GOOS != "windows" && waitErr != nil {
		t.Fatalf("mcp http 收到 SIGINT 期望退出码 0，实际=%v", waitErr)
	}
}

func postMCPHTTPWithRetry(ctx context.Context, url, payload string) (int, []byte, error) {
	var respBody []byte
	var statusCode int
	err := conc.RunWait(ctx, func(wCtx context.Context, _ *conc.Nursery) error {
		client := &http.Client{Timeout: 3 * time.Second}
		defer client.CloseIdleConnections()
		for range 50 {
			code, body, doErr := doSingleMCPHTTPPost(wCtx, client, url, payload)
			if doErr == nil {
				statusCode, respBody = code, body
				return nil
			}
			if waitErr := waitShortBackoff(wCtx, 20*time.Millisecond); waitErr != nil {
				return waitErr
			}
		}
		return io.ErrUnexpectedEOF
	})
	return statusCode, respBody, err
}

func doSingleMCPHTTPPost(ctx context.Context, client *http.Client, url, payload string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, rErr := io.ReadAll(resp.Body)
	return resp.StatusCode, body, rErr
}

func waitShortBackoff(ctx context.Context, d time.Duration) error {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}

// TestE2E_CompiledBinaryHostsConfigImportAndAuditQuery 验证真实编译二进制的 config formats/import（csv + openssh）、
// hosts CRUD 与 audit list/tail/reconcile 全链路闭环。
func TestE2E_CompiledBinaryHostsConfigImportAndAuditQuery(t *testing.T) {
	defer goleak.VerifyNone(t)
	binPath := buildCompiledXops(t, "-X 'main.buildVersion=v2.5.0-full'")
	iso := newIsolatedOwnerOnlyEnv(t)

	assertConfigImportE2E(t, binPath, iso.homeDir.String(), iso.env)
	assertHostsCRUDE2E(t, binPath, iso.env)
	assertAuditQueryE2E(t, binPath, iso.env)
	assertNoRemainingLocks(t, iso.xopsHome)
}

func assertConfigImportE2E(t *testing.T, binPath, homeDir string, env []string) {
	t.Helper()
	stdout, stderr, code, err := runCompiledXops(binPath, env, nil, "config", "formats", "--json")
	if err != nil || code != 0 || !strings.Contains(stdout, `"csv"`) || !strings.Contains(stdout, `"openssh"`) {
		t.Fatalf("config formats 失配: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	csvFile := filepath.Join(filepath.FromSlash(homeDir), "hosts.csv")
	if err := os.WriteFile(csvFile, []byte("alias,address,port,user\nweb-csv,10.10.0.1,2222,ops\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(hosts.csv): %v", err)
	}
	stdout, stderr, code, err = runCompiledXops(
		binPath, env, nil,
		"config", "import", "--format", "csv", "--file", csvFile, "--symlink-policy", "follow_operator_source", "--json",
	)
	if err != nil || code != 0 || !strings.Contains(stdout, `"ok":true`) {
		t.Fatalf("config import csv 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	sshCfgFile := filepath.Join(filepath.FromSlash(homeDir), "import_ssh.cfg")
	if err := os.WriteFile(sshCfgFile, []byte("Host app-ssh\n  HostName 10.10.0.2\n  Port 22\n  User deploy\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(import_ssh.cfg): %v", err)
	}
	stdout, stderr, code, err = runCompiledXops(
		binPath, env, nil,
		"config", "import", "--format", "openssh", "--file", sshCfgFile, "--symlink-policy", "follow_operator_source", "--json",
	)
	if err != nil || code != 0 || !strings.Contains(stdout, `"ok":true`) {
		t.Fatalf("config import openssh 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
}

func assertHostsCRUDE2E(t *testing.T, binPath string, env []string) {
	t.Helper()
	stdout, stderr, code, err := runCompiledXops(
		binPath, env, nil,
		"hosts", "add-host", "--id", "h-manual", "--address", "10.20.0.5:22", "--json",
	)
	if err != nil || code != 0 {
		t.Fatalf("hosts add-host 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	stdout, stderr, code, err = runCompiledXops(binPath, env, nil, "hosts", "list", "--kind", "all", "--json")
	if err != nil || code != 0 || !strings.Contains(stdout, "web-csv") || !strings.Contains(stdout, "app-ssh") || !strings.Contains(stdout, "h-manual") {
		t.Fatalf("hosts list 失配: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	stdout, stderr, code, err = runCompiledXops(binPath, env, nil, "hosts", "delete-host", "h-manual", "--json")
	if err != nil || code != 0 {
		t.Fatalf("hosts delete-host 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
}

func assertAuditQueryE2E(t *testing.T, binPath string, env []string) {
	t.Helper()
	stdout, stderr, code, err := runCompiledXops(binPath, env, nil, "audit", "list", "--json")
	if err != nil || code != 0 {
		t.Fatalf("audit list 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	var auditRes struct {
		TotalMatched int `json:"total_matched"`
		Entries      []struct {
			Phase   string `json:"phase"`
			Outcome string `json:"outcome"`
		} `json:"entries"`
	}
	if err := jsonv2.Unmarshal([]byte(stdout), &auditRes); err != nil || auditRes.TotalMatched < 2 || len(auditRes.Entries) < 2 {
		t.Fatalf("audit list 返回记录数不足: stdout=%q err=%v", stdout, err)
	}
	stdout, stderr, code, err = runCompiledXops(binPath, env, nil, "audit", "tail", "--limit", "2", "--json")
	if err != nil || code != 0 {
		t.Fatalf("audit tail 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
	stdout, stderr, code, err = runCompiledXops(binPath, env, nil, "audit", "reconcile", "--json")
	if err != nil || code != 0 {
		t.Fatalf("audit reconcile 失败: code=%d err=%v stdout=%q stderr=%q", code, err, stdout, stderr)
	}
}
