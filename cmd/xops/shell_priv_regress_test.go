package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/host/sys/interact"
	"github.com/wentf9/xops-cli/internal/host/vault/offline"
)

// TestRegress_ShellDialectInterpreterAndQuotingMatrix 验证全平台（Linux/Windows/macOS/FreeBSD）下
// `xops exec` 的启动方言（posix/raw）、解释器（sh/bash/zsh/server）、登录模式、复杂引号/空格/换行/$ 渲染、
// SendEnv 透传、非法组合失败关闭以及非零退出码与 JSON 视图映射。
func TestRegress_ShellDialectInterpreterAndQuotingMatrix(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)
	t.Setenv("XOPS_REGRESS_ENV", "sendenv-val-99")

	clientKey, keyPEM := generateGracefulEd25519Key(t)
	keyPath := spWriteTestKey(t, homeDir, "id_dialect", keyPEM)
	srv := startSPSSHServer(t, clientKey.PublicKey(), func(_ context.Context, ch ssh.Channel, rec spExecRecord) {
		handleDialectMatrixStub(ch, rec)
	})
	defer srv.Close()

	baseArgs := []string{
		"exec", "-F", "none", "-p", srv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-o", "SendEnv=XOPS_REGRESS_ENV",
	}
	assertValidDialectCases(t, baseArgs, srv)
	assertInvalidDialectCombinationsFailClosed(t, baseArgs, srv)
	assertNonZeroExitAndJSONMapping(t, baseArgs)
	assertZeroRemainingLocks(t, xopsHome)
}

func handleDialectMatrixStub(ch ssh.Channel, rec spExecRecord) {
	switch {
	case strings.Contains(rec.Command, "EXIT_42"):
		_, _ = io.WriteString(ch, "partial-out\n")
		_, _ = io.WriteString(ch.Stderr(), "boom-42\n")
		spSendExitStatus(ch, 42)
	case strings.Contains(rec.Command, "EXIT_127"):
		spSendExitStatus(ch, 127)
	default:
		_, _ = io.WriteString(ch, "WIRE="+rec.Command+"\nSENDENV="+rec.Env["XOPS_REGRESS_ENV"]+"\n")
		spSendExitStatus(ch, 0)
	}
}

func assertValidDialectCases(t *testing.T, baseArgs []string, srv *spSSHServer) {
	t.Helper()
	cases := []struct {
		name      string
		extra     []string
		cmd       string
		wantParts []string
	}{
		{
			name:  "posix-sh-quoting-env-workdir-newline",
			extra: []string{"--dialect", "posix", "--interpreter", "sh", "--workdir", "/var/tmp/my dir", "--env", `QUOTED=it's "ok" $HOME`},
			cmd:   "printf '%s' \"line1\nline2\"",
			wantParts: []string{
				"sh -c 'cd -- '\\''/var/tmp/my dir'\\'' || exit $?; ",
				"export QUOTED='\\''it'\\''\\'\\'''\\''s \"ok\" $HOME'\\'' || exit $?; ",
				"line1\nline2",
				"SENDENV=sendenv-val-99",
			},
		},
		{
			name:      "posix-bash-login",
			extra:     []string{"--dialect", "posix", "--interpreter", "bash", "--login", "login"},
			cmd:       "echo '$USER' && true",
			wantParts: []string{"bash -l -c 'echo '\\''$USER'\\'' && true'"},
		},
		{
			name:      "posix-zsh-nonlogin",
			extra:     []string{"--dialect", "posix", "--interpreter", "zsh"},
			cmd:       `echo "zsh ok"`,
			wantParts: []string{`zsh -c 'echo "zsh ok"'`},
		},
		{
			name:      "raw-server-fish-verbatim",
			extra:     []string{"--dialect", "raw", "--interpreter", "server"},
			cmd:       "string join ':' alpha beta $status",
			wantParts: []string{"WIRE=string join ':' alpha beta $status\n"},
		},
	}
	ctx := context.Background()
	for _, tc := range cases {
		var outBuf, errBuf bytes.Buffer
		args := append(append([]string(nil), baseArgs...), tc.extra...)
		args = append(args, "127.0.0.1", "--", tc.cmd)
		code := runProcessWithContext(ctx, args, strings.NewReader(""), &outBuf, &errBuf)
		if code != 0 || errBuf.Len() != 0 {
			t.Fatalf("[%s] 期望退出码 0: code=%d stdout=%q stderr=%q", tc.name, code, outBuf.String(), errBuf.String())
		}
		for _, want := range tc.wantParts {
			if !strings.Contains(outBuf.String(), want) {
				t.Fatalf("[%s] 输出缺少 %q，实际=%q", tc.name, want, outBuf.String())
			}
		}
	}
	if len(srv.snapshotRecords()) != len(cases) {
		t.Fatalf("期望服务端收到 %d 次 exec，实际=%d", len(cases), len(srv.snapshotRecords()))
	}
}

func assertInvalidDialectCombinationsFailClosed(t *testing.T, baseArgs []string, srv *spSSHServer) {
	t.Helper()
	dialsBefore := srv.dialsCount()
	invalidCases := [][]string{
		{"--dialect", "raw", "--interpreter", "bash", "127.0.0.1", "echo hi"},
		{"--dialect", "raw", "--workdir", "/tmp", "127.0.0.1", "echo hi"},
		{"--interpreter", "sh", "--login", "login", "127.0.0.1", "echo hi"},
		{"--dialect", "posix", "--interpreter", "sh", "--env", "BAD=line1\nline2", "127.0.0.1", "echo hi"},
	}
	for _, extra := range invalidCases {
		var outBuf, errBuf bytes.Buffer
		args := append(append([]string(nil), baseArgs...), extra...)
		code := runProcessWithContext(context.Background(), args, strings.NewReader(""), &outBuf, &errBuf)
		if code != 2 {
			t.Fatalf("非法方言组合 %v 期望退出码 2，实际=%d stderr=%q", extra, code, errBuf.String())
		}
	}
	if srv.dialsCount() != dialsBefore {
		t.Fatalf("非法方言组合必须在拨号前拒绝，实际新增拨号=%d", srv.dialsCount()-dialsBefore)
	}
}

func assertNonZeroExitAndJSONMapping(t *testing.T, baseArgs []string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	args127 := append(append([]string(nil), baseArgs...), "127.0.0.1", "EXIT_127")
	if code := runProcessWithContext(context.Background(), args127, strings.NewReader(""), &outBuf, &errBuf); code != 127 {
		t.Fatalf("EXIT_127 期望退出码 127，实际=%d stderr=%q", code, errBuf.String())
	}

	outBuf.Reset()
	errBuf.Reset()
	args42 := append(append([]string(nil), baseArgs...), "--json", "127.0.0.1", "EXIT_42")
	code := runProcessWithContext(context.Background(), args42, strings.NewReader(""), &outBuf, &errBuf)
	if code != 42 {
		t.Fatalf("EXIT_42 (--json) 期望退出码 42，实际=%d stdout=%q stderr=%q", code, outBuf.String(), errBuf.String())
	}
	var view struct {
		OK          bool   `json:"ok"`
		ExitCode    int    `json:"exit_code"`
		OutcomeKind string `json:"outcome_kind"`
		Stdout      string `json:"stdout"`
		Stderr      string `json:"stderr"`
	}
	if err := jsonv2.Unmarshal(outBuf.Bytes(), &view); err != nil {
		t.Fatalf("解析 --json 输出失败: %v raw=%q", err, outBuf.String())
	}
	if view.OK || view.ExitCode != 42 || view.OutcomeKind != "completed" || view.Stdout != "partial-out\n" || view.Stderr != "boom-42\n" {
		t.Fatalf("EXIT_42 JSON 视图失配: %+v", view)
	}
}

// TestRegress_ShellProbeCompatibilityMatrix 验证真实 wireRuntime + sshnet/probe 两阶段探测对
// sh / bash / zsh / POSIX+SHELL=fish 回退 / 纯 fish 登录壳（严格失败关闭）的兼容性矩阵。
func TestRegress_ShellProbeCompatibilityMatrix(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)
	clientKey, keyPEM := generateGracefulEd25519Key(t)
	keyPath := spWriteTestKey(t, homeDir, "id_probe", keyPEM)

	profiles := []struct {
		name       string
		shellPath  string
		avail      []string
		fishLogin  bool
		wantErr    bool
		wantInterp execution.Interpreter
	}{
		{name: "sh", shellPath: "/bin/sh", avail: []string{"sh", "bash"}, wantInterp: execution.InterpreterSH},
		{name: "bash", shellPath: "/bin/bash", avail: []string{"bash", "sh"}, wantInterp: execution.InterpreterBash},
		{name: "zsh", shellPath: "/usr/bin/zsh", avail: []string{"bash", "sh", "zsh"}, wantInterp: execution.InterpreterZsh},
		{name: "posix-with-fish-env", shellPath: "/usr/bin/fish", avail: []string{"bash", "sh"}, wantInterp: execution.InterpreterBash},
		{name: "fish-login-fail-closed", shellPath: "/usr/bin/fish", fishLogin: true, wantErr: true},
	}

	ctx := context.Background()
	rt, err := wireRuntime(ctx, cli.EngineInitOptions{OpenSSHConfigFile: "none"}, runtimeModeCLI, strings.NewReader(""), io.Discard)
	if err != nil {
		t.Fatalf("wireRuntime: %v", err)
	}
	defer func() {
		if cErr := rt.Close(ctx); cErr != nil {
			t.Errorf("rt.Close: %v", cErr)
		}
		assertZeroRemainingLocks(t, xopsHome)
	}()

	keyList, err := option.ParsePathListEntries([]string{keyPath})
	if err != nil {
		t.Fatalf("ParsePathListEntries: %v", err)
	}
	cliOpts := option.UnsetOptionLayer().
		WithIdentityFiles(keyList).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew)

	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			assertProbeProfileCase(t, ctx, rt.engine, clientKey.PublicKey(), cliOpts, tc.name, tc.shellPath, tc.avail, tc.fishLogin, tc.wantErr, tc.wantInterp)
		})
	}
}

func assertProbeProfileCase(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	pub ssh.PublicKey,
	cliOpts option.OptionLayer,
	name, shellPath string,
	avail []string,
	fishLogin, wantErr bool,
	wantInterp execution.Interpreter,
) {
	t.Helper()
	srv := startSPSSHServer(t, pub, func(_ context.Context, ch ssh.Channel, rec spExecRecord) {
		emulateShellProbe(ch, rec.Command, shellPath, avail, fishLogin)
	})
	defer srv.Close()

	rc := engine.RemoteCall{
		TargetInput: engine.TargetInput{
			TargetSpec: "deploy@127.0.0.1:" + srv.port,
			CLIOptions: cliOpts,
		},
	}
	res, pErr := eng.ProbeShell(ctx, engine.ProbeShellRequest{RemoteCall: rc})
	if wantErr {
		if pErr == nil {
			t.Fatalf("纯 fish 登录壳必须失败关闭，但返回成功: dialect=%s interp=%s", res.Dialect(), res.Interpreter())
		}
		return
	}
	if pErr != nil {
		t.Fatalf("ProbeShell(%s) 失败: %v", name, pErr)
	}
	if res.Dialect() != execution.DialectPOSIX || res.Interpreter() != wantInterp || res.ProbeStage() != 2 {
		t.Fatalf("ProbeShell(%s) 失配: dialect=%s interp=%s stage=%d", name, res.Dialect(), res.Interpreter(), res.ProbeStage())
	}
}

func emulateShellProbe(ch ssh.Channel, cmd, shellPath string, avail []string, fishLogin bool) {
	if fishLogin {
		switch {
		case strings.Contains(cmd, "__XOPS_DIALECT_POSIX__"):
			_, _ = io.WriteString(ch.Stderr(), "fish: Expected end to balance if statement\n")
			spSendExitStatus(ch, 127)
		case strings.Contains(cmd, "__XOPS_DIALECT_CMD__"):
			_, _ = io.WriteString(ch, "__XOPS_DIALECT_CMD__:%COMSPEC%\n")
			spSendExitStatus(ch, 0)
		default:
			_, _ = io.WriteString(ch.Stderr(), "fish: Unknown command: Write-Output\n")
			spSendExitStatus(ch, 127)
		}
		return
	}
	if strings.Contains(cmd, "__XOPS_DIALECT_POSIX__") {
		_, _ = io.WriteString(ch, "__XOPS_DIALECT_POSIX__:Linux:"+shellPath+"\n")
		spSendExitStatus(ch, 0)
		return
	}
	if strings.Contains(cmd, "__XOPS_INTERP_END__") {
		for _, interp := range avail {
			_, _ = io.WriteString(ch, "__XOPS_INTERP__:"+interp+"\n")
		}
		_, _ = io.WriteString(ch, "__XOPS_INTERP_END__\n")
		spSendExitStatus(ch, 0)
		return
	}
	spSendExitStatus(ch, 1)
}

// TestRegress_PrivilegeEscalationVaultAndInteractive 端到端覆盖全量提权回归契约：
//  1. external_helper Vault（`--sudo --password-ref`）+ 随机 `-p` 令牌不可复用性 + `sudo-rs` 掩码 + `--privilege-user`；
//  2. 解锁态 offline_aead Vault（`--su --password-ref`）+ 交互式 `InteractionPort`（`--sudo/--su --prompt-password`）；
//  3. 非 TTY 管道下 `--prompt-password` 失败关闭、错误口令零执行拒绝、不支持 `--dialect raw` 拒绝；
//  4. 就绪帧后取消返回 `OutcomeUnknown`（JSON `do_not_retry: true`）与就绪后断连返回非零退出码；
//  5. 全路径严格断言明文口令零泄露（stdout / stderr / audit.jsonl）。
func TestRegress_PrivilegeEscalationVaultAndInteractive(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)
	clientKey, keyPEM := generateGracefulEd25519Key(t)
	keyPath := spWriteTestKey(t, homeDir, "id_priv", keyPEM)

	const (
		sudoSecret  = "Sudo!Regress#Pass-8472"
		wrongSecret = "Wrong!Regress#Pass-0000"
		suSecret    = "Su!Regress#RootPass-5913"
	)
	vaultFile := spSetupExternalHelperVault(t, xopsHome, map[string]string{
		"extvault/sudo-pass":  sudoSecret,
		"extvault/wrong-pass": wrongSecret,
		"extvault/su-pass":    suSecret,
	})
	t.Setenv(spVaultHelperModeEnv, "serve")
	t.Setenv(spVaultHelperFileEnv, vaultFile)

	assertSudoExternalHelperSuccessAndNonceUniqueness(t, keyPath, xopsHome, clientKey.PublicKey(), sudoSecret)
	assertPrivWrongPassNonTTYAndRawDialectDenied(t, keyPath, xopsHome, clientKey.PublicKey(), sudoSecret, wrongSecret)
	assertPrivPostReadyOutcomeUnknownAndDrop(t, keyPath, xopsHome, clientKey.PublicKey(), sudoSecret)
	assertOfflineVaultAndInteractivePromptEscalation(t, keyPath, xopsHome, clientKey.PublicKey(), sudoSecret, suSecret)
}

func assertSudoExternalHelperSuccessAndNonceUniqueness(
	t *testing.T,
	keyPath string,
	xopsHome pathalg.LocalDir,
	pub ssh.PublicKey,
	sudoSecret string,
) {
	t.Helper()
	cfg := &spPrivEmulationCfg{expectedPass: sudoSecret}
	srv := startSPSSHServer(t, pub, newSPPrivEmulationHandler(cfg))
	defer srv.Close()

	baseArgs := []string{
		"exec", "-F", "none", "-p", srv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"--sudo", "--privilege-user", "opsadmin", "--password-ref", "extvault/sudo-pass",
		"127.0.0.1", "--", "id",
	}
	var out1, err1 bytes.Buffer
	if code := runProcessWithContext(context.Background(), baseArgs, strings.NewReader(""), &out1, &err1); code != 0 || out1.String() != "uid=0(root) method=sudo\n" {
		t.Fatalf("sudo 首次提权失败: code=%d stdout=%q stderr=%q", code, out1.String(), err1.String())
	}
	assertSecretNeverLeaked(t, sudoSecret, out1.String(), err1.String(), xopsHome)

	// 第二次启用 sudo-rs 封套与 * 掩码回显，同时校验两次随机 -p 提示令牌互不相同。
	cfg.sudoRSStyle = true
	var out2, err2 bytes.Buffer
	if code := runProcessWithContext(context.Background(), baseArgs, strings.NewReader(""), &out2, &err2); code != 0 || out2.String() != "uid=0(root) method=sudo\n" {
		t.Fatalf("sudo-rs 提权失败: code=%d stdout=%q stderr=%q", code, out2.String(), err2.String())
	}
	assertSecretNeverLeaked(t, sudoSecret, out2.String(), err2.String(), xopsHome)

	nonces := cfg.snapshotNonces()
	if len(nonces) != 2 || nonces[0] == nonces[1] || !strings.HasPrefix(nonces[0], "[xops-priv-prompt-") {
		t.Fatalf("sudo -p 随机提示令牌必须每次独立且符合格式: %v", nonces)
	}
	recs := srv.snapshotRecords()
	if len(recs) != 2 || !strings.Contains(recs[0].Command, "-u 'opsadmin'") {
		t.Fatalf("sudo 命令应包含 -u 'opsadmin': %+v", recs)
	}
}

func assertPrivWrongPassNonTTYAndRawDialectDenied(
	t *testing.T,
	keyPath string,
	xopsHome pathalg.LocalDir,
	pub ssh.PublicKey,
	sudoSecret, wrongSecret string,
) {
	t.Helper()
	cfg := &spPrivEmulationCfg{expectedPass: sudoSecret}
	srv := startSPSSHServer(t, pub, newSPPrivEmulationHandler(cfg))
	defer srv.Close()

	common := []string{
		"exec", "-F", "none", "-p", srv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
	}
	// 1. sudo 错误口令：严格失败关闭、0 次命令执行、JSON outcome_kind=not_started、0 泄露。
	var outBuf, errBuf bytes.Buffer
	argsWrong := append(append([]string(nil), common...), "--json", "--sudo", "--password-ref", "extvault/wrong-pass", "127.0.0.1", "--", "id")
	code := runProcessWithContext(context.Background(), argsWrong, strings.NewReader(""), &outBuf, &errBuf)
	if code != 255 || cfg.execCount.Load() != 0 {
		t.Fatalf("错误 sudo 口令必须失败关闭且零执行: code=%d exec=%d stdout=%q stderr=%q", code, cfg.execCount.Load(), outBuf.String(), errBuf.String())
	}
	assertSecretNeverLeaked(t, wrongSecret, outBuf.String(), errBuf.String(), xopsHome)
	if !strings.Contains(outBuf.String(), `"outcome_kind":"not_started"`) {
		t.Fatalf("错误 sudo 口令 JSON 应为 not_started: %q", outBuf.String())
	}

	// 2. su 错误口令：同样严格失败关闭、0 次命令执行、0 泄露。
	outBuf.Reset()
	errBuf.Reset()
	argsSuWrong := append(append([]string(nil), common...), "--su", "--password-ref", "extvault/wrong-pass", "127.0.0.1", "--", "id")
	if code := runProcessWithContext(context.Background(), argsSuWrong, strings.NewReader(""), &outBuf, &errBuf); code != 255 || cfg.execCount.Load() != 0 {
		t.Fatalf("错误 su 口令必须失败关闭且零执行: code=%d exec=%d stderr=%q", code, cfg.execCount.Load(), errBuf.String())
	}
	assertSecretNeverLeaked(t, wrongSecret, outBuf.String(), errBuf.String(), xopsHome)

	// 3. 非 TTY 管道下 --prompt-password 必须失败关闭（不从非交互管道窃取口令）。
	outBuf.Reset()
	errBuf.Reset()
	dialsBefore := srv.dialsCount()
	argsNonTTY := append(append([]string(nil), common...), "--sudo", "--prompt-password", "127.0.0.1", "--", "id")
	if code := runProcessWithContext(context.Background(), argsNonTTY, strings.NewReader(sudoSecret+"\n"), &outBuf, &errBuf); code != 255 || srv.dialsCount() != dialsBefore {
		t.Fatalf("非 TTY --prompt-password 必须拨号前拒绝: code=%d dialsDelta=%d stderr=%q", code, srv.dialsCount()-dialsBefore, errBuf.String())
	}
	assertSecretNeverLeaked(t, sudoSecret, outBuf.String(), errBuf.String(), xopsHome)

	// 4. --dialect raw 与 --sudo 组合必须在远端执行前拒绝。
	outBuf.Reset()
	errBuf.Reset()
	argsRaw := append(append([]string(nil), common...), "--sudo", "--dialect", "raw", "--password-ref", "extvault/sudo-pass", "127.0.0.1", "--", "id")
	if code := runProcessWithContext(context.Background(), argsRaw, strings.NewReader(""), &outBuf, &errBuf); code == 0 || cfg.execCount.Load() != 0 {
		t.Fatalf("--sudo --dialect raw 必须失败关闭: code=%d exec=%d stderr=%q", code, cfg.execCount.Load(), errBuf.String())
	}
	assertSecretNeverLeaked(t, sudoSecret, outBuf.String(), errBuf.String(), xopsHome)
}

func assertPrivPostReadyOutcomeUnknownAndDrop(
	t *testing.T,
	keyPath string,
	xopsHome pathalg.LocalDir,
	pub ssh.PublicKey,
	sudoSecret string,
) {
	t.Helper()
	// 1. 就绪帧后阻塞 -> 收到 "post-ready-started\n" 信号后立即取消 ctx -> 必须产出 OutcomeUnknown（do_not_retry=true）。
	hangCfg := &spPrivEmulationCfg{expectedPass: sudoSecret, hangAfterReady: true}
	hangSrv := startSPSSHServer(t, pub, newSPPrivEmulationHandler(hangCfg))
	defer hangSrv.Close()

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outSig := newSignalLineWriter("post-ready-started\n")
	var errBuf bytes.Buffer
	exitCode := -1
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			args := []string{
				"exec", "-F", "none", "-p", hangSrv.port, "-l", "deploy", "-i", keyPath,
				"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
				"--sudo", "--password-ref", "extvault/sudo-pass", "127.0.0.1", "--", "long-op",
			}
			exitCode = runProcessWithContext(runCtx, args, strings.NewReader(""), outSig, &errBuf)
			return nil
		}); gErr != nil {
			return gErr
		}
		if wErr := waitSignalWithTimeout(outSig.readyCh, 10*time.Second); wErr != nil {
			cancel()
			return wErr
		}
		cancel()
		return nil
	})
	if err != nil || exitCode != 255 || !strings.Contains(errBuf.String(), "do not blindly retry") {
		t.Fatalf("就绪后取消必须返回 OutcomeUnknown 禁重试诊断: err=%v code=%d stdout=%q stderr=%q", err, exitCode, outSig.String(), errBuf.String())
	}
	assertSecretNeverLeaked(t, sudoSecret, outSig.String(), errBuf.String(), xopsHome)

	// 2. --json 模式下通过 --timeout 触发就绪后超时，验证 do_not_retry:true 与 outcome_kind:"unknown"。
	var jsonOut, jsonErr bytes.Buffer
	timeoutArgs := []string{
		"exec", "--json", "--timeout", "250ms", "-F", "none", "-p", hangSrv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
		"--sudo", "--password-ref", "extvault/sudo-pass", "127.0.0.1", "--", "long-op",
	}
	tCode := runProcessWithContext(context.Background(), timeoutArgs, strings.NewReader(""), &jsonOut, &jsonErr)
	var uView struct {
		OK          bool   `json:"ok"`
		OutcomeKind string `json:"outcome_kind"`
		DoNotRetry  bool   `json:"do_not_retry"`
	}
	if err := jsonv2.Unmarshal(jsonOut.Bytes(), &uView); err != nil {
		t.Fatalf("解析 OutcomeUnknown JSON 失败: %v raw=%q", err, jsonOut.String())
	}
	if tCode != 255 || uView.OK || uView.OutcomeKind != "unknown" || !uView.DoNotRetry {
		t.Fatalf("就绪后超时 JSON 必须标明 unknown + do_not_retry=true: code=%d view=%+v raw=%q", tCode, uView, jsonOut.String())
	}
	assertSecretNeverLeaked(t, sudoSecret, jsonOut.String(), jsonErr.String(), xopsHome)

	// 3. 就绪帧后无 exit-status 断连：必须返回非零退出码（255），绝不假绿为 0。
	dropCfg := &spPrivEmulationCfg{expectedPass: sudoSecret, dropAfterReady: true}
	dropSrv := startSPSSHServer(t, pub, newSPPrivEmulationHandler(dropCfg))
	defer dropSrv.Close()
	var dropOut, dropErr bytes.Buffer
	dropArgs := []string{
		"exec", "-F", "none", "-p", dropSrv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"--sudo", "--password-ref", "extvault/sudo-pass", "127.0.0.1", "--", "drop-op",
	}
	if dCode := runProcessWithContext(context.Background(), dropArgs, strings.NewReader(""), &dropOut, &dropErr); dCode != 255 {
		t.Fatalf("就绪后无 exit-status 断连必须返回 255: code=%d stderr=%q", dCode, dropErr.String())
	}
	assertSecretNeverLeaked(t, sudoSecret, dropOut.String(), dropErr.String(), xopsHome)
}

func assertOfflineVaultAndInteractivePromptEscalation(
	t *testing.T,
	keyPath string,
	xopsHome pathalg.LocalDir,
	pub ssh.PublicKey,
	sudoSecret, suSecret string,
) {
	t.Helper()
	ctx := context.Background()
	// 1. 使用真实 offline_aead Vault（Init + PutAndVerify）配合 --su --password-ref，
	//    以及真实可交互 interact.NewStreamInteraction(Interactive: true) 配合 --sudo/--su --prompt-password。
	vaultDir, err := xopsHome.JoinComponent("offline_priv_vault")
	if err != nil {
		t.Fatalf("JoinComponent(offline_priv_vault): %v", err)
	}
	offVault, err := offline.NewVault(offline.Spec{
		ScopedFS:   osfs.NewScopedRootFS(),
		RootDir:    vaultDir,
		Entropy:    sys.NewCryptoEntropy(),
		StoreNames: []string{"offline"},
	})
	if err != nil {
		t.Fatalf("offline.NewVault: %v", err)
	}
	defer func() { _ = offVault.Lock(context.Background()) }()
	suRef, _ := secret.NewRef("offline", "su-pass")
	if err := secret.WithBytes([]byte("Master!Pass-9911"), func(master *secret.SecretBox) error {
		return offVault.Init(ctx, master)
	}); err != nil {
		t.Fatalf("offline.Init: %v", err)
	}
	if err := secret.WithBytes([]byte(suSecret), func(box *secret.SecretBox) error {
		return offVault.PutAndVerify(ctx, suRef, box)
	}); err != nil {
		t.Fatalf("offline.PutAndVerify: %v", err)
	}

	suCfg := &spPrivEmulationCfg{expectedPass: suSecret}
	suSrv := startSPSSHServer(t, pub, newSPPrivEmulationHandler(suCfg))
	defer suSrv.Close()

	// 1a. offline_aead Vault --su --password-ref offline/su-pass。
	var out1, err1 bytes.Buffer
	code1 := runCLIWithInjectedVaultAndInteraction(
		t, ctx, offVault, nil, &out1, &err1,
		[]string{
			"exec", "-F", "none", "-p", suSrv.port, "-l", "deploy", "-i", keyPath,
			"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
			"--su", "--password-ref", "offline/su-pass", "127.0.0.1", "--", "id",
		},
	)
	if code1 != 0 || out1.String() != "uid=0(root) method=su\n" {
		t.Fatalf("offline_aead Vault --su 失败: code=%d stdout=%q stderr=%q", code1, out1.String(), err1.String())
	}
	assertSecretNeverLeaked(t, suSecret, out1.String(), err1.String(), xopsHome)

	// 1b. 交互式 InteractionPort --sudo --prompt-password 与 --su --prompt-password。
	sudoCfg := &spPrivEmulationCfg{expectedPass: sudoSecret}
	sudoSrv := startSPSSHServer(t, pub, newSPPrivEmulationHandler(sudoCfg))
	defer sudoSrv.Close()

	var promptOut bytes.Buffer
	inter, err := interact.NewStreamInteraction(interact.StreamSpec{
		In:          strings.NewReader(sudoSecret + "\n"),
		Out:         &promptOut,
		Interactive: true,
	})
	if err != nil {
		t.Fatalf("NewStreamInteraction: %v", err)
	}
	var out2, err2 bytes.Buffer
	code2 := runCLIWithInjectedVaultAndInteraction(
		t, ctx, offVault, inter, &out2, &err2,
		[]string{
			"exec", "-F", "none", "-p", sudoSrv.port, "-l", "deploy", "-i", keyPath,
			"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
			"--sudo", "--prompt-password", "127.0.0.1", "--", "id",
		},
	)
	if code2 != 0 || out2.String() != "uid=0(root) method=sudo\n" || !strings.Contains(promptOut.String(), "Enter sudo password") {
		t.Fatalf("交互式 --sudo --prompt-password 失败: code=%d stdout=%q stderr=%q prompt=%q", code2, out2.String(), err2.String(), promptOut.String())
	}
	assertSecretNeverLeaked(t, sudoSecret, out2.String()+promptOut.String(), err2.String(), xopsHome)

	var suPromptOut bytes.Buffer
	suInter, err := interact.NewStreamInteraction(interact.StreamSpec{
		In:          strings.NewReader(suSecret + "\n"),
		Out:         &suPromptOut,
		Interactive: true,
	})
	if err != nil {
		t.Fatalf("NewStreamInteraction(su): %v", err)
	}
	var out3, err3 bytes.Buffer
	code3 := runCLIWithInjectedVaultAndInteraction(
		t, ctx, offVault, suInter, &out3, &err3,
		[]string{
			"exec", "-F", "none", "-p", suSrv.port, "-l", "deploy", "-i", keyPath,
			"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
			"--su", "--prompt-password", "127.0.0.1", "--", "id",
		},
	)
	if code3 != 0 || out3.String() != "uid=0(root) method=su\n" || !strings.Contains(suPromptOut.String(), "Enter su password") {
		t.Fatalf("交互式 --su --prompt-password 失败: code=%d stdout=%q stderr=%q prompt=%q", code3, out3.String(), err3.String(), suPromptOut.String())
	}
	assertSecretNeverLeaked(t, suSecret, out3.String()+suPromptOut.String(), err3.String(), xopsHome)
}

func runCLIWithInjectedVaultAndInteraction(
	t *testing.T,
	ctx context.Context,
	vaultOverride ports.SecretVault,
	interOverride ports.InteractionPort,
	stdout, stderr io.Writer,
	args []string,
) int {
	t.Helper()
	app, err := cli.NewApp(cli.AppConfig{
		BuildInfo: currentBuildInfo(),
		EngineFactory: func(callCtx context.Context, opts cli.EngineInitOptions) (cli.EngineHandle, error) {
			stack := newShutdownStack(defaultShutdownGrace)
			adapters, aErr := assembleHostAdapters(callCtx, opts, runtimeModeCLI, strings.NewReader(""), io.Discard, nil, stack)
			if aErr != nil {
				_ = stack.Close(context.Background())
				return cli.EngineHandle{}, aErr
			}
			cfg := buildEngineConfig(adapters, runtimeModeCLI)
			if vaultOverride != nil {
				cfg.Vault = vaultOverride
			}
			if interOverride != nil {
				cfg.Interaction = interOverride
			}
			eng, eErr := engine.New(cfg)
			if eErr != nil {
				_ = stack.Close(context.Background())
				return cli.EngineHandle{}, eErr
			}
			stack.Add("engine", eng.Close)
			if _, rErr := eng.ReconcileCrashedAudits(callCtx); rErr != nil {
				_ = stack.Close(context.Background())
				return cli.EngineHandle{}, rErr
			}
			return cli.EngineHandle{Runner: eng, Close: stack.Close}, nil
		},
		Stdin:  strings.NewReader(""),
		Stdout: stdout,
		Stderr: stderr,
	})
	if err != nil {
		t.Fatalf("cli.NewApp: %v", err)
	}
	return app.Run(ctx, args)
}

// TestRegress_CompiledBinaryShellAndSudoVaultE2E 编译真实独立 xops 二进制并经回环 SSH 验证
// `--dialect posix --interpreter sh` 与 `--sudo --password-ref`（由自托管 external_helper 投递口令）全链路闭环。
func TestRegress_CompiledBinaryShellAndSudoVaultE2E(t *testing.T) {
	defer goleak.VerifyNone(t)
	// 先在修改隔离 HOME 前编译二进制，复用宿主 Go 模块缓存，避免在临时 HOME 内写入只读 pkg/mod 导致清理失败。
	binPath := filepath.Join(t.TempDir(), "xops")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("编译 xops 二进制失败: %v\n%s", err, string(out))
	}

	homeDir, xopsHome := setupIsolatedRootEnv(t)
	clientKey, keyPEM := generateGracefulEd25519Key(t)
	keyPath := spWriteTestKey(t, homeDir, "id_bin", keyPEM)

	const binSecret = "CompiledBin!Sudo#Secret-3141"
	vaultFile := spSetupExternalHelperVault(t, xopsHome, map[string]string{
		"extvault/bin-sudo": binSecret,
	})
	t.Setenv(spVaultHelperModeEnv, "serve")
	t.Setenv(spVaultHelperFileEnv, vaultFile)

	// 1. 编译二进制执行 --dialect posix --interpreter sh。
	shellSrv := startSPSSHServer(t, clientKey.PublicKey(), func(_ context.Context, ch ssh.Channel, rec spExecRecord) {
		handleDialectMatrixStub(ch, rec)
	})
	defer shellSrv.Close()
	shCmd := exec.Command(
		binPath, "exec", "-F", "none", "-p", shellSrv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"--dialect", "posix", "--interpreter", "sh", "127.0.0.1", "--", "echo 'compiled ok'",
	)
	var shOut, shErr bytes.Buffer
	shCmd.Stdout, shCmd.Stderr = &shOut, &shErr
	if err := shCmd.Run(); err != nil || !strings.Contains(shOut.String(), "sh -c 'echo '\\''compiled ok'\\'''") {
		t.Fatalf("编译二进制 --dialect posix --interpreter sh 失败: err=%v stdout=%q stderr=%q", err, shOut.String(), shErr.String())
	}

	// 2. 编译二进制执行 --sudo --password-ref（经 external_helper 投递口令）并严审零明文泄露。
	cfg := &spPrivEmulationCfg{expectedPass: binSecret}
	srv := startSPSSHServer(t, clientKey.PublicKey(), newSPPrivEmulationHandler(cfg))
	defer srv.Close()

	runCmd := exec.Command(
		binPath, "exec", "--json", "-F", "none", "-p", srv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"--sudo", "--password-ref", "extvault/bin-sudo", "127.0.0.1", "--", "id",
	)
	var outBuf, errBuf bytes.Buffer
	runCmd.Stdout, runCmd.Stderr = &outBuf, &errBuf
	if err := runCmd.Run(); err != nil {
		t.Fatalf("编译二进制 --sudo 执行失败: err=%v stdout=%q stderr=%q", err, outBuf.String(), errBuf.String())
	}
	if !strings.Contains(outBuf.String(), `"ok":true`) || !strings.Contains(outBuf.String(), `uid=0(root) method=sudo`) {
		t.Fatalf("编译二进制 --sudo JSON 输出失配: %q", outBuf.String())
	}
	assertSecretNeverLeaked(t, binSecret, outBuf.String(), errBuf.String(), xopsHome)
}
