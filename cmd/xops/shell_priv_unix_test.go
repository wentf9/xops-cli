//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli"
)

// TestRegress_NativeUnixShellsExecAndQuoting 在 Unix 平台使用本机真实 sh / bash / zsh / fish 可执行文件
// 作为进程内回环 SSH 服务端的远端登录 Shell，实测真实引号解析、空白/单双引号/换行/$ 零注入、--workdir、
// SendEnv 透传与非零退出码映射（0 外部主机、0 root 权限）。
func TestRegress_NativeUnixShellsExecAndQuoting(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)
	t.Setenv("XOPS_NATIVE_ENV", "native-shell-v2")
	clientKey, keyPEM := generateGracefulEd25519Key(t)
	keyPath := spWriteTestKey(t, homeDir, "id_native_shells", keyPEM)

	for _, shellName := range []string{"sh", "bash", "zsh"} {
		shellBin, err := exec.LookPath(shellName)
		if err != nil {
			t.Logf("跳过未安装的原生 Shell %s: %v", shellName, err)
			continue
		}
		t.Run("posix-"+shellName, func(t *testing.T) {
			assertNativePOSIXShellExec(t, shellName, shellBin, keyPath, clientKey.PublicKey())
		})
	}
	if fishBin, err := exec.LookPath("fish"); err == nil {
		t.Run("raw-fish", func(t *testing.T) {
			assertNativeFishRawExec(t, fishBin, keyPath, clientKey.PublicKey())
		})
	}
	assertZeroRemainingLocks(t, xopsHome)
}

func assertNativePOSIXShellExec(t *testing.T, shellName, shellBin, keyPath string, pub ssh.PublicKey) {
	t.Helper()
	workDir := filepath.Join(t.TempDir(), "dir with space")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(workDir): %v", err)
	}
	resolvedWorkDir, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		resolvedWorkDir = workDir
	}
	srv := startSPSSHServer(t, pub, newRealUnixShellHandler(t.TempDir(), shellBin, nil))
	defer srv.Close()

	baseArgs := []string{
		"exec", "-F", "none", "-p", srv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-o", "SendEnv=XOPS_NATIVE_ENV",
	}
	// 1. 复杂字符（单引号/双引号/$HOME/反引号）经 --env、嵌入换行符经命令正文、含空格目录经 --workdir 原样送达真实壳。
	wantVal := "it's \"ok\" $HOME `id`"
	var outBuf, errBuf bytes.Buffer
	args := append(append([]string(nil), baseArgs...),
		"--dialect", "posix", "--interpreter", shellName,
		"--workdir", workDir,
		"--env", "XOPS_QUOTED="+wantVal,
		"127.0.0.1", "--", "printf '%s|%s|%s|%s' \"$(pwd -P)\" \"$XOPS_NATIVE_ENV\" \"$XOPS_QUOTED\" \"line1\nline2\"",
	)
	code := runProcessWithContext(context.Background(), args, strings.NewReader(""), &outBuf, &errBuf)
	wantOut := resolvedWorkDir + "|native-shell-v2|" + wantVal + "|line1\nline2"
	if code != 0 || errBuf.Len() != 0 || outBuf.String() != wantOut {
		t.Fatalf("原生 %s 执行失配: code=%d got=%q want=%q stderr=%q", shellName, code, outBuf.String(), wantOut, errBuf.String())
	}

	// 2. 非零退出码（37）精确透传。
	outBuf.Reset()
	errBuf.Reset()
	exitArgs := append(append([]string(nil), baseArgs...), "--dialect", "posix", "--interpreter", shellName, "127.0.0.1", "--", "exit 37")
	if code := runProcessWithContext(context.Background(), exitArgs, strings.NewReader(""), &outBuf, &errBuf); code != 37 {
		t.Fatalf("原生 %s 退出码应为 37，实际=%d stderr=%q", shellName, code, errBuf.String())
	}
}

func assertNativeFishRawExec(t *testing.T, fishBin, keyPath string, pub ssh.PublicKey) {
	t.Helper()
	srv := startSPSSHServer(t, pub, newRealUnixShellHandler(t.TempDir(), fishBin, nil))
	defer srv.Close()

	baseArgs := []string{
		"exec", "-F", "none", "-p", srv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-o", "SendEnv=XOPS_NATIVE_ENV",
		"--dialect", "raw", "--interpreter", "server",
	}
	var outBuf, errBuf bytes.Buffer
	args := append(append([]string(nil), baseArgs...), "127.0.0.1", "--", `string join ':' alpha beta $XOPS_NATIVE_ENV`)
	if code := runProcessWithContext(context.Background(), args, strings.NewReader(""), &outBuf, &errBuf); code != 0 || outBuf.String() != "alpha:beta:native-shell-v2\n" {
		t.Fatalf("原生 fish --dialect raw 失配: code=%d stdout=%q stderr=%q", code, outBuf.String(), errBuf.String())
	}

	outBuf.Reset()
	errBuf.Reset()
	exitArgs := append(append([]string(nil), baseArgs...), "127.0.0.1", "--", "exit 19")
	if code := runProcessWithContext(context.Background(), exitArgs, strings.NewReader(""), &outBuf, &errBuf); code != 19 {
		t.Fatalf("原生 fish 退出码应为 19，实际=%d stderr=%q", code, errBuf.String())
	}
}

// TestRegress_NativeUnixShellsProbeRealSubprocess 使用真实本机 sh / bash / zsh / fish 子进程验证
// Engine.ProbeShell 的端到端方言探测与 fish 失败关闭语义。
func TestRegress_NativeUnixShellsProbeRealSubprocess(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)
	clientKey, keyPEM := generateGracefulEd25519Key(t)
	keyPath := spWriteTestKey(t, homeDir, "id_native_probe", keyPEM)

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

	for _, tc := range []struct {
		name       string
		wantInterp execution.Interpreter
	}{
		{name: "sh", wantInterp: execution.InterpreterSH},
		{name: "bash", wantInterp: execution.InterpreterBash},
		{name: "zsh", wantInterp: execution.InterpreterZsh},
	} {
		shellBin, err := exec.LookPath(tc.name)
		if err != nil {
			continue
		}
		t.Run("probe-"+tc.name, func(t *testing.T) {
			assertRealPOSIXShellProbe(t, ctx, rt.engine, clientKey.PublicKey(), cliOpts, tc.name, shellBin, tc.wantInterp)
		})
	}

	if fishBin, err := exec.LookPath("fish"); err == nil {
		t.Run("probe-fish-fail-closed", func(t *testing.T) {
			assertRealFishProbeFailClosed(t, ctx, rt.engine, clientKey.PublicKey(), cliOpts, fishBin)
		})
	}
}

func assertRealPOSIXShellProbe(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	pub ssh.PublicKey,
	cliOpts option.OptionLayer,
	name, shellBin string,
	wantInterp execution.Interpreter,
) {
	t.Helper()
	srv := startSPSSHServer(t, pub, newRealUnixShellHandler(t.TempDir(), shellBin, nil))
	defer srv.Close()
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:" + srv.port, CLIOptions: cliOpts}}
	res, pErr := eng.ProbeShell(ctx, engine.ProbeShellRequest{RemoteCall: rc})
	if pErr != nil {
		t.Fatalf("真实 %s ProbeShell 失败: %v", name, pErr)
	}
	if res.Dialect() != execution.DialectPOSIX || res.Interpreter() != wantInterp || res.ProbeStage() != 2 {
		t.Fatalf("真实 %s ProbeShell 失配: dialect=%s interp=%s stage=%d", name, res.Dialect(), res.Interpreter(), res.ProbeStage())
	}
}

func assertRealFishProbeFailClosed(
	t *testing.T,
	ctx context.Context,
	eng *engine.Engine,
	pub ssh.PublicKey,
	cliOpts option.OptionLayer,
	fishBin string,
) {
	t.Helper()
	srv := startSPSSHServer(t, pub, newRealUnixShellHandler(t.TempDir(), fishBin, nil))
	defer srv.Close()
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "deploy@127.0.0.1:" + srv.port, CLIOptions: cliOpts}}
	if res, pErr := eng.ProbeShell(ctx, engine.ProbeShellRequest{RemoteCall: rc}); pErr == nil {
		t.Fatalf("真实 fish 登录壳 ProbeShell 必须失败关闭，实际=%s/%s", res.Dialect(), res.Interpreter())
	}
}

// TestRegress_NativeUnixFakeSudoAndSuInRealShell 在真实 /bin/sh 子进程中运行 sshnet/priv 生成的
// 完整 `LC_ALL=C sudo -S -p '...' -- /bin/sh -c '...'` 与 `LC_ALL=C su 'root' -c 'exec /bin/sh -c ...'`，
// 通过隔离 PATH 中的无特权 POSIX 桩脚本实测真实双重 POSIX 单引号解引用、stdin 口令投递、就绪帧剥离与零口令泄露。
func TestRegress_NativeUnixFakeSudoAndSuInRealShell(t *testing.T) {
	defer goleak.VerifyNone(t)
	shBin, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("系统未安装 /bin/sh")
	}
	homeDir, xopsHome := setupIsolatedRootEnv(t)
	clientKey, keyPEM := generateGracefulEd25519Key(t)
	keyPath := spWriteTestKey(t, homeDir, "id_realsh_priv", keyPEM)

	const (
		sudoPass  = "RealSh!Sudo#Pass-7319"
		suPass    = "RealSh!Su#Pass-6204"
		wrongPass = "RealSh!Bad#Pass-0000"
	)
	vaultFile := spSetupExternalHelperVault(t, xopsHome, map[string]string{
		"extvault/sudo":  sudoPass,
		"extvault/su":    suPass,
		"extvault/wrong": wrongPass,
	})
	t.Setenv(spVaultHelperModeEnv, "serve")
	t.Setenv(spVaultHelperFileEnv, vaultFile)

	fakeBinDir := installFakeSudoSuScripts(t)
	extraEnv := []string{
		"PATH=" + fakeBinDir + ":" + os.Getenv("PATH"),
		"XOPS_FAKE_SUDO_PASS=" + sudoPass,
		"XOPS_FAKE_SU_PASS=" + suPass,
	}
	srv := startSPSSHServer(t, clientKey.PublicKey(), newRealUnixShellHandler(t.TempDir(), shBin, extraEnv))
	defer srv.Close()

	common := []string{
		"exec", "-F", "none", "-p", srv.port, "-l", "deploy", "-i", keyPath,
		"-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
	}

	// 1. 真实 /bin/sh 嵌套单引号解引用 + sudo 口令握手 + --env 含单引号与 $ 零展开。
	var out1, err1 bytes.Buffer
	argsSudo := append(append([]string(nil), common...),
		"--sudo", "--password-ref", "extvault/sudo",
		"--dialect", "posix", "--interpreter", "sh",
		"--env", "MSG=it's $HOME ok",
		"127.0.0.1", "--", `printf 'sudo:%s\n' "$MSG"`,
	)
	if code := runProcessWithContext(context.Background(), argsSudo, strings.NewReader(""), &out1, &err1); code != 0 || out1.String() != "sudo:it's $HOME ok\n" {
		t.Fatalf("真实 /bin/sh sudo 回归失败: code=%d stdout=%q stderr=%q", code, out1.String(), err1.String())
	}
	assertSecretNeverLeaked(t, sudoPass, out1.String(), err1.String(), xopsHome)

	// 2. 真实 /bin/sh + su 目标用户切换与口令握手。
	var out2, err2 bytes.Buffer
	argsSu := append(append([]string(nil), common...),
		"--su", "--privilege-user", "dbadmin", "--password-ref", "extvault/su",
		"127.0.0.1", "--", `printf 'su:%s\n' "$XOPS_SU_TARGET"`,
	)
	if code := runProcessWithContext(context.Background(), argsSu, strings.NewReader(""), &out2, &err2); code != 0 || out2.String() != "su:dbadmin\n" {
		t.Fatalf("真实 /bin/sh su 回归失败: code=%d stdout=%q stderr=%q", code, out2.String(), err2.String())
	}
	assertSecretNeverLeaked(t, suPass, out2.String(), err2.String(), xopsHome)

	// 3. 真实 /bin/sh + 错误 sudo 口令必须拒绝且绝不泄露口令。
	var out3, err3 bytes.Buffer
	argsBad := append(append([]string(nil), common...), "--sudo", "--password-ref", "extvault/wrong", "127.0.0.1", "--", "echo should-never-run")
	if code := runProcessWithContext(context.Background(), argsBad, strings.NewReader(""), &out3, &err3); code != 255 || strings.Contains(out3.String(), "should-never-run") {
		t.Fatalf("真实 /bin/sh 错误 sudo 口令必须拒绝: code=%d stdout=%q stderr=%q", code, out3.String(), err3.String())
	}
	assertSecretNeverLeaked(t, wrongPass, out3.String(), err3.String(), xopsHome)
}

func installFakeSudoSuScripts(t *testing.T) string {
	t.Helper()
	binDir := filepath.Join(t.TempDir(), "fakebin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(fakebin): %v", err)
	}
	sudoScript := `#!/bin/sh
prompt=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -S|-n) shift ;;
    -p) prompt="$2"; shift 2 ;;
    -u) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
printf '%s' "$prompt" >&2
IFS= read -r pw || exit 1
if [ "$pw" != "$XOPS_FAKE_SUDO_PASS" ]; then
  printf 'Sorry, try again.\n' >&2
  exit 1
fi
exec "$@"
`
	suScript := `#!/bin/sh
target="$1"
shift
cmd=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -c) cmd="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf 'Password: ' >&2
IFS= read -r pw || exit 1
if [ "$pw" != "$XOPS_FAKE_SU_PASS" ]; then
  printf 'su: Authentication failure\n' >&2
  exit 1
fi
export XOPS_SU_TARGET="$target"
exec /bin/sh -c "$cmd"
`
	if err := os.WriteFile(filepath.Join(binDir, "sudo"), []byte(sudoScript), 0o700); err != nil {
		t.Fatalf("WriteFile(fake sudo): %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "su"), []byte(suScript), 0o700); err != nil {
		t.Fatalf("WriteFile(fake su): %v", err)
	}
	return binDir
}

func newRealUnixShellHandler(sandboxHome, shellBin string, extraEnv []string) func(context.Context, ssh.Channel, spExecRecord) {
	return func(ctx context.Context, ch ssh.Channel, rec spExecRecord) {
		cmd := exec.CommandContext(ctx, shellBin, "-c", rec.Command)
		env := []string{
			"PATH=" + os.Getenv("PATH"),
			"SHELL=" + shellBin,
			"HOME=" + sandboxHome,
			"XDG_CONFIG_HOME=" + filepath.Join(sandboxHome, "cfg"),
			"XDG_DATA_HOME=" + filepath.Join(sandboxHome, "data"),
			"XDG_CACHE_HOME=" + filepath.Join(sandboxHome, "cache"),
		}
		env = append(env, extraEnv...)
		for k, v := range rec.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
		stdinPipe, pErr := cmd.StdinPipe()
		if pErr != nil {
			spSendExitStatus(ch, 1)
			return
		}
		cmd.Stdout = ch
		cmd.Stderr = ch.Stderr()
		if sErr := cmd.Start(); sErr != nil {
			_ = stdinPipe.Close()
			spSendExitStatus(ch, 1)
			return
		}
		// 显式使用 StdinPipe + conc.RunWait 桥接 stdin，避免 os/exec.Wait 在子进程已退出但客户端尚未关闭通道时阻塞。
		_ = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
			_ = n.Go(func(context.Context) error {
				defer func() { _ = stdinPipe.Close() }()
				_, _ = io.Copy(stdinPipe, ch)
				return nil
			})
			waitErr := cmd.Wait()
			sendUnixCmdExitStatus(ch, waitErr)
			_ = ch.Close()
			return nil
		})
	}
}

func sendUnixCmdExitStatus(ch ssh.Channel, waitErr error) {
	if waitErr == nil {
		spSendExitStatus(ch, 0)
		return
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](waitErr); ok {
		spSendExitStatus(ch, uint32(exitErr.ExitCode()))
		return
	}
	spSendExitStatus(ch, 1)
}
