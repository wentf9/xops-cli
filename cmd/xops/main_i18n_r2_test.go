package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/host/store"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type failingEnv struct{ base ports.EnvPort }

func (f failingEnv) LookupEnv(key string) (string, bool) { return f.base.LookupEnv(key) }
func (f failingEnv) Environ() map[string]string          { return f.base.Environ() }
func (f failingEnv) LookupLocalIdentity() (ports.LocalIdentityInfo, error) {
	return zeroVal[ports.LocalIdentityInfo](), errors.New("identity probe failed")
}

type failingLongErrWriter struct{ err error }

func (w failingLongErrWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCmdXopsNestedTargetAndComponentLabels_PureChinese(t *testing.T) {
	defer goleak.VerifyNone(t)

	homeDir, xopsHome := setupIsolatedRootEnv(t)
	catalog, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	enLoc := catalog.For(domi18n.LocaleEn)
	zhLoc := catalog.For(domi18n.LocaleZh)
	ctx := context.Background()

	assertCmdXopsTargetLabels(t, ctx, homeDir, xopsHome, catalog, enLoc, zhLoc)
	assertCmdXopsComponentLabels(t, homeDir, xopsHome, enLoc, zhLoc)
}

func assertCmdXopsTargetLabels(
	t *testing.T,
	ctx context.Context,
	homeDir, xopsHome pathalg.LocalDir,
	catalog *i18n.Catalog,
	enLoc, zhLoc *i18n.Localizer,
) {
	t.Helper()
	// 1. resolveHostDirs -> KeyCmdTargetLocalIdentity
	_, _, _, idErr := resolveHostDirs(failingEnv{base: sys.NewSystemEnv()})
	assertPureBilingual(t, "local_identity", idErr, enLoc, zhLoc, "local identity", "本机身份")

	// 2. resolveOpenSSHConfigPath -> KeyCmdTargetOpenSSHConfig
	_, sshCfgErr := resolveOpenSSHConfigPath("bad\x00cfg", homeDir)
	assertPureBilingual(t, "openssh_config", sshCfgErr, enLoc, zhLoc, "OpenSSH config", "OpenSSH 配置")

	// 3. splitAbsoluteAuditLocation -> KeyCmdTargetAuditLogFile
	_, _, audFileErr := splitAbsoluteAuditLocation("/tmp/bad\x00audit.jsonl")
	assertPureBilingual(t, "audit_log_file", audFileErr, enLoc, zhLoc, "policy.guardrail.audit_log file", "policy.guardrail.audit_log 文件")

	// 4. runSFTPShellSubEntry -> KeyCmdTargetInitialRemoteDir
	sftpErr := runSFTPShellSubEntry(ctx, cli.SFTPShellStartRequest{
		InitOptions: cli.EngineInitOptions{OpenSSHConfigFile: "none"},
		Locale:      domi18n.LocaleZh,
		TargetSpec:  "127.0.0.1",
		InitialDir:  "bad\x00dir",
		Stdin:       strings.NewReader(""),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	}, catalog, domi18n.LocaleZh)
	assertPureBilingual(t, "initial_remote_dir", sftpErr, enLoc, zhLoc, "initial remote dir", "初始远端目录")

	// 5. vault_wire offline_aead -> KeyCmdTargetVaultStore（含 {name}）
	deps := vaultWireDeps{
		scopedFS: osfs.NewScopedRootFS(),
		stateDir: xopsHome,
		homeDir:  homeDir,
		env:      newHomeAwareEnv(sys.NewSystemEnv()),
		entropy:  sys.NewCryptoEntropy(),
		proc:     sys.NewSystemProcess(),
	}
	_, _, vDirErr := instantiateVaultStore("corp", store.VaultStoreDTO{Kind: "offline_aead", Path: "bad\x00dir"}, deps)
	assertPureBilingual(t, "vault_store", vDirErr, enLoc, zhLoc, "vault store corp", "凭据库存储 corp")
}

func assertCmdXopsComponentLabels(
	t *testing.T,
	homeDir, xopsHome pathalg.LocalDir,
	enLoc, zhLoc *i18n.Localizer,
) {
	t.Helper()
	// 1. vault_wire: KeyCmdCompExternalHelperVault / KeyCmdCompPlatformKeychainVault / KeyCmdCompOSKeychainVault
	deps := vaultWireDeps{
		scopedFS: osfs.NewScopedRootFS(),
		stateDir: xopsHome,
		homeDir:  homeDir,
		env:      newHomeAwareEnv(sys.NewSystemEnv()),
		entropy:  sys.NewCryptoEntropy(),
		proc:     sys.NewSystemProcess(),
		newOSKeychain: func(ports.EnvPort, ports.Entropy) (ports.SecretVault, error) {
			return nil, errors.New("keychain unavailable")
		},
	}
	_, _, helperErr := instantiateVaultStore("ext", store.VaultStoreDTO{Kind: "external_helper"}, deps)
	assertPureBilingual(t, "external_helper_vault", helperErr, enLoc, zhLoc, "external_helper vault ext", "external_helper 凭据库 ext")

	_, kcDefErr := buildDefaultVaultAdapters("", nil, deps)
	assertPureBilingual(t, "platform_keychain_vault", kcDefErr, enLoc, zhLoc, "platform os_keychain vault", "平台 os_keychain 凭据库")

	_, _, kcNamedErr := instantiateVaultStore("mac", store.VaultStoreDTO{Kind: "os_keychain"}, deps)
	assertPureBilingual(t, "os_keychain_vault", kcNamedErr, enLoc, zhLoc, "os_keychain vault mac", "os_keychain 凭据库 mac")

	// 2. wire.go: KeyCmdCompProcessInstanceID / KeyCmdCompInventoryStore / KeyCmdCompTerminalAdapter / KeyCmdTargetWorkingDir
	_, _, auditErr := buildAuditAdapters(osfs.NewScopedRootFS(), xopsHome, algebraic.None[pathalg.LocalRootedDest](), nil)
	assertPureBilingual(t, "process_instance_id", auditErr, enLoc, zhLoc, "process instance id", "进程实例 ID")

	var emptyAdapters hostAdapters
	invErr := initStoreAndPolicy(context.Background(), cli.EngineInitOptions{}, runtimeModeCLI, zeroVal[ports.LocalIdentityInfo](), &emptyAdapters, newShutdownStack(defaultShutdownGrace))
	assertPureBilingual(t, "inventory_store", invErr, enLoc, zhLoc, "inventory store", "资产存储")

	termErr := i18n.Wrap(errors.New("tty probe failed"), i18n.KeyCmdInitComponentFailed, i18n.Msg("component", i18n.NewMessage(i18n.KeyCmdCompTerminalAdapter)))
	assertPureBilingual(t, "terminal_adapter", termErr, enLoc, zhLoc, "terminal adapter", "终端适配器")

	wdErr := i18n.Wrap(errors.New("getwd failed"), i18n.KeyCmdResolveDirFailed, i18n.Msg("target", i18n.NewMessage(i18n.KeyCmdTargetWorkingDir)))
	assertPureBilingual(t, "working_directory", wdErr, enLoc, zhLoc, "working directory", "工作目录")
}

func assertPureBilingual(t *testing.T, label string, err error, enLoc, zhLoc *i18n.Localizer, wantEn, wantZh string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s 期望错误，实际 nil", label)
	}
	enText := enLoc.RenderError(err)
	zhText := zhLoc.RenderError(err)
	if !strings.Contains(enText, wantEn) {
		t.Fatalf("%s EN 缺少 %q: got=%q", label, wantEn, enText)
	}
	if !strings.Contains(zhText, wantZh) {
		t.Fatalf("%s ZH 缺少 %q: got=%q", label, wantZh, zhText)
	}
	if wantEn != wantZh && strings.Contains(zhText, wantEn) {
		t.Fatalf("%s ZH 不得泄露英文短语 %q: got=%q", label, wantEn, zhText)
	}
}

func TestRunProcess_PlaybookLongMarshalErrorBoundStrAndBatchStatusZh(t *testing.T) {
	defer goleak.VerifyNone(t)
	setupIsolatedRootEnv(t)
	setProcessLocaleEnv(t, "zh", "", "", "zh_CN.UTF-8")

	// 1. 创建一个指向不可达回环端口的资产节点，供 playbook 与 batch exec 生成真实有效的 Engine 报告。
	code, _, errOut := runCLIInProc("hosts", "create-host", "--id", "h1", "--address", "127.0.0.1:1")
	if code != 0 {
		t.Fatalf("create-host 失败: code=%d stderr=%q", code, errOut)
	}
	code, _, errOut = runCLIInProc("hosts", "create-identity", "--id", "i1", "--user", "ops", "--auth-kind", "agent")
	if code != 0 {
		t.Fatalf("create-identity 失败: code=%d stderr=%q", code, errOut)
	}
	code, _, errOut = runCLIInProc("hosts", "create-node", "--id", "n1", "--host", "h1", "--identity", "i1")
	if code != 0 {
		t.Fatalf("create-node 失败: code=%d stderr=%q", code, errOut)
	}

	// 2. playbook run --json 在 Stdout 写入返回 >4096B 错误时必须经 BoundStr 裁剪渲染，绝不泄露字面 {err}。
	pbYAML := "version: 2\nid: pb-long\nname: pb-long\non_error: fail_fast\ntarget:\n  nodes:\n    - n1\nsteps:\n  - id: s1\n    name: s1\n    action:\n      kind: shell\n      command: echo hi\n"
	longWriteErr := errors.New("write-boom-" + strings.Repeat("Z", 5000))
	var stderrBuf bytes.Buffer
	pbCode := runProcessWithContext(
		context.Background(),
		[]string{"--lang", "zh", "playbook", "run", "--stdin", "--json"},
		strings.NewReader(pbYAML),
		failingLongErrWriter{err: longWriteErr},
		&stderrBuf,
	)
	if pbCode != 1 {
		t.Fatalf("playbook JSON 写失败期望退出码 1，实际=%d stderr=%q", pbCode, stderrBuf.String())
	}
	gotErr := stderrBuf.String()
	if !strings.Contains(gotErr, "JSON 序列化失败") || !strings.Contains(gotErr, "write-boom-") {
		t.Fatalf("playbook 超长错误应保留诊断信息: %q", gotErr)
	}
	if strings.Contains(gotErr, "{err}") {
		t.Fatalf("playbook 超长错误绝不得退化为字面 {err}: %q", gotErr)
	}

	// 3. 批量 exec 在中文模式下渲染节点状态标签 [未启动]（不得泄露英文 not_started / failed）。
	execCode, execOut, _ := runCLIInProc("--lang", "zh", "exec", "--all", "--", "echo", "hi")
	if execCode == 0 {
		t.Fatalf("不可达节点批量 exec 不应成功")
	}
	if !strings.Contains(execOut, "[未启动]") || strings.Contains(execOut, "[not_started]") {
		t.Fatalf("批量 exec 中文节点状态标签失配: stdout=%q", execOut)
	}
}
