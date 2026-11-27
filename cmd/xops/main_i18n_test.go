package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/entry/tui"
	"github.com/wentf9/xops-cli/internal/host/store"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"github.com/wentf9/xops-cli/internal/host/sys/interact"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func setProcessLocaleEnv(t *testing.T, xopsLang, lcAll, lcMessages, lang string) {
	t.Helper()
	t.Setenv("XOPS_LANG", xopsLang)
	t.Setenv("LC_ALL", lcAll)
	t.Setenv("LC_MESSAGES", lcMessages)
	t.Setenv("LANG", lang)
}

func setupUnwritableNoTouchHome(t *testing.T) (homePath, xopsPath string) {
	t.Helper()
	// 使用常规文件作为父路径前缀，确保跨平台（含 root）任何创建目录尝试均失败关闭。
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("block"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocker): %v", err)
	}
	homePath = filepath.Join(blocker, "home")
	xopsPath = filepath.Join(blocker, "xops")
	t.Setenv("HOME", homePath)
	t.Setenv("USERPROFILE", homePath)
	t.Setenv("XOPS_HOME", xopsPath)
	return homePath, xopsPath
}

func runCLIInProc(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runProcessWithContext(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func assertSubstrings(t *testing.T, label, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Fatalf("%s 缺少期望片段 %q\n实际输出:\n%s", label, want, got)
		}
	}
}

func TestRunProcess_LocalePrecedenceAndHelpVersionZeroDiskTouch(t *testing.T) {
	defer goleak.VerifyNone(t)
	_, xopsPath := setupUnwritableNoTouchHome(t)

	// 1. XOPS_LANG=zh -> version 与 --help 默认渲染简体中文且零触盘。
	setProcessLocaleEnv(t, "zh", "", "", "en_US.UTF-8")
	code, out, errOut := runCLIInProc("version")
	if code != 0 || errOut != "" {
		t.Fatalf("XOPS_LANG=zh version 失败: code=%d stderr=%q", code, errOut)
	}
	assertSubstrings(t, "XOPS_LANG=zh version", out, "xops 版本", "提交：", "构建：", "Go：")

	// 2. LC_ALL=C 覆盖 LANG=zh_CN.UTF-8（POSIX 优先级 -> 英文）。
	setProcessLocaleEnv(t, "", "C", "", "zh_CN.UTF-8")
	code, out, errOut = runCLIInProc("version")
	if code != 0 || errOut != "" {
		t.Fatalf("LC_ALL=C version 失败: code=%d stderr=%q", code, errOut)
	}
	assertSubstrings(t, "LC_ALL=C version", out, "xops version", "commit:", "built:", "go:")

	// 3. --lang zh 覆写 XOPS_LANG=en（覆盖 version / --help / help ssh / ssh --help 全路径，含前置与后置）。
	setProcessLocaleEnv(t, "en", "", "", "en_US.UTF-8")
	cases := []struct {
		name  string
		args  []string
		wants []string
	}{
		{name: "prefix --lang zh version", args: []string{"--lang", "zh", "version"}, wants: []string{"xops 版本", "提交："}},
		{name: "postfix version --lang zh", args: []string{"version", "--lang", "zh"}, wants: []string{"xops 版本", "构建："}},
		{name: "--help --lang zh", args: []string{"--help", "--lang", "zh"}, wants: []string{"用法：", "全局选项："}},
		{name: "help ssh --lang zh", args: []string{"help", "ssh", "--lang", "zh"}, wants: []string{"用法：", "ssh"}},
		{name: "ssh --help --lang zh", args: []string{"ssh", "--help", "--lang", "zh"}, wants: []string{"用法：", "ssh"}},
		{name: "version en baseline", args: []string{"version"}, wants: []string{"xops version", "commit:"}},
		{name: "--help en baseline", args: []string{"--help"}, wants: []string{"Usage:", "Global Flags:"}},
	}
	for _, tc := range cases {
		c, o, e := runCLIInProc(tc.args...)
		if c != 0 || e != "" {
			t.Fatalf("%s 期望退出码 0 且 stderr 为空: code=%d stderr=%q stdout=%q", tc.name, c, e, o)
		}
		assertSubstrings(t, tc.name, o, tc.wants...)
	}

	// 4. --lang en 覆写 XOPS_LANG=zh。
	setProcessLocaleEnv(t, "zh", "", "", "zh_CN.UTF-8")
	code, out, errOut = runCLIInProc("version", "--lang", "en")
	if code != 0 || errOut != "" {
		t.Fatalf("version --lang en 失败: code=%d stderr=%q", code, errOut)
	}
	assertSubstrings(t, "version --lang en", out, "xops version", "commit:")

	// 确认全程零触盘：不可写父路径下的 XOPS_HOME 从未被创建。
	if _, statErr := os.Stat(xopsPath); statErr == nil {
		t.Fatalf("help/version 路径绝不应创建 XOPS_HOME: %s", xopsPath)
	}
}

func TestRunProcess_InvalidLangFailClosedAndAppInitErrorLocalization(t *testing.T) {
	defer goleak.VerifyNone(t)
	setupUnwritableNoTouchHome(t)

	// 1. 英文环境下非法 --lang fr：文本与 JSON 均严格 ExitUsage(2) 且 error_code 保持英文常量。
	setProcessLocaleEnv(t, "en", "", "", "en_US.UTF-8")
	code, out, errOut := runCLIInProc("--lang", "fr", "version")
	if code != 2 || out != "" {
		t.Fatalf("EN 非法 --lang fr 期望 ExitUsage(2): code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	assertSubstrings(t, "EN invalid --lang text", errOut, "invalid --lang value fr", "invalid locale")

	code, out, errOut = runCLIInProc("--lang", "fr", "--json", "version")
	if code != 2 || errOut != "" {
		t.Fatalf("EN 非法 --lang fr --json 期望 ExitUsage(2): code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	assertInvalidLangJSONEnvelope(t, out, "usage_error", "invalid --lang value fr", "invalid locale")

	// 2. 中文环境下非法 --lang fr：文本与 JSON 均按环境语言中文渲染错误，同时 error_code 保持英文常量。
	setProcessLocaleEnv(t, "zh", "", "", "zh_CN.UTF-8")
	code, out, errOut = runCLIInProc("--lang", "fr", "version")
	if code != 2 || out != "" {
		t.Fatalf("ZH 非法 --lang fr 期望 ExitUsage(2): code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	assertSubstrings(t, "ZH invalid --lang text", errOut, "选项 --lang 的取值 fr 非法")

	code, out, errOut = runCLIInProc("--lang", "fr", "--json", "version")
	if code != 2 || errOut != "" {
		t.Fatalf("ZH 非法 --lang fr --json 期望 ExitUsage(2): code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	assertInvalidLangJSONEnvelope(t, out, "usage_error", "选项 --lang 的取值 fr 非法")

	// 3. cli.NewApp 失败路径（stdout == nil）同样经 catalog.For(defaultLocale).RenderError 渲染到 stderr。
	var stderrBuf bytes.Buffer
	initCode := runProcessWithContext(context.Background(), []string{"version"}, strings.NewReader(""), nil, &stderrBuf)
	if initCode != 1 {
		t.Fatalf("cli.NewApp 失败期望退出码 1，实际=%d", initCode)
	}
	assertSubstrings(t, "ZH cli.NewApp error", stderrBuf.String(), "xops:", "Stdout 与 Stderr 均不能为空")
}

func assertInvalidLangJSONEnvelope(t *testing.T, rawJSON, wantCode string, wantErrSubstrs ...string) {
	t.Helper()
	var env struct {
		OK        bool   `json:"ok"`
		ErrorCode string `json:"error_code"`
		Error     string `json:"error"`
		ExitCode  int    `json:"exit_code"`
	}
	if err := jsonv2.Unmarshal([]byte(rawJSON), &env); err != nil {
		t.Fatalf("解析错误信封 JSON 失败: err=%v raw=%q", err, rawJSON)
	}
	if env.OK || env.ExitCode != 2 || env.ErrorCode != wantCode {
		t.Fatalf("错误信封字段失配: %+v", env)
	}
	assertSubstrings(t, "JSON error_envelope.error", env.Error, wantErrSubstrs...)
}

func TestTUILocaleChangeSyncsInteractionLocalizer(t *testing.T) {
	defer goleak.VerifyNone(t)
	catalog, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}

	var promptOut bytes.Buffer
	inBuf := bytes.NewBufferString("y\ny\ny\n")
	ui, err := interact.NewStreamInteraction(interact.StreamSpec{
		In:          inBuf,
		Out:         &promptOut,
		Interactive: true,
		Localizer:   catalog.For(domi18n.LocaleEn),
	})
	if err != nil {
		t.Fatalf("NewStreamInteraction: %v", err)
	}

	titleMsg := domi18n.NewMessage(domi18n.KeyInteractHostKeyTitle)
	bodyMsg := domi18n.NewMessage(
		domi18n.KeyInteractHostKeyBody,
		domi18n.BoundStr("algorithm", "ssh-ed25519"),
		domi18n.BoundStr("fingerprint", "SHA256:testfp"),
		domi18n.BoundStr("endpoint", "10.0.0.8:22"),
	)
	confirmReq, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{
		Title:        titleMsg.Canonical(),
		Message:      bodyMsg.Canonical(),
		Subject:      "10.0.0.8:22",
		Risk:         security.RiskModerate,
		TitleMessage: algebraic.Some(titleMsg),
		BodyMessage:  algebraic.Some(bodyMsg),
	})
	if err != nil {
		t.Fatalf("NewConfirmRequest: %v", err)
	}

	m := tui.NewModel(tui.ModelOptions{
		InitialView:    tui.ViewHosts,
		Catalog:        catalog,
		Locale:         domi18n.LocaleEn,
		OnLocaleChange: buildTUILocaleSync(catalog, ui),
	})

	ctx := context.Background()
	// 1. 初始英文：交互提示以英文渲染。
	if v, cErr := ui.Confirm(ctx, confirmReq); cErr != nil || v != security.VerdictAllow {
		t.Fatalf("Confirm(EN) 失败: v=%v err=%v", v, cErr)
	}
	assertSubstrings(t, "initial EN prompt", promptOut.String(), "[moderate] SSH Host Key Verification:", "[y/N]: ")

	// 2. 在 TUI 中按大写 L 切至中文：OnLocaleChange 自动热同步 Interaction.SetLocalizer，后续 SSH 接管提示立即变中文。
	promptOut.Reset()
	next, _ := m.Update(tea.KeyPressMsg{Code: 'L', Text: "L"})
	m = next.(tui.Model)
	if m.Locale() != domi18n.LocaleZh {
		t.Fatalf("按 L 后 TUI 语言期望 LocaleZh，实际=%v", m.Locale())
	}
	if v, cErr := ui.Confirm(ctx, confirmReq); cErr != nil || v != security.VerdictAllow {
		t.Fatalf("Confirm(ZH) 失败: v=%v err=%v", v, cErr)
	}
	assertSubstrings(t, "synced ZH prompt", promptOut.String(), "[中等风险] SSH 主机密钥验证:", "[y/N]: ")

	// 3. 再次按大写 L 切回英文：Interaction 立即回切英文。
	promptOut.Reset()
	next, _ = m.Update(tea.KeyPressMsg{Code: 'L', Text: "L"})
	m = next.(tui.Model)
	if m.Locale() != domi18n.LocaleEn {
		t.Fatalf("再次按 L 后 TUI 语言期望 LocaleEn，实际=%v", m.Locale())
	}
	if v, cErr := ui.Confirm(ctx, confirmReq); cErr != nil || v != security.VerdictAllow {
		t.Fatalf("Confirm(EN back) 失败: v=%v err=%v", v, cErr)
	}
	assertSubstrings(t, "synced back EN prompt", promptOut.String(), "[moderate] SSH Host Key Verification:", "[y/N]: ")
}

func TestWireRuntimeWithLocalizer_KeepsInteractionAndMCPIsolation(t *testing.T) {
	defer goleak.VerifyNone(t)
	setupIsolatedRootEnv(t)
	catalog, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	ctx := context.Background()

	// CLI 模式保留具体 *interact.Interaction 句柄并绑定至 engine.Config.Interaction。
	rt, err := wireRuntimeWithLocalizer(ctx, cli.EngineInitOptions{
		OpenSSHConfigFile: "none",
		Locale:            domi18n.LocaleZh,
	}, runtimeModeCLI, strings.NewReader(""), io.Discard, catalog.For(domi18n.LocaleZh))
	if err != nil {
		t.Fatalf("wireRuntimeWithLocalizer(CLI): %v", err)
	}
	defer func() {
		if cErr := rt.Close(ctx); cErr != nil {
			t.Errorf("rt.Close(CLI): %v", cErr)
		}
	}()
	if rt.interaction == nil || rt.engineCfg.Interaction != rt.interaction {
		t.Fatalf("CLI 模式必须保留具体 *interact.Interaction 并注入 engine.Config")
	}
	syncFn := buildTUILocaleSync(catalog, rt.interaction)
	syncFn(domi18n.LocaleEn)
	syncFn(domi18n.LocaleZh)

	// MCP 模式严守物理隔离：OperatorReadFS / Interaction / Terminal 全为 nil。
	mcpRT, err := wireRuntimeWithLocalizer(ctx, cli.EngineInitOptions{}, runtimeModeMCP, strings.NewReader(""), io.Discard, catalog.For(domi18n.LocaleZh))
	if err != nil {
		t.Fatalf("wireRuntimeWithLocalizer(MCP): %v", err)
	}
	defer func() {
		if cErr := mcpRT.Close(ctx); cErr != nil {
			t.Errorf("mcpRT.Close: %v", cErr)
		}
	}()
	if mcpRT.interaction != nil || mcpRT.engineCfg.Interaction != nil || mcpRT.engineCfg.OperatorReadFS != nil || mcpRT.engineCfg.Terminal != nil {
		t.Fatal("MCP 模式必须物理隔离 Interaction / OperatorReadFS / Terminal")
	}
}

func TestCmdXopsStructuredErrors_BilingualRenderAndSentinels(t *testing.T) {
	defer goleak.VerifyNone(t)
	homeDir, xopsHome := setupIsolatedRootEnv(t)
	catalog, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	enLoc := catalog.For(domi18n.LocaleEn)
	zhLoc := catalog.For(domi18n.LocaleZh)
	ctx := context.Background()

	assertTakeoverStructuredErrors(t, enLoc, zhLoc)
	assertHostWiringStructuredErrors(t, ctx, homeDir, xopsHome, enLoc, zhLoc)
	assertSFTPShellAndShutdownErrors(t, ctx, xopsHome, catalog, enLoc, zhLoc)
}

func assertTakeoverStructuredErrors(t *testing.T, enLoc, zhLoc *i18n.Localizer) {
	t.Helper()
	notStarted, _ := execution.NewOutcomeNotStarted(execution.StartPhaseValidate, "denied", "policy blocked")
	unknown, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "eof", "link dropped")
	cases := []struct {
		err    error
		wantID domi18n.MessageID
		wantEn string
		wantZh string
	}{
		{checkTakeoverOutcome(nil), i18n.KeyCmdTakeoverInvalidOutcome, "invalid outcome", "返回无效终态"},
		{checkTakeoverOutcome((*execution.OutcomeCompleted)(nil)), i18n.KeyCmdTakeoverInvalidOutcome, "invalid outcome", "返回无效终态"},
		{checkTakeoverOutcome(notStarted), i18n.KeyCmdTakeoverNotStarted, "not started", "启动前失败"},
		{checkTakeoverOutcome(unknown), i18n.KeyCmdTakeoverOutcomeUnknown, "outcome unknown", "终态未知"},
	}
	for _, tc := range cases {
		if id, ok := domi18n.ErrorID(tc.err); !ok || id != tc.wantID {
			t.Fatalf("ErrorID(%v) = (%q, %v), want %q", tc.err, id, ok, tc.wantID)
		}
		assertSubstrings(t, "takeover EN", enLoc.RenderError(tc.err), tc.wantEn)
		assertSubstrings(t, "takeover ZH", zhLoc.RenderError(tc.err), tc.wantZh)
	}
}

func assertHostWiringStructuredErrors(
	t *testing.T,
	ctx context.Context,
	homeDir, xopsHome pathalg.LocalDir,
	enLoc, zhLoc *i18n.Localizer,
) {
	t.Helper()
	// 1. homeAwareEnv 未初始化：保留 ports.ErrInvalidArgument 哨兵语义。
	var uninitEnv homeAwareEnv
	_, envErr := uninitEnv.LookupLocalIdentity()
	if !errors.Is(envErr, ports.ErrInvalidArgument) {
		t.Fatalf("未初始化 homeAwareEnv 必须保留 ports.ErrInvalidArgument，实际=%v", envErr)
	}
	assertSubstrings(t, "env EN", enLoc.RenderError(envErr), "homeAwareEnv is not initialized")
	assertSubstrings(t, "env ZH", zhLoc.RenderError(envErr), "尚未初始化")

	// 2. readOperatorFileHook 超限：保留 engine.ErrLimitExceeded 哨兵语义。
	sample := filepath.Join(filepath.FromSlash(homeDir.String()), "oversize.txt")
	if err := os.WriteFile(sample, []byte("0123456789"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	srcPath, _ := pathalg.ParseLocalSourcePath(sample)
	_, limErr := readOperatorFileHook(ctx, srcPath, pathalg.SymlinkFollowOperatorSource, 4)
	if !errors.Is(limErr, engine.ErrLimitExceeded) {
		t.Fatalf("readOperatorFileHook 超限必须保留 engine.ErrLimitExceeded，实际=%v", limErr)
	}
	assertSubstrings(t, "limit EN", enLoc.RenderError(limErr), "exceeds limit")
	assertSubstrings(t, "limit ZH", zhLoc.RenderError(limErr), "超过上限")

	// 3. resolveAuditLocation 裸 home 目录拒绝。
	_, _, auditHomeErr := resolveAuditLocation(xopsHome, homeDir, &store.PolicyConfigDTO{
		Guardrail: &store.GuardrailConfigDTO{AuditLog: "~/audit.jsonl"},
	})
	assertSubstrings(t, "audit home EN", enLoc.RenderError(auditHomeErr), "home directory")
	assertSubstrings(t, "audit home ZH", zhLoc.RenderError(auditHomeErr), "用户家目录")

	// 4. buildVaultAdapters 未知默认存储与不支持的存储类型。
	deps := vaultWireDeps{
		scopedFS: osfs.NewScopedRootFS(),
		stateDir: xopsHome,
		homeDir:  homeDir,
		env:      newHomeAwareEnv(sys.NewSystemEnv()),
		entropy:  sys.NewCryptoEntropy(),
		proc:     sys.NewSystemProcess(),
	}
	_, defErr := buildVaultAdapters(&store.VaultConfigDTO{DefaultStore: "mystery"}, nil, deps)
	assertSubstrings(t, "vault default EN", enLoc.RenderError(defErr), "mystery")
	assertSubstrings(t, "vault default ZH", zhLoc.RenderError(defErr), "不是已知的默认存储")

	_, kindErr := buildVaultAdapters(&store.VaultConfigDTO{
		Stores: map[string]store.VaultStoreDTO{"bad": {Kind: "unsupported_xyz"}},
	}, nil, deps)
	assertSubstrings(t, "vault kind EN", enLoc.RenderError(kindErr), "unsupported_xyz")
	assertSubstrings(t, "vault kind ZH", zhLoc.RenderError(kindErr), "不支持的凭据库存储")
}

func assertSFTPShellAndShutdownErrors(
	t *testing.T,
	ctx context.Context,
	xopsHome pathalg.LocalDir,
	catalog *i18n.Catalog,
	enLoc, zhLoc *i18n.Localizer,
) {
	t.Helper()
	// 1. runSFTPShellSubEntry 校验初始远端目录失败时返回结构化错误且逆序释放全部运行锁。
	sftpErr := runSFTPShellSubEntry(ctx, cli.SFTPShellStartRequest{
		InitOptions: cli.EngineInitOptions{OpenSSHConfigFile: "none"},
		Locale:      domi18n.LocaleZh,
		TargetSpec:  "127.0.0.1",
		InitialDir:  "bad\x00dir",
		Stdin:       strings.NewReader(""),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	}, catalog, domi18n.LocaleZh)
	if id, ok := domi18n.ErrorID(sftpErr); !ok || id != i18n.KeyCmdInvalidDirPath {
		t.Fatalf("runSFTPShellSubEntry 非法 InitialDir 期望 KeyCmdInvalidDirPath，实际=(%q, %v, err=%v)", id, ok, sftpErr)
	}
	assertSubstrings(t, "sftp init dir ZH", zhLoc.RenderError(sftpErr), "路径", "非法")
	assertZeroRemainingLocks(t, xopsHome)

	// 2. shutdownStack 阶段失败保留底层 cause 且双语渲染。
	cause := errors.New("boom-stage")
	st := newShutdownStack(time.Second)
	st.Add("audit", func(context.Context) error { return cause })
	shutErr := st.Close(ctx)
	if !errors.Is(shutErr, cause) {
		t.Fatalf("shutdownStack 必须保留底层错误链: %v", shutErr)
	}
	assertSubstrings(t, "shutdown EN", enLoc.RenderError(shutErr), "shutdown audit failed")
	assertSubstrings(t, "shutdown ZH", zhLoc.RenderError(shutErr), "停机阶段 audit 关闭失败")
}
