package cli_test

import (
	"context"
	jsonv2 "encoding/json/v2"
	"slices"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func TestApp_LangFlagPositionsAndZeroDiskTouch(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	cases := []struct {
		name       string
		defaultLoc domi18n.Locale
		args       []string
		wantSub    string
	}{
		{"prefix_help", domi18n.LocaleEn, []string{"--lang", "zh", "--help"}, "用法："},
		{"postfix_help", domi18n.LocaleEn, []string{"--help", "--lang", "zh"}, "用法："},
		{"prefix_version", domi18n.LocaleEn, []string{"--lang", "zh", "version"}, "xops 版本 v2.3.3"},
		{"postfix_version", domi18n.LocaleEn, []string{"version", "--lang", "zh"}, "xops 版本 v2.3.3"},
		{"postfix_version_eq", domi18n.LocaleEn, []string{"version", "--lang=zh"}, "xops 版本 v2.3.3"},
		{"short_version_postfix", domi18n.LocaleEn, []string{"-V", "--lang", "zh"}, "xops 版本 v2.3.3"},
		{"help_topic_postfix", domi18n.LocaleEn, []string{"help", "ssh", "--lang", "zh"}, "远端主机连接端口"},
		{"ssh_help_postfix", domi18n.LocaleEn, []string{"ssh", "--help", "--lang", "zh"}, "远端主机连接端口"},
		{"last_wins_zh_to_en", domi18n.LocaleEn, []string{"--lang", "zh", "--lang", "en", "version"}, "xops version v2.3.3"},
		{"last_wins_en_to_zh", domi18n.LocaleEn, []string{"--lang", "en", "version", "--lang", "zh"}, "xops 版本 v2.3.3"},
		{"default_zh", domi18n.LocaleZh, []string{"version"}, "xops 版本 v2.3.3"},
		{"default_zh_override_en", domi18n.LocaleZh, []string{"version", "--lang", "en"}, "xops version v2.3.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFullAppHarness(t, func(cfg *cli.AppConfig) {
				cfg.Catalog = cat
				cfg.DefaultLocale = tc.defaultLoc
			}, nil)
			code := h.app.Run(context.Background(), tc.args)
			if code != clikit.ExitOK {
				t.Fatalf("args=%v 期望退出码 0，实际=%d stderr=%q", tc.args, code, h.stderr.String())
			}
			if h.factoryCalls != 0 {
				t.Fatalf("args=%v 不得初始化 Engine（零触盘），实际 factoryCalls=%d", tc.args, h.factoryCalls)
			}
			if !strings.Contains(h.stdout.String(), tc.wantSub) {
				t.Fatalf("args=%v 输出缺少 %q，实际=%q", tc.args, tc.wantSub, h.stdout.String())
			}
		})
	}
}

func TestApp_LangFlagInvalidFailClosedAndJSON(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	assertInvalidLangText(t, cat)
	assertInvalidLangJSON(t, cat)
}

func assertInvalidLangText(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	textCases := []struct {
		name       string
		defaultLoc domi18n.Locale
		args       []string
		wantSub    string
	}{
		{"invalid_en", domi18n.LocaleEn, []string{"--lang", "fr", "version"}, "invalid --lang value"},
		{"invalid_zh", domi18n.LocaleZh, []string{"--lang=fr", "--help"}, "--lang"},
		{"missing_en", domi18n.LocaleEn, []string{"version", "--lang"}, "requires a value"},
		{"missing_zh", domi18n.LocaleZh, []string{"ssh", "--lang"}, "缺少参数值"},
	}
	for _, tc := range textCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFullAppHarness(t, func(cfg *cli.AppConfig) {
				cfg.Catalog = cat
				cfg.DefaultLocale = tc.defaultLoc
			}, nil)
			code := h.app.Run(context.Background(), tc.args)
			if code != clikit.ExitUsage || h.factoryCalls != 0 {
				t.Fatalf("args=%v 期望 ExitUsage 且 0 触盘，实际 code=%d calls=%d", tc.args, code, h.factoryCalls)
			}
			if !strings.Contains(h.stderr.String(), tc.wantSub) {
				t.Fatalf("args=%v stderr 缺少 %q，实际=%q", tc.args, tc.wantSub, h.stderr.String())
			}
		})
	}
}

func assertInvalidLangJSON(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	enEnv := runInvalidLangJSON(t, cat, domi18n.LocaleEn)
	zhEnv := runInvalidLangJSON(t, cat, domi18n.LocaleZh)
	if enEnv.Error == zhEnv.Error || !strings.Contains(zhEnv.Error, "非法") {
		t.Fatalf("非法 --lang JSON 错误消息应按语言本地化: en=%q zh=%q", enEnv.Error, zhEnv.Error)
	}
}

func runInvalidLangJSON(t *testing.T, cat *i18n.Catalog, loc domi18n.Locale) clikit.ErrorEnvelope {
	t.Helper()
	h := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.Catalog = cat
		cfg.DefaultLocale = loc
	}, nil)
	code := h.app.Run(context.Background(), []string{"--lang=fr", "--json", "version"})
	if code != clikit.ExitUsage || h.factoryCalls != 0 {
		t.Fatalf("loc=%s 期望 ExitUsage 且 0 触盘，实际 code=%d calls=%d", loc, code, h.factoryCalls)
	}
	var env clikit.ErrorEnvelope
	if err := jsonv2.Unmarshal(h.stdout.Bytes(), &env); err != nil {
		t.Fatalf("loc=%s JSON 解析失败: %v raw=%q", loc, err, h.stdout.String())
	}
	if env.OK || env.ErrorCode != "usage_error" {
		t.Fatalf("loc=%s ErrorEnvelope 契约失配: %+v", loc, env)
	}
	return env
}

func TestApp_LangFlagRemotePassthroughAndValueFlags(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	assertScanLangIgnoresValueAndRemoteArgs(t)
	assertSSHRemotePassthrough(t, cat)
	assertExecRemotePassthrough(t, cat)
}

func assertScanLangIgnoresValueAndRemoteArgs(t *testing.T) {
	t.Helper()
	for _, rawArgs := range [][]string{
		{"ssh", "web", "mytool", "--lang=fr"},
		{"ssh", "web", "mytool", "--lang", "zh"},
		{"ssh", "-l", "--lang", "web", "hostname"},
		{"ssh", "-tl", "--lang", "web", "hostname"},
		{"ssh", "-o", "SetEnv=--lang=fr", "web", "hostname"},
		{"ssh", "--", "--lang=fr"},
		{"-F", "--lang", "ssh", "web", "id"},
	} {
		locOpt, err := clikit.ScanLangFlag(rawArgs)
		if err != nil || locOpt.IsSome() {
			t.Fatalf("ScanLangFlag(%v) 应忽略值/远端参数中的 --lang: opt=%v err=%v", rawArgs, locOpt, err)
		}
	}
}

func assertSSHRemotePassthrough(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	sshPassthrough := []struct {
		name     string
		args     []string
		wantCmd  []string
		wantLoc  domi18n.Locale
		wantHost string
	}{
		{"remote_eq_fr", []string{"ssh", "web", "mytool", "--lang=fr"}, []string{"mytool", "--lang=fr"}, domi18n.LocaleEn, "web"},
		{"remote_sep_zh", []string{"ssh", "web", "mytool", "--lang", "zh"}, []string{"mytool", "--lang", "zh"}, domi18n.LocaleEn, "web"},
		{"short_o_identity_val", []string{"ssh", "-o", "IdentityFile=/tmp/--lang=fr", "web", "hostname"}, []string{"hostname"}, domi18n.LocaleEn, "web"},
		{"global_F_val", []string{"-F", "--lang", "ssh", "web", "id"}, []string{"id"}, domi18n.LocaleEn, "web"},
		{"ssh_prefix_lang_zh", []string{"ssh", "--lang", "zh", "web", "uname", "--lang=fr"}, []string{"uname", "--lang=fr"}, domi18n.LocaleZh, "web"},
	}
	for _, tc := range sshPassthrough {
		t.Run(tc.name, func(t *testing.T) {
			h := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
			if code := h.app.Run(context.Background(), tc.args); code != clikit.ExitOK {
				t.Fatalf("args=%v 不应误判 --lang: code=%d stderr=%q", tc.args, code, h.stderr.String())
			}
			if !slices.Equal(h.eng.lastSSHReq.CommandArgs, tc.wantCmd) || h.eng.lastSSHReq.TargetSpec != tc.wantHost {
				t.Fatalf("args=%v 远端透传失配: host=%q cmd=%v", tc.args, h.eng.lastSSHReq.TargetSpec, h.eng.lastSSHReq.CommandArgs)
			}
			if h.lastInitOpts.Locale != tc.wantLoc {
				t.Fatalf("args=%v Locale 期望=%s 实际=%s", tc.args, tc.wantLoc, h.lastInitOpts.Locale)
			}
		})
	}
	hUser := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	if code := hUser.app.Run(context.Background(), []string{"ssh", "-l", "--lang", "web", "hostname"}); code != clikit.ExitUsage || !strings.Contains(hUser.stderr.String(), "invalid -l value") {
		t.Fatalf("ssh -l --lang 应报错于 -l 而非 --lang: code=%d stderr=%q", code, hUser.stderr.String())
	}
}

func assertExecRemotePassthrough(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	hExec := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	if code := hExec.app.Run(context.Background(), []string{"exec", "--lang", "zh", "web", "--", "echo", "--lang=fr"}); code != clikit.ExitOK {
		t.Fatalf("exec --lang zh 透传远端 --lang=fr 失败: code=%d stderr=%q", code, hExec.stderr.String())
	}
	if hExec.lastInitOpts.Locale != domi18n.LocaleZh {
		t.Fatalf("exec Locale 期望 zh，实际=%s", hExec.lastInitOpts.Locale)
	}
}

func TestApp_JSONErrorExecDiagnosticAndMuxContract(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	assertJSONErrorEnvelopeBilingual(t, cat)
	assertExecDiagnosticBilingual(t, cat)
	assertOpenSSHMuxEnglishContract(t, cat)
}

func assertJSONErrorEnvelopeBilingual(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	envEn := runUnsupportedJSON(t, cat, "en")
	envZh := runUnsupportedJSON(t, cat, "zh")
	if envEn.Error == envZh.Error || !strings.Contains(envZh.Error, "暂未开放") {
		t.Fatalf("ErrorEnvelope.Error 必须双语本地化: en=%q zh=%q", envEn.Error, envZh.Error)
	}
}

func runUnsupportedJSON(t *testing.T, cat *i18n.Catalog, lang string) clikit.ErrorEnvelope {
	t.Helper()
	h := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	code := h.app.Run(context.Background(), []string{"--lang", lang, "--json", "ssh", "-W", "10.0.0.5:443", "bastion"})
	if code != clikit.ExitSSHError {
		t.Fatalf("lang=%s ssh -W 期望 255，实际=%d", lang, code)
	}
	var env clikit.ErrorEnvelope
	if err := jsonv2.Unmarshal(h.stdout.Bytes(), &env); err != nil {
		t.Fatalf("lang=%s JSON 解析失败: %v", lang, err)
	}
	if env.OK || env.ErrorCode != "unsupported" {
		t.Fatalf("lang=%s error_code 必须恒为 unsupported: %+v", lang, env)
	}
	return env
}

func assertExecDiagnosticBilingual(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	viewEn := runUnknownOutcomeJSON(t, cat, "en")
	viewZh := runUnknownOutcomeJSON(t, cat, "zh")
	if !viewEn.DoNotRetry || !viewZh.DoNotRetry || viewEn.ExitCode != viewZh.ExitCode {
		t.Fatalf("ExecOutcomeView 机器字段不可漂移: en=%+v zh=%+v", viewEn, viewZh)
	}
	if !strings.Contains(viewEn.Diagnostic, "outcome unknown") || !strings.Contains(viewZh.Diagnostic, "终态未知") {
		t.Fatalf("ExecOutcomeView.Diagnostic 应双语本地化: en=%q zh=%q", viewEn.Diagnostic, viewZh.Diagnostic)
	}
}

func runUnknownOutcomeJSON(t *testing.T, cat *i18n.Catalog, lang string) clikit.ExecOutcomeView {
	t.Helper()
	h := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	h.eng.runSSHFn = func(context.Context, engine.RunSSHRequest) (execution.ExecutionOutcome, error) {
		out, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "broken_pipe", "connection reset")
		return out, nil
	}
	code := h.app.Run(context.Background(), []string{"--lang", lang, "ssh", "--json", "web", "id"})
	if code != clikit.ExitSSHError {
		t.Fatalf("lang=%s OutcomeUnknown 期望 255，实际=%d", lang, code)
	}
	var view clikit.ExecOutcomeView
	if err := jsonv2.Unmarshal(h.stdout.Bytes(), &view); err != nil {
		t.Fatalf("lang=%s ExecOutcomeView 解析失败: %v", lang, err)
	}
	return view
}

func assertOpenSSHMuxEnglishContract(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	hMux := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	if code := hMux.app.Run(context.Background(), []string{"--lang", "zh", "mux", "check", "web"}); code != clikit.ExitOK {
		t.Fatalf("mux check 失败: code=%d stderr=%q", code, hMux.stderr.String())
	}
	if !strings.Contains(hMux.stdout.String(), "mux check: master running (pid=4242)") {
		t.Fatalf("OpenSSH -O 机器契约必须保持英文输出，实际=%q", hMux.stdout.String())
	}
}

func TestApp_LocalePropagationToSubEntries(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	var gotTUI cli.TUIStartRequest
	var gotSFTP cli.SFTPShellStartRequest
	var gotMCP cli.MCPStartRequest
	var gotMux cli.MuxDaemonStartRequest
	h := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.Catalog = cat
		cfg.RunTUI = func(_ context.Context, req cli.TUIStartRequest) error {
			gotTUI = req
			return nil
		}
		cfg.RunSFTPShell = func(_ context.Context, req cli.SFTPShellStartRequest) error {
			gotSFTP = req
			return nil
		}
		cfg.RunMCP = func(_ context.Context, req cli.MCPStartRequest) error {
			gotMCP = req
			return nil
		}
		cfg.RunMuxDaemon = func(_ context.Context, req cli.MuxDaemonStartRequest) error {
			gotMux = req
			return nil
		}
	}, nil)

	for _, args := range [][]string{
		{"--lang", "zh", "tui"},
		{"--lang", "zh", "sftp", "web"},
		{"--lang", "zh", "mcp", "serve"},
		{"--lang", "zh", "ssh", "-f", "-N", "-L", "8080:db:5432", "web"},
	} {
		if code := h.app.Run(context.Background(), args); code != clikit.ExitOK {
			t.Fatalf("子入口 %v 失败: code=%d stderr=%q", args, code, h.stderr.String())
		}
	}
	if gotTUI.Locale != domi18n.LocaleZh || gotTUI.InitOptions.Locale != domi18n.LocaleZh {
		t.Fatalf("TUIStartRequest 未透传 LocaleZh: %+v", gotTUI)
	}
	if gotSFTP.Locale != domi18n.LocaleZh || gotSFTP.InitOptions.Locale != domi18n.LocaleZh {
		t.Fatalf("SFTPShellStartRequest 未透传 LocaleZh: %+v", gotSFTP)
	}
	if gotMCP.Locale != domi18n.LocaleZh || gotMCP.InitOptions.Locale != domi18n.LocaleZh {
		t.Fatalf("MCPStartRequest 未透传 LocaleZh: %+v", gotMCP)
	}
	if gotMux.Locale != domi18n.LocaleZh || gotMux.InitOptions.Locale != domi18n.LocaleZh {
		t.Fatalf("MuxDaemonStartRequest 未透传 LocaleZh: %+v", gotMux)
	}
}

func TestApp_VaultInteractivePromptsStructuredMessages(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	h := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)

	// 1) vault init（主口令 + 确认口令）
	if code := h.app.Run(context.Background(), []string{"vault", "init"}); code != clikit.ExitOK {
		t.Fatalf("vault init 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	assertPromptMessageIDs(t, "vault init primary", h.eng.lastVaultInitReq.Prompt,
		i18n.KeyInteractVaultInitTitle, i18n.KeyInteractVaultMasterPrompt)
	confirmPrompt, ok := h.eng.lastVaultInitReq.ConfirmPrompt.Get()
	if !ok {
		t.Fatalf("vault init 必须携带 ConfirmPrompt")
	}
	assertPromptMessageIDs(t, "vault init confirm", confirmPrompt,
		i18n.KeyInteractVaultConfirmTitle, i18n.KeyInteractVaultConfirmPrompt)

	// 2) vault unlock
	if code := h.app.Run(context.Background(), []string{"vault", "unlock"}); code != clikit.ExitOK {
		t.Fatalf("vault unlock 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	assertPromptMessageIDs(t, "vault unlock", h.eng.lastVaultUnlockReq.Prompt,
		i18n.KeyInteractVaultUnlockTitle, i18n.KeyInteractVaultMasterPrompt)

	// 3) vault enroll-password
	if code := h.app.Run(context.Background(), []string{"vault", "enroll-password", "--id", "pw-1", "--user", "ops", "--store", "offline"}); code != clikit.ExitOK {
		t.Fatalf("vault enroll-password 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	assertPromptMessageIDs(t, "vault enroll-password", h.eng.lastVaultSaga.Prompt,
		i18n.KeyInteractVaultEnrollPassTitle, i18n.KeyInteractVaultEnrollPassPrompt)

	// 4) vault set-node-privilege
	if code := h.app.Run(context.Background(), []string{"vault", "set-node-privilege", "--node", "web-1", "--ref", "offline/sudo"}); code != clikit.ExitOK {
		t.Fatalf("vault set-node-privilege 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	assertPromptMessageIDs(t, "vault set-node-privilege", h.eng.lastVaultSaga.Prompt,
		i18n.KeyInteractVaultNodePrivTitle, i18n.KeyInteractVaultNodePrivPrompt)

	// 5) vault rotate
	if code := h.app.Run(context.Background(), []string{"vault", "rotate", "offline/old", "--store", "offline"}); code != clikit.ExitOK {
		t.Fatalf("vault rotate 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	assertPromptMessageIDs(t, "vault rotate", h.eng.lastRotateReq.Prompt,
		i18n.KeyInteractVaultRotateTitle, i18n.KeyInteractVaultRotatePrompt)

	// 6) vault enroll-key
	if code := h.app.Run(context.Background(), []string{"vault", "enroll-key", "--id", "key-1", "--user", "ops", "--key-path", "/home/ops/.ssh/id_ed25519"}); code != clikit.ExitOK {
		t.Fatalf("vault enroll-key 失败: code=%d stderr=%q", code, h.stderr.String())
	}
	assertPromptMessageIDs(t, "vault enroll-key", h.eng.lastEnrollReq.Prompt,
		i18n.KeyInteractVaultEnrollKeyTitle, i18n.KeyInteractVaultEnrollKeyPrompt)
}

func assertPromptMessageIDs(t *testing.T, label string, req engine.SecretPromptRequest, wantTitle, wantBody domi18n.MessageID) {
	t.Helper()
	if !req.IsValid() {
		t.Fatalf("%s: SecretPromptRequest 无效", label)
	}
	tMsg, okT := req.TitleMessage().Get()
	bMsg, okB := req.BodyMessage().Get()
	if !okT || !okB || tMsg.ID() != wantTitle || bMsg.ID() != wantBody {
		t.Fatalf("%s: MessageID 失配: title=(%v,%q) body=(%v,%q)", label, okT, tMsg.ID(), okB, bMsg.ID())
	}
	if req.Title() != tMsg.Canonical() || req.Prompt() != bMsg.Canonical() {
		t.Fatalf("%s: 规范英文兜底与结构化消息不一致: title=%q vs %q, prompt=%q vs %q",
			label, req.Title(), tMsg.Canonical(), req.Prompt(), bMsg.Canonical())
	}
}
