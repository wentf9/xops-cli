package cli_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func TestApp_InvalidNonNilCatalogFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)

	var out, errBuf bytes.Buffer
	factory := func(context.Context, cli.EngineInitOptions) (cli.EngineHandle, error) {
		return cli.EngineHandle{Runner: &fakeFullEngine{}}, nil
	}
	// 非 nil 无效零值 Catalog 必须严格失败关闭返回 ErrInvalidConfig。
	var invalidCatalog i18n.Catalog
	if _, err := cli.NewApp(cli.AppConfig{
		EngineFactory: factory,
		Stdout:        &out,
		Stderr:        &errBuf,
		Catalog:       &invalidCatalog,
	}); !errors.Is(err, cli.ErrInvalidConfig) {
		t.Fatalf("非 nil 无效 Catalog 应返回 ErrInvalidConfig，实际=%v", err)
	}
	// nil Catalog 仍自动内存加载内置词库。
	app, err := cli.NewApp(cli.AppConfig{
		EngineFactory: factory,
		Stdout:        &out,
		Stderr:        &errBuf,
		Catalog:       nil,
	})
	if err != nil {
		t.Fatalf("nil Catalog 应自动加载内置词库，实际失败=%v", err)
	}
	if code := app.Run(context.Background(), []string{"version"}); code != clikit.ExitOK {
		t.Fatalf("nil Catalog App 运行 version 失败: code=%d stderr=%q", code, errBuf.String())
	}
}

func TestApp_UnifiedPreScannerJSONAndHelpShortCluster(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	// 1. 远端参数或选项值含 --json 时必须输出 stderr 纯文本报错，绝不污染 stdout 为 JSON。
	textErrCases := []struct {
		name string
		args []string
	}{
		{"ssh_bad_lang_remote_json", []string{"ssh", "--lang=fr", "web", "echo", "--json"}},
		{"ssh_short_l_json_bad_lang", []string{"ssh", "-l", "--json", "--lang=fr", "web"}},
		{"global_policy_json", []string{"--policy", "--json", "ssh", "web"}},
		{"ssh_bad_short_remote_json", []string{"ssh", "-z", "web", "mytool", "--json"}},
		{"exec_bad_short_remote_json", []string{"exec", "-z", "web", "mytool", "--json"}},
		{"hosts_create_desc_json", []string{"hosts", "create-host", "--desc", "--json"}},
	}
	for _, tc := range textErrCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
			code := h.app.Run(context.Background(), tc.args)
			if code != clikit.ExitUsage {
				t.Fatalf("args=%v 期望 ExitUsage，实际=%d stdout=%q stderr=%q", tc.args, code, h.stdout.String(), h.stderr.String())
			}
			if h.stdout.Len() != 0 {
				t.Fatalf("args=%v stdout 必须为空（禁止误输出 JSON），实际=%q", tc.args, h.stdout.String())
			}
			if strings.TrimSpace(h.stderr.String()) == "" {
				t.Fatalf("args=%v stderr 应包含文本错误诊断", tc.args)
			}
		})
	}

	// 2. ssh -hl --lang=fr 不得被 -l 吞掉；ssh -hl --lang=zh 必须输出简体中文帮助。
	assertSSHShortClusterHelp(t, cat)
}

func assertSSHShortClusterHelp(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	hBad := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	if code := hBad.app.Run(context.Background(), []string{"ssh", "-hl", "--lang=fr"}); code != clikit.ExitUsage || hBad.stdout.Len() != 0 {
		t.Fatalf("ssh -hl --lang=fr 期望 ExitUsage 且 stdout 空: code=%d out=%q err=%q", code, hBad.stdout.String(), hBad.stderr.String())
	}
	hZh := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	if code := hZh.app.Run(context.Background(), []string{"ssh", "-hl", "--lang=zh"}); code != clikit.ExitOK || hZh.factoryCalls != 0 {
		t.Fatalf("ssh -hl --lang=zh 期望 ExitOK 且零触盘: code=%d calls=%d err=%q", code, hZh.factoryCalls, hZh.stderr.String())
	}
	if !strings.Contains(hZh.stdout.String(), "远端主机连接端口") {
		t.Fatalf("ssh -hl --lang=zh 应渲染中文 SSH 帮助，实际=%q", hZh.stdout.String())
	}
}

func TestApp_MultiLevelSubcommandPrefixesAndSFTPRouting(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	assertSFTPPrefixRouting(t, cat)
	assertMultiLevelPrefixHelpAndExec(t, cat)
}

func assertSFTPPrefixRouting(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	// 1. sftp --lang zh ls web /tmp 路由至 ListRemoteDir，绝不拨号名为 "ls" 的交互主机。
	shellCalled := false
	hLS := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.Catalog = cat
		cfg.RunSFTPShell = func(context.Context, cli.SFTPShellStartRequest) error {
			shellCalled = true
			return nil
		}
	}, nil)
	if code := hLS.app.Run(context.Background(), []string{"sftp", "--lang", "zh", "ls", "web", "/tmp"}); code != clikit.ExitOK {
		t.Fatalf("sftp --lang zh ls web /tmp 失败: code=%d stderr=%q", code, hLS.stderr.String())
	}
	if shellCalled || !hLS.eng.hasCall("ListRemoteDir") || hLS.lastInitOpts.Locale != domi18n.LocaleZh {
		t.Fatalf("sftp --lang zh ls 误路由: shellCalled=%v hasLS=%v loc=%s", shellCalled, hLS.eng.hasCall("ListRemoteDir"), hLS.lastInitOpts.Locale)
	}

	// 2. sftp --json --lang zh ls web /tmp 输出规范 JSON 且不触发交互拒绝。
	hJSON := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.Catalog = cat
		cfg.RunSFTPShell = func(context.Context, cli.SFTPShellStartRequest) error {
			shellCalled = true
			return nil
		}
	}, nil)
	if code := hJSON.app.Run(context.Background(), []string{"sftp", "--json", "--lang", "zh", "ls", "web", "/tmp"}); code != clikit.ExitOK {
		t.Fatalf("sftp --json --lang zh ls 失败: code=%d stderr=%q", code, hJSON.stderr.String())
	}
	var lsOut struct {
		OK bool `json:"ok"`
	}
	if err := jsonv2.Unmarshal(hJSON.stdout.Bytes(), &lsOut); err != nil || !lsOut.OK || shellCalled {
		t.Fatalf("sftp --json --lang zh ls 应输出 JSON 且不进交互壳: err=%v out=%q shell=%v", err, hJSON.stdout.String(), shellCalled)
	}

	// 3. sftp -P 2222 ls web /tmp 跳过前置 SSH 标志后正确识别 ls 子命令。
	hPort := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.Catalog = cat
		cfg.RunSFTPShell = func(context.Context, cli.SFTPShellStartRequest) error {
			shellCalled = true
			return nil
		}
	}, nil)
	if code := hPort.app.Run(context.Background(), []string{"sftp", "-P", "2222", "ls", "web", "/tmp"}); code != clikit.ExitOK {
		t.Fatalf("sftp -P 2222 ls 失败: code=%d stderr=%q", code, hPort.stderr.String())
	}
	if shellCalled || !hPort.eng.hasCall("ListRemoteDir") {
		t.Fatalf("sftp -P 2222 ls 不得误拨号主机 ls")
	}

	// 4. sftp --lang zh web 仍正常进入交互式 SFTP Shell 并透传 LocaleZh。
	var gotShell cli.SFTPShellStartRequest
	hInt := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.Catalog = cat
		cfg.RunSFTPShell = func(_ context.Context, req cli.SFTPShellStartRequest) error {
			gotShell = req
			return nil
		}
	}, nil)
	if code := hInt.app.Run(context.Background(), []string{"sftp", "--lang", "zh", "web"}); code != clikit.ExitOK {
		t.Fatalf("sftp --lang zh web 失败: code=%d stderr=%q", code, hInt.stderr.String())
	}
	if gotShell.TargetSpec != "web" || gotShell.Locale != domi18n.LocaleZh {
		t.Fatalf("sftp --lang zh web 交互壳参数失配: %+v", gotShell)
	}
}

func assertMultiLevelPrefixHelpAndExec(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	// 全部 8 个多级命令族支持 `<cmd> --lang zh --help` 零触盘输出中文帮助。
	helpCmds := []string{"hosts", "creds", "config", "audit", "mux", "playbook", "tunnel", "sftp"}
	for _, cmd := range helpCmds {
		h := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
		code := h.app.Run(context.Background(), []string{cmd, "--lang", "zh", "--help"})
		if code != clikit.ExitOK || h.factoryCalls != 0 || !strings.Contains(h.stdout.String(), "用法：") {
			t.Fatalf("%s --lang zh --help 失败: code=%d calls=%d out=%q err=%q", cmd, code, h.factoryCalls, h.stdout.String(), h.stderr.String())
		}
	}

	// 二级命令前置 --lang / --json 正常路由执行。
	assertMultiLevelPrefixExec(t, cat)
}

func assertMultiLevelPrefixExec(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	hHosts := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	if code := hHosts.app.Run(context.Background(), []string{"hosts", "--lang", "zh", "--json", "list"}); code != clikit.ExitOK || !hHosts.eng.hasCall("ListNodes") || !strings.Contains(hHosts.stdout.String(), `"nodes"`) {
		t.Fatalf("hosts --lang zh --json list 失败: code=%d out=%q err=%q", code, hHosts.stdout.String(), hHosts.stderr.String())
	}
	hCreds := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	if code := hCreds.app.Run(context.Background(), []string{"creds", "--lang", "zh", "status"}); code != clikit.ExitOK || !strings.Contains(hCreds.stdout.String(), "凭据库") {
		t.Fatalf("creds --lang zh status 失败: code=%d out=%q err=%q", code, hCreds.stdout.String(), hCreds.stderr.String())
	}
	hCfg := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	if code := hCfg.app.Run(context.Background(), []string{"config", "--lang", "zh", "formats"}); code != clikit.ExitOK || !hCfg.eng.hasCall("SupportedImportFormats") {
		t.Fatalf("config --lang zh formats 失败: code=%d out=%q err=%q", code, hCfg.stdout.String(), hCfg.stderr.String())
	}
	hAudit := newFullAppHarness(t, func(cfg *cli.AppConfig) {
		cfg.Catalog = cat
		cfg.ReadAuditLog = func(context.Context, clikit.AuditQueryRequest) (clikit.AuditQueryResult, error) {
			return clikit.AuditQueryResult{}, nil
		}
	}, nil)
	if code := hAudit.app.Run(context.Background(), []string{"audit", "--lang", "zh", "list"}); code != clikit.ExitOK || !strings.Contains(hAudit.stdout.String(), "审计记录") {
		t.Fatalf("audit --lang zh list 失败: code=%d out=%q err=%q", code, hAudit.stdout.String(), hAudit.stderr.String())
	}
	assertMultiLevelPrefixOpsExec(t, cat)
}

func assertMultiLevelPrefixOpsExec(t *testing.T, cat *i18n.Catalog) {
	t.Helper()
	hMux := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	if code := hMux.app.Run(context.Background(), []string{"mux", "--lang", "zh", "check", "web"}); code != clikit.ExitOK || !hMux.eng.hasCall("ProbeMux") {
		t.Fatalf("mux --lang zh check web 失败: code=%d out=%q err=%q", code, hMux.stdout.String(), hMux.stderr.String())
	}
	pbYAML := "version: 2\nid: pb-zh\nname: pb\non_error: fail_fast\ntarget:\n  all: true\nsteps:\n  - id: s1\n    name: s1\n    action:\n      kind: shell\n      command: echo ok\n"
	hPB := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, strings.NewReader(pbYAML))
	if code := hPB.app.Run(context.Background(), []string{"playbook", "--lang", "zh", "validate", "--stdin"}); code != clikit.ExitOK || hPB.factoryCalls != 0 || !strings.Contains(hPB.stdout.String(), "Playbook 校验通过") {
		t.Fatalf("playbook --lang zh validate 失败: code=%d calls=%d out=%q err=%q", code, hPB.factoryCalls, hPB.stdout.String(), hPB.stderr.String())
	}
	hTun := newFullAppHarness(t, func(cfg *cli.AppConfig) { cfg.Catalog = cat }, nil)
	tunCtx, tunCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer tunCancel()
	if code := hTun.app.Run(tunCtx, []string{"tunnel", "--lang", "zh", "local", "web", "8080:127.0.0.1:80"}); code != clikit.ExitOK || !hTun.eng.hasCall("StartForward") {
		t.Fatalf("tunnel --lang zh local 失败: code=%d out=%q err=%q", code, hTun.stdout.String(), hTun.stderr.String())
	}
}

func TestApp_ChineseNestedFieldLabelsZeroEnglishLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	cases := []struct {
		name      string
		args      []string
		wantZh    string
		forbidEng string
	}{
		{"scp_remote_dest", []string{"--lang", "zh", "scp", "/tmp/a.txt", "web:bad\x00dest"}, "远端目标路径", "remote destination path"},
		{"scp_remote_src", []string{"--lang", "zh", "scp", "web:bad\x00src", "/tmp/b.txt"}, "远端源路径", "remote source path"},
		{"scp_local_src", []string{"--lang", "zh", "scp", "bad\x00local", "web:/tmp/a.txt"}, "本地源路径", "local source path"},
		{"scp_local_dest", []string{"--lang", "zh", "scp", "web:/tmp/a.txt", "bad\x00dest"}, "本地目标路径", "local destination path"},
		{"sftp_remote_path", []string{"--lang", "zh", "sftp", "ls", "web", "bad\x00path"}, "远端路径", "remote path"},
		{"sftp_old_path", []string{"--lang", "zh", "sftp", "mv", "web", "bad\x00old", "/tmp/new"}, "旧路径", "old path"},
		{"sftp_new_path", []string{"--lang", "zh", "sftp", "mv", "web", "/tmp/old", "bad\x00new"}, "新路径", "new path"},
		{"sftp_transfer_id", []string{"--lang", "zh", "sftp", "recover", "web", "bad op!id"}, "传输 ID", "transfer_id"},
		{"ssh_control_socket", []string{"--lang", "zh", "ssh", "-O", "check", "-S", "../bad.sock", "web"}, "控制套接字路径", "control socket path"},
		{"vault_secret_ref", []string{"--lang", "zh", "creds", "refs", "bad-ref"}, "凭据引用", "secret ref"},
		{"hosts_tag", []string{"--lang", "zh", "hosts", "create-host", "--id", "h1", "--address", "10.0.0.1:22", "--tag", "bad tag!"}, "标签", "invalid tag"},
		{"hosts_alias", []string{"--lang", "zh", "hosts", "create-node", "--id", "n1", "--host", "h1", "--identity", "i1", "--alias", "bad alias!"}, "别名", "invalid alias"},
		{"local_file_path", []string{"--lang", "zh", "playbook", "validate", "bad\x00file.yaml"}, "本地文件路径", "local file path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFullAppHarness(t, func(cfg *cli.AppConfig) {
				cfg.Catalog = cat
				cfg.ReadOperatorFile = func(context.Context, pathalg.LocalSourcePath, pathalg.SymlinkPolicy, int64) ([]byte, error) {
					return nil, engine.ErrNotFound
				}
			}, nil)
			code := h.app.Run(context.Background(), tc.args)
			if code == clikit.ExitOK {
				t.Fatalf("args=%v 应报错退出，实际=0", tc.args)
			}
			got := h.stderr.String()
			if !strings.Contains(got, tc.wantZh) {
				t.Fatalf("args=%v 中文报错缺少 %q，实际=%q", tc.args, tc.wantZh, got)
			}
			if strings.Contains(got, tc.forbidEng) {
				t.Fatalf("args=%v 中文报错不得泄露英文短语 %q，实际=%q", tc.args, tc.forbidEng, got)
			}
		})
	}
}
