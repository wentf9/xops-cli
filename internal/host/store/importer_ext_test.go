package store_test

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/store"
	"github.com/wentf9/xops-cli/internal/i18n"
	"go.uber.org/goleak"
)

// TestTCKFormatImporterSuite_CSV 验证 CSVImporter 完整通过 core/ports/tck 契约套件。
func TestTCKFormatImporterSuite_CSV(t *testing.T) {
	defer goleak.VerifyNone(t)
	tck.RunFormatImporterSuite(t, tck.FormatImporterFixture{
		NewImporter: func(t *testing.T) ports.FormatImporter {
			imp, err := store.NewCSVImporter(store.CSVImporterSpec{})
			if err != nil {
				t.Fatalf("NewCSVImporter 失败: %v", err)
			}
			return imp
		},
		ValidInput: func() io.Reader {
			return strings.NewReader("name,address,port,user\nweb-01,192.0.2.10,22,deploy\n")
		},
		InvalidInput: func() io.Reader {
			return strings.NewReader("name,address,password,user\nweb-01,192.0.2.10,plaintext,deploy\n")
		},
		SourceName: "hosts.csv",
	})
}

// TestTCKFormatImporterSuite_OpenSSH 验证 OpenSSHImporter 完整通过 core/ports/tck 契约套件。
func TestTCKFormatImporterSuite_OpenSSH(t *testing.T) {
	defer goleak.VerifyNone(t)
	defUser, err := option.ParseUsername("ops")
	if err != nil {
		t.Fatal(err)
	}
	tck.RunFormatImporterSuite(t, tck.FormatImporterFixture{
		NewImporter: func(t *testing.T) ports.FormatImporter {
			imp, iErr := store.NewOpenSSHImporter(store.OpenSSHImporterSpec{
				DefaultUser: algebraic.Some(defUser),
			})
			if iErr != nil {
				t.Fatalf("NewOpenSSHImporter 失败: %v", iErr)
			}
			return imp
		},
		ValidInput: func() io.Reader {
			return strings.NewReader("Host web-01\n  HostName 192.0.2.10\n  Port 2222\n  User deploy\n")
		},
		InvalidInput: func() io.Reader {
			return strings.NewReader("Host web-01\n  Port not-a-number\n")
		},
		SourceName: "~/.ssh/config",
	})
}

// TestCSVImporterHeaderedHeaderlessAndRejectsPlaintextSecrets 验证 CSV 导入器的表头/无表头模式、
// 完整可选列解析与明文密码列严格拒绝（ADR-006）。
func TestCSVImporterHeaderedHeaderlessAndRejectsPlaintextSecrets(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	imp, err := store.NewCSVImporter(store.CSVImporterSpec{})
	if err != nil {
		t.Fatal(err)
	}

	// 1. 带 UTF-8 BOM、# 注释、空行与全部可选扩展列的表头 CSV。
	richCSV := "\xEF\xBB\xBF# XOps v2 CSV inventory\n" +
		"name,address,port,user,key_path,cert_path,proxy_jump,aliases,tags,description\n\n" +
		"bastion-01,198.51.100.1,22,jump,~/.ssh/id_jump,,,,edge;prod,jump host\n" +
		"app-01,198.51.100.20,2222,deploy,~/.ssh/id_app1;~/.ssh/id_app2,~/.ssh/id_app1-cert.pub,bastion-01,a1;a2,app;prod,web node\n"
	bundle, err := imp.Import(ctx, "fleet.csv", strings.NewReader(richCSV))
	if err != nil {
		t.Fatalf("Import(richCSV) 失败: %v", err)
	}
	if len(bundle.Hosts()) != 2 || len(bundle.Identities()) != 2 || len(bundle.Nodes()) != 2 {
		t.Fatalf("CSV 导入资产数异常: hosts=%d idents=%d nodes=%d", len(bundle.Hosts()), len(bundle.Identities()), len(bundle.Nodes()))
	}
	// 验证与空 Graph 做 PlanImport 零冲突。
	rep, err := inventory.PlanImport(inventory.EmptyGraph(), bundle)
	if err != nil || rep.HasConflicts() || rep.AddCount != 6 {
		t.Fatalf("PlanImport(csv) 异常: rep=%+v err=%v", rep, err)
	}

	// 2. 无表头 4 列模式（alias,address,port,user）。
	compact := "# comment\nedge-1,192.0.2.5,2200,ops\n"
	b2, err := imp.Import(ctx, "compact.csv", strings.NewReader(compact))
	if err != nil || len(b2.Nodes()) != 1 || b2.Nodes()[0].ID().String() != "edge-1" {
		t.Fatalf("无表头 4 列 CSV 导入失败: bundle=%v err=%v", b2, err)
	}

	// 3. 严格拒绝明文密码/机密列。
	for _, col := range []string{"password", "passphrase", "secret", "token", "private_key", "totp_secret"} {
		bad := "name,address,port,user," + col + "\nweb,192.0.2.1,22,ops,leak\n"
		if _, err := imp.Import(ctx, "bad.csv", strings.NewReader(bad)); !errors.Is(err, store.ErrPlaintextSecretForbidden) {
			t.Fatalf("包含明文列 %q 返回 %v, 期望 ErrPlaintextSecretForbidden", col, err)
		}
	}

	// 4. 拒绝未知列、空输入与超限流。
	for _, bad := range []string{"", "# only comment\n", "name,address,user,unknown_col\na,192.0.2.1,ops,x\n", "only-two,192.0.2.1\n"} {
		if _, err := imp.Import(ctx, "bad.csv", strings.NewReader(bad)); err == nil {
			t.Fatalf("非法 CSV %q 期望报错但返回 nil", bad)
		}
	}
}

// TestOpenSSHImporterPreservesPolicyAndEmitsWarnings 验证 OpenSSHImporter：
//   - 复用同源单层 t4 自上而下折叠（含 SendEnv -PATTERN、IdentityFile none 封口与 ProxyJump）；
//   - 产出 OriginOpenSSHDerived 节点；
//   - 对 Include、Match exec、Match canonical、模板 IdentityFile 与无 HostName 别名发出结构化 ImportWarning。
func TestOpenSSHImporterPreservesPolicyAndEmitsWarnings(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	defUser, _ := option.ParseUsername("fallbackops")
	imp, err := store.NewOpenSSHImporter(store.OpenSSHImporterSpec{
		DefaultUser: algebraic.Some(defUser),
	})
	if err != nil {
		t.Fatal(err)
	}

	rawCfg := `
Include conf.d/*.conf

Match exec "echo nope"
  Port 9999

Match canonical all
  Port 9998

Host bastion
  HostName 198.51.100.1
  User jump

Host app-01
  HostName 198.51.100.20
  Port 2222
  User deploy
  ProxyJump bastion
  IdentityFile ~/.ssh/id_app
  IdentityFile ~/.ssh/id_%r_template
  IdentityFile none
  CertificateFile ~/.ssh/id_app-cert.pub
  SendEnv LANG LC_* FOO
  ControlMaster auto
  ControlPath ~/.xops/cm-%C
  ControlPersist 5m

Host unresolved_alias_without_hostname
  User nobody

Host *
  SendEnv -LC_TIME -FOO BAR
  IdentityFile ~/.ssh/id_after_none
`
	bundle, err := imp.Import(ctx, "~/.ssh/config", strings.NewReader(rawCfg))
	if err != nil {
		t.Fatalf("OpenSSH Import 失败: %v", err)
	}
	if len(bundle.Nodes()) != 2 {
		t.Fatalf("期望导入 2 个可解析节点（bastion, app-01），实际 %d", len(bundle.Nodes()))
	}
	verifyOpenSSHImportedAppNode(t, bundle)
	verifyOpenSSHImportWarnings(t, bundle.Warnings(), []string{
		"host_unresolved", "include_skipped", "match_canonical_ignored", "match_exec_ignored", "template_key_skipped",
	})
}

func verifyOpenSSHImportedAppNode(t *testing.T, bundle inventory.ImportBundle) {
	t.Helper()
	var appNode inventory.Node
	for _, n := range bundle.Nodes() {
		if n.ID().String() == "app-01" {
			appNode = n
		}
	}
	if !appNode.IsValid() {
		t.Fatal("未找到导入节点 app-01")
	}
	if _, ok := appNode.Origin().(*inventory.OriginOpenSSHDerived); !ok {
		t.Fatalf("导入节点来源类型 = %T, 期望 *OriginOpenSSHDerived", appNode.Origin())
	}
	if gotEnv := appNode.Options().SendEnv().Patterns(); !slices.Equal(gotEnv, []string{"LANG", "LC_*", "BAR"}) {
		t.Fatalf("导入节点 OptionLayer SendEnv = %v, 期望 [LANG LC_* BAR]", gotEnv)
	}
	// 验证 identity 认证为 AuthPrivateKey 且仅保留非模板 key 与 cert。
	for _, id := range bundle.Identities() {
		if id.ID().String() != "ident-app-01" {
			continue
		}
		pk, ok := id.Auth().(*inventory.AuthPrivateKey)
		if !ok || pk.KeyPaths().Len() != 1 || len(pk.CertPaths()) != 1 {
			t.Fatalf("ident-app-01 认证异常: auth=%T", id.Auth())
		}
	}
}

func verifyOpenSSHImportWarnings(t *testing.T, warnings []inventory.ImportWarning, wantCodes []string) {
	t.Helper()
	var gotCodes []string
	for _, w := range warnings {
		gotCodes = append(gotCodes, w.Code())
	}
	for _, code := range wantCodes {
		if !slices.Contains(gotCodes, code) {
			t.Fatalf("缺少预期导入告警 %q，实际告警码=%v", code, gotCodes)
		}
	}
}

// TestOpenSSHImporterLocalizedWarningsBilingual 验证全部 8 类 OpenSSH 导入告警
// （3 类转发自 openssh.StreamDiagnostic + 5 类由 importer_openssh 产生）均携带有效 LocalizedMessage，
// 规范英文与原契约逐字一致，中文渲染完整无占位符残留。
func TestOpenSSHImporterLocalizedWarningsBilingual(t *testing.T) {
	defer goleak.VerifyNone(t)
	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	enLoc := cat.For(domi18n.LocaleEn)
	zhLoc := cat.For(domi18n.LocaleZh)

	imp, err := store.NewOpenSSHImporter(store.OpenSSHImporterSpec{})
	if err != nil {
		t.Fatalf("NewOpenSSHImporter 失败: %v", err)
	}
	rawCfg := `Include conf.d/*.conf
Match canonical all
  Port 9998
Match exec "echo nope"
  Port 9999
Host 2001:db8::1
  HostName 192.0.2.1
  User ops
Host unresolved_no_host
  User ops
Host no-user
  HostName 192.0.2.2
Host cert-only
  HostName 192.0.2.3
  User ops
  CertificateFile ~/.ssh/id_cert.pub
Host tpl-node
  HostName 192.0.2.4
  User ops
  IdentityFile ~/.ssh/id_%r
  CertificateFile ~/.ssh/cert_%r.pub
`
	bundle, err := imp.Import(context.Background(), "~/.ssh/config", strings.NewReader(rawCfg))
	if err != nil {
		t.Fatalf("Import 失败: %v", err)
	}
	wantByCode := map[string][2]string{
		"include_skipped": {
			`line 1: Include "conf.d/*.conf" skipped in stream-only import (local files are not expanded)`,
			`第 1 行：纯流式导入已跳过 Include "conf.d/*.conf"（不展开本地文件）`,
		},
		"match_canonical_ignored": {
			"line 2: Match canonical block ignored (fail-closed by security policy)",
			"第 2 行：已忽略 Match canonical 代码块（按安全策略失败关闭）",
		},
		"match_exec_ignored": {
			"line 4: Match exec block ignored (fail-closed; external commands are never executed)",
			"第 4 行：已忽略 Match exec 代码块（失败关闭；绝不执行外部命令）",
		},
		"alias_skipped": {
			"alias does not satisfy managed NodeID naming rules; skipped",
			"别名不满足托管节点 ID 命名规则，已跳过",
		},
		"host_unresolved": {
			"missing resolvable HostName or valid host; skipped",
			"缺少可解析的 HostName 或有效主机地址，已跳过",
		},
		"user_missing": {
			"missing User and no default username configured; skipped",
			"缺少 User 且未配置默认用户名，已跳过",
		},
		"cert_without_key_skipped": {
			"no usable literal IdentityFile; skipped unbound CertificateFile",
			"缺少可用的字面量 IdentityFile，已跳过未绑定的 CertificateFile",
		},
		"template_key_skipped": {
			`skipped unsupported IdentityFile "~/.ssh/id_%r" for direct import`,
			`直接导入已跳过不受支持的 IdentityFile 项 "~/.ssh/id_%r"`,
		},
		"template_cert_skipped": {
			`skipped unsupported CertificateFile "~/.ssh/cert_%r.pub" for direct import`,
			`直接导入已跳过不受支持的 CertificateFile 项 "~/.ssh/cert_%r.pub"`,
		},
	}
	assertLocalizedWarningsMatch(t, enLoc, zhLoc, bundle.Warnings(), wantByCode)
}

func assertLocalizedWarningsMatch(t *testing.T, enLoc, zhLoc *i18n.Localizer, warnings []inventory.ImportWarning, wantByCode map[string][2]string) {
	t.Helper()
	seen := make(map[string]bool, len(wantByCode))
	for _, w := range warnings {
		want, ok := wantByCode[w.Code()]
		if !ok {
			t.Fatalf("非预期导入告警码 %q: %q", w.Code(), w.Message())
		}
		seen[w.Code()] = true
		assertSingleLocalizedWarning(t, enLoc, zhLoc, w, want[0], want[1])
	}
	for code := range wantByCode {
		if !seen[code] {
			t.Fatalf("缺少预期告警码 %q", code)
		}
	}
}

func assertSingleLocalizedWarning(t *testing.T, enLoc, zhLoc *i18n.Localizer, w inventory.ImportWarning, wantEn, wantZh string) {
	t.Helper()
	if w.Message() != wantEn {
		t.Fatalf("告警 %s 规范英文失配: got=%q want=%q", w.Code(), w.Message(), wantEn)
	}
	msg, hasLoc := w.LocalizedMessage().Get()
	if !hasLoc || !msg.IsValid() || msg.Canonical() != w.Message() || enLoc.Render(msg) != w.Message() {
		t.Fatalf("告警 %s LocalizedMessage 异常: has=%v en=%q msg=%q", w.Code(), hasLoc, enLoc.Render(msg), w.Message())
	}
	if gotZh := zhLoc.Render(msg); gotZh != wantZh {
		t.Fatalf("告警 %s 中文渲染失配: got=%q want=%q", w.Code(), gotZh, wantZh)
	}
}
