package store_test

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/store"
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
