package cmdops_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdops"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type doctorStub struct {
	opsStub
	invRep   engine.InventoryDoctorRep
	vaultRep engine.CredentialDoctorRep
	vaultErr error
}

func (s *doctorStub) InventoryDoctor(_ context.Context, _ engine.InventoryDoctorRequest) (engine.InventoryDoctorRep, error) {
	return s.invRep, nil
}

func (s *doctorStub) VaultDoctor(_ context.Context, _ engine.VaultDoctorRequest) (engine.CredentialDoctorRep, error) {
	if s.vaultErr != nil {
		return engine.CredentialDoctorRep{}, s.vaultErr
	}
	return s.vaultRep, nil
}

func newDoctorStub() *doctorStub {
	causeErr := domi18n.EF(engine.ErrVaultLocked, domi18n.KeyEngineVaultLocked)
	return &doctorStub{
		invRep: engine.InventoryDoctorRep{
			Healthy:       false,
			HostCount:     1,
			IdentityCount: 1,
			NodeCount:     1,
			ErrorCount:    1,
			WarnCount:     1,
			InfoCount:     1,
			Findings: []engine.DoctorFinding{
				{
					Severity:  engine.DoctorSeverityInfo,
					Code:      "unused_host",
					Subject:   "host-legacy",
					Message:   "Host is not referenced by any Node",
					Localized: algebraic.Some(domi18n.NewMessage(domi18n.KeyUCDoctorUnusedHost)),
				},
				{
					Severity:  engine.DoctorSeverityError,
					Code:      "store_load_failed",
					Subject:   "",
					Message:   "failed to load inventory store snapshot: " + causeErr.Error(),
					Localized: algebraic.Some(domi18n.NewMessage(domi18n.KeyUCDoctorStoreLoadSnap)),
					Cause:     causeErr,
				},
				{
					Severity: engine.DoctorSeverityWarn,
					Code:     "legacy_fallback",
					Subject:  "node-1",
					Message:  "plain fallback diagnostic",
				},
			},
		},
		vaultRep: engine.CredentialDoctorRep{
			Healthy:          false,
			ReferencedCount:  2,
			DistinctRefCount: 1,
			Findings: []engine.DoctorFinding{
				{
					Severity:  engine.DoctorSeverityWarn,
					Code:      "vault_locked",
					Subject:   "",
					Message:   "vault is locked; skipping read-only secret probe",
					Localized: algebraic.Some(domi18n.NewMessage(domi18n.KeyUCDoctorVaultLockedSkip)),
				},
				{
					Severity:  engine.DoctorSeverityError,
					Code:      "secret_probe_failed",
					Subject:   "offline/sec-1",
					Message:   "read-only secret probe failed: " + causeErr.Error(),
					Localized: algebraic.Some(domi18n.NewMessage(domi18n.KeyUCDoctorSecretProbeFailed)),
					Cause:     causeErr,
				},
			},
		},
	}
}

func runDoctorWithLocale(t *testing.T, stub *doctorStub, loc *i18n.Localizer, args []string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	rt := &clikit.Runtime{
		Stdin:           strings.NewReader(""),
		Stdout:          &stdout,
		Stderr:          &stderr,
		Localizer:       loc,
		ShutdownTimeout: time.Second,
		EngineFactory: func(context.Context, clikit.EngineInitOptions) (clikit.EngineHandle, error) {
			return clikit.EngineHandle{Runner: stub}, nil
		},
	}
	code := cmdops.RunDoctor(context.Background(), rt, args)
	return code, stdout.String()
}

func assertDoctorTextOutput(t *testing.T, label, out string, wants, forbids []string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Fatalf("%s doctor 输出缺少 %q\n实际输出:\n%s", label, w, out)
		}
	}
	for _, f := range forbids {
		if strings.Contains(out, f) {
			t.Fatalf("%s doctor 输出不得包含 %q\n实际输出:\n%s", label, f, out)
		}
	}
}

func assertDoctorCanonicalJSON(t *testing.T, outJSON string) {
	t.Helper()
	if strings.Contains(outJSON, `"Localized"`) || strings.Contains(outJSON, `"Cause"`) {
		t.Fatalf("Doctor JSON 不得序列化 json:\"-\" 字段:\n%s", outJSON)
	}
	for _, r := range outJSON {
		if unicode.Is(unicode.Han, r) {
			t.Fatalf("Doctor JSON 必须保持 100%% 规范英文（检出汉字 %q）:\n%s", r, outJSON)
		}
	}
	var parsed struct {
		OK        bool                        `json:"ok"`
		Healthy   bool                        `json:"healthy"`
		Inventory *engine.InventoryDoctorRep  `json:"inventory"`
		Vault     *engine.CredentialDoctorRep `json:"vault"`
	}
	if err := jsonv2.Unmarshal([]byte(outJSON), &parsed); err != nil {
		t.Fatalf("Doctor JSON 解析失败: %v\nraw=%s", err, outJSON)
	}
	if !parsed.OK || parsed.Healthy || parsed.Inventory == nil || parsed.Vault == nil {
		t.Fatalf("Doctor JSON 顶层字段异常: %+v", parsed)
	}
	if len(parsed.Inventory.Findings) != 3 || parsed.Inventory.Findings[0].Message != "Host is not referenced by any Node" {
		t.Fatalf("Doctor JSON inventory findings 规范英文异常: %+v", parsed.Inventory.Findings)
	}
	if len(parsed.Vault.Findings) != 2 || !strings.Contains(parsed.Vault.Findings[1].Message, "read-only secret probe failed: engine: secret vault is locked") {
		t.Fatalf("Doctor JSON vault findings 规范英文异常: %+v", parsed.Vault.Findings)
	}
}

func TestRunDoctor_BilingualTextAndCanonicalJSON(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	stub := newDoctorStub()

	codeEN, outEN := runDoctorWithLocale(t, stub, cat.For(domi18n.LocaleEn), []string{"--scope", "all"})
	if codeEN != clikit.ExitGeneral {
		t.Fatalf("unhealthy doctor 应返回 ExitGeneral，实际=%d", codeEN)
	}
	assertDoctorTextOutput(t, "EN", outEN, []string{
		"[info] unused_host (host-legacy): Host is not referenced by any Node",
		"[error] store_load_failed: failed to load inventory store snapshot: engine: secret vault is locked",
		"[warn] legacy_fallback (node-1): plain fallback diagnostic",
		"[warn] vault_locked: vault is locked; skipping read-only secret probe",
		"[error] secret_probe_failed (offline/sec-1): read-only secret probe failed: engine: secret vault is locked",
	}, []string{"()"})

	codeZH, outZH := runDoctorWithLocale(t, stub, cat.For(domi18n.LocaleZh), []string{"--scope", "all"})
	if codeZH != clikit.ExitGeneral {
		t.Fatalf("unhealthy doctor (zh) 应返回 ExitGeneral，实际=%d", codeZH)
	}
	assertDoctorTextOutput(t, "ZH", outZH, []string{
		"[提示] unused_host（host-legacy）：该主机资产未被任何节点引用",
		"[错误] store_load_failed：加载资产存储快照失败：凭据库处于锁定状态",
		"[警告] legacy_fallback（node-1）：plain fallback diagnostic",
		"[警告] vault_locked：凭据库处于锁定状态，跳过只读凭据探活",
		"[错误] secret_probe_failed（offline/sec-1）：只读凭据探活失败：凭据库处于锁定状态",
	}, []string{
		"Host is not referenced",
		"failed to load inventory store snapshot",
		"secret vault is locked",
		"read-only secret probe failed",
		"()",
		"（）",
	})

	codeJSON, outJSON := runDoctorWithLocale(t, stub, cat.For(domi18n.LocaleZh), []string{"--scope", "all", "--json"})
	if codeJSON != clikit.ExitGeneral {
		t.Fatalf("unhealthy doctor (--json) 应返回 ExitGeneral，实际=%d", codeJSON)
	}
	assertDoctorCanonicalJSON(t, outJSON)

	// 验证 Vault 未配置时：中文文本输出本地化说明，而 --lang zh --json 保持规范纯英文 vault_note。
	noVaultStub := &doctorStub{
		invRep:   engine.InventoryDoctorRep{Healthy: true},
		vaultErr: engine.ErrVaultUnavailable,
	}
	codeNVText, outNVText := runDoctorWithLocale(t, noVaultStub, cat.For(domi18n.LocaleZh), []string{"--scope", "all"})
	if codeNVText != clikit.ExitOK {
		t.Fatalf("healthy doctor (zh vault unavailable) 应返回 ExitOK，实际=%d", codeNVText)
	}
	assertDoctorTextOutput(t, "ZH-no-vault", outNVText, []string{"凭据库：未配置凭据库"}, []string{"vault not configured"})

	codeNVJSON, outNVJSON := runDoctorWithLocale(t, noVaultStub, cat.For(domi18n.LocaleZh), []string{"--scope", "all", "--json"})
	if codeNVJSON != clikit.ExitOK {
		t.Fatalf("healthy doctor (--json vault unavailable) 应返回 ExitOK，实际=%d", codeNVJSON)
	}
	for _, r := range outNVJSON {
		if unicode.Is(unicode.Han, r) {
			t.Fatalf("Doctor vault_note JSON 必须保持规范纯英文（检出汉字 %q）:\n%s", r, outNVJSON)
		}
	}
	if !strings.Contains(outNVJSON, `"vault_note":"vault not configured"`) {
		t.Fatalf("Doctor JSON 缺少规范英文 vault_note:\n%s", outNVJSON)
	}

	// 验证 f.Cause 非空但渲染为空串时不得残留尾随冒号（EN ":" 与 ZH "："）。
	emptyCauseStub := &doctorStub{
		invRep: engine.InventoryDoctorRep{
			Healthy:    false,
			ErrorCount: 1,
			Findings: []engine.DoctorFinding{
				{
					Severity:  engine.DoctorSeverityError,
					Code:      "empty_cause",
					Subject:   "offline/sec-2",
					Message:   "read-only secret probe failed",
					Localized: algebraic.Some(domi18n.NewMessage(domi18n.KeyUCDoctorSecretProbeFailed)),
					Cause:     errors.New(""),
				},
			},
		},
		vaultRep: engine.CredentialDoctorRep{Healthy: true},
	}
	_, outECEn := runDoctorWithLocale(t, emptyCauseStub, cat.For(domi18n.LocaleEn), []string{"--scope", "inventory"})
	assertDoctorTextOutput(t, "EN-empty-cause", outECEn,
		[]string{"[error] empty_cause (offline/sec-2): read-only secret probe failed\n"},
		[]string{"read-only secret probe failed:"},
	)
	_, outECZh := runDoctorWithLocale(t, emptyCauseStub, cat.For(domi18n.LocaleZh), []string{"--scope", "inventory"})
	assertDoctorTextOutput(t, "ZH-empty-cause", outECZh,
		[]string{"[错误] empty_cause（offline/sec-2）：只读凭据探活失败\n"},
		[]string{"只读凭据探活失败："},
	)
}
