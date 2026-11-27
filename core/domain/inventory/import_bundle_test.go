package inventory_test

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
)

// TestImportWarningLocalizedAndJSONRoundTrip 验证 ImportWarning 的双轨本地化构造器、
// 只读访问器、Equal 规范字段比对语义以及 JSON 线协议零泄露往返不变性。
func TestImportWarningLocalizedAndJSONRoundTrip(t *testing.T) {
	msg := domi18n.NewMessage(domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "host"), domi18n.BoundStr("value", "bad-host"))
	assertLocalizedWarningRejects(t, msg)
	locWarn := mustLocalizedWarning(t, "invalid_host", "web-1", msg)
	assertLocalizedWarningParity(t, locWarn, msg)
	assertImportWarningJSONRoundTrip(t, locWarn)
	assertImportBundleWarningJSONRoundTrip(t, locWarn)
}

func assertLocalizedWarningRejects(t *testing.T, validMsg domi18n.Message) {
	t.Helper()
	var zero inventory.ImportWarning
	if zero.IsValid() || zero.LocalizedMessage().IsSome() {
		t.Fatalf("零值 ImportWarning 必须无效且 LocalizedMessage 为 None: valid=%v", zero.IsValid())
	}
	var zeroMsg domi18n.Message
	multiLineMsg := domi18n.NewMessage(domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "host"), domi18n.BoundStr("value", "a\nb"))
	cases := []struct {
		name, code, subject string
		msg                 domi18n.Message
	}{
		{"invalid_message", "warn_code", "web-1", zeroMsg},
		{"invalid_code", "bad code", "web-1", validMsg},
		{"multiline_subject", "warn_code", "bad\nsubject", validMsg},
		{"multiline_canonical", "warn_code", "web-1", multiLineMsg},
	}
	for _, tc := range cases {
		if _, err := inventory.NewLocalizedImportWarning(tc.code, tc.subject, tc.msg); !errors.Is(err, inventory.ErrInvalidImportBundle) {
			t.Fatalf("%s 期望 ErrInvalidImportBundle，实际=%v", tc.name, err)
		}
	}
}

func mustLocalizedWarning(t *testing.T, code, subject string, msg domi18n.Message) inventory.ImportWarning {
	t.Helper()
	w, err := inventory.NewLocalizedImportWarning(code, subject, msg)
	if err != nil {
		t.Fatalf("NewLocalizedImportWarning 失败: %v", err)
	}
	return w
}

func assertLocalizedWarningParity(t *testing.T, locWarn inventory.ImportWarning, msg domi18n.Message) {
	t.Helper()
	if !locWarn.IsValid() || locWarn.Code() != "invalid_host" || locWarn.Subject() != "web-1" || locWarn.Message() != msg.Canonical() {
		t.Fatalf("ImportWarning 字段失配: code=%q subj=%q msg=%q want=%q", locWarn.Code(), locWarn.Subject(), locWarn.Message(), msg.Canonical())
	}
	gotMsg, ok := locWarn.LocalizedMessage().Get()
	if !ok || !gotMsg.Equal(msg) {
		t.Fatalf("LocalizedMessage() 失配: ok=%v got=%v want=%v", ok, gotMsg, msg)
	}
	plainWarn, err := inventory.NewImportWarning("invalid_host", "web-1", msg.Canonical())
	if err != nil {
		t.Fatalf("NewImportWarning 失败: %v", err)
	}
	if plainWarn.LocalizedMessage().IsSome() || !locWarn.Equal(plainWarn) || !plainWarn.Equal(locWarn) {
		t.Fatalf("Equal 须仅比对规范字段且普通构造器 LocalizedMessage 为 None")
	}
}

func assertImportWarningJSONRoundTrip(t *testing.T, locWarn inventory.ImportWarning) {
	t.Helper()
	raw, err := jsonv2.Marshal(locWarn, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal ImportWarning 失败: %v", err)
	}
	if strings.Contains(string(raw), "localized") {
		t.Fatalf("JSON 线协议不得包含 localized 字段: %s", raw)
	}
	var dec inventory.ImportWarning
	if err := jsonv2.Unmarshal(raw, &dec); err != nil {
		t.Fatalf("Unmarshal ImportWarning 失败: %v", err)
	}
	if !dec.IsValid() || dec.LocalizedMessage().IsSome() || !dec.Equal(locWarn) || !locWarn.Equal(dec) {
		t.Fatalf("ImportWarning JSON 往返失配: valid=%v hasLoc=%v eq=%v raw=%s", dec.IsValid(), dec.LocalizedMessage().IsSome(), dec.Equal(locWarn), raw)
	}
}

func assertImportBundleWarningJSONRoundTrip(t *testing.T, locWarn inventory.ImportWarning) {
	t.Helper()
	bundle, err := inventory.NewImportBundle(inventory.ImportBundleSpec{
		SourceFormat: "openssh",
		Warnings:     []inventory.ImportWarning{locWarn},
	})
	if err != nil {
		t.Fatalf("NewImportBundle 失败: %v", err)
	}
	if ws := bundle.Warnings(); len(ws) != 1 || ws[0].LocalizedMessage().IsNone() {
		t.Fatalf("ImportBundle 须保留内存态 LocalizedMessage: %+v", ws)
	}
	raw, err := jsonv2.Marshal(bundle, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal ImportBundle 失败: %v", err)
	}
	if strings.Contains(string(raw), "localized") {
		t.Fatalf("ImportBundle JSON 不得泄露 localized 字段: %s", raw)
	}
	var dec inventory.ImportBundle
	if err := jsonv2.Unmarshal(raw, &dec); err != nil {
		t.Fatalf("Unmarshal ImportBundle 失败: %v", err)
	}
	if !dec.Equal(bundle) || dec.Warnings()[0].LocalizedMessage().IsSome() {
		t.Fatalf("ImportBundle JSON 往返失配: eq=%v", dec.Equal(bundle))
	}
}
