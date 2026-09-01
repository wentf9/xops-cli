package i18n

import (
	"errors"
	"testing"

	goi18n "github.com/nicksnyder/go-i18n/v2/i18n"
)

func mustInit(t *testing.T, lang string) {
	t.Helper()
	if err := Init(lang); err != nil {
		t.Fatalf("Init(%q) failed: %v", lang, err)
	}
}

func TestInit_DefaultChinese(t *testing.T) {
	t.Setenv("XOPS_LANG", "")
	t.Setenv("LANG", "")
	t.Setenv("LC_ALL", "")

	mustInit(t, "")
	if Lang() != "zh" {
		t.Errorf("expected default lang 'zh', got %q", Lang())
	}
}

func TestInit_ExplicitEnglish(t *testing.T) {
	mustInit(t, "en")
	if Lang() != "en" {
		t.Errorf("expected lang 'en', got %q", Lang())
	}
}

func TestInit_FromEnv(t *testing.T) {
	t.Setenv("XOPS_LANG", "en_US.UTF-8")
	mustInit(t, "")
	if Lang() != "en" {
		t.Errorf("expected lang 'en', got %q", Lang())
	}
}

func TestT_Chinese(t *testing.T) {
	mustInit(t, "zh")
	got := T("root_short")
	if got == "root_short" {
		t.Errorf("expected translated string, got key %q", got)
	}
	if got != "安全管理和自动化远程主机的命令行工具" {
		t.Errorf("unexpected translation: %q", got)
	}
}

func TestT_English(t *testing.T) {
	mustInit(t, "en")
	got := T("root_short")
	if got == "root_short" {
		t.Errorf("expected translated string, got key %q", got)
	}
	expected := "Safely manage and automate remote hosts"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestT_MissingKey(t *testing.T) {
	mustInit(t, "zh")
	got := T("nonexistent_key_12345")
	if got != "nonexistent_key_12345" {
		t.Errorf("expected fallback to key, got %q", got)
	}
}

func TestTf_WithData(t *testing.T) {
	mustInit(t, "zh")
	got := Tf("node_add_success", map[string]any{"Name": "web-01"})
	expected := "成功添加节点: web-01"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestTf_English(t *testing.T) {
	mustInit(t, "en")
	got := Tf("node_add_success", map[string]any{"Name": "web-01"})
	expected := "Successfully added node: web-01"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestSetLang(t *testing.T) {
	mustInit(t, "zh")
	if Lang() != "zh" {
		t.Fatalf("expected zh, got %s", Lang())
	}
	SetLang("en")
	if Lang() != "en" {
		t.Errorf("expected en after SetLang, got %s", Lang())
	}
	got := T("root_short")
	if got == "安全管理和自动化远程主机的命令行工具" {
		t.Errorf("expected english after SetLang, got chinese")
	}
}

func TestNormalizeLang(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"zh", "zh"},
		{"zh_CN", "zh"},
		{"zh-CN", "zh"},
		{"zh_CN.UTF-8", "zh"},
		{"en", "en"},
		{"en_US", "en"},
		{"en_US.UTF-8", "en"},
		{"EN", "en"},
		{"fr_FR", "zh"}, // unsupported falls back to zh
		{"", "zh"},
	}

	for _, tt := range tests {
		got := normalizeLang(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeLang(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestTf_MissingKey(t *testing.T) {
	mustInit(t, "zh")
	got := Tf("nonexistent_key_99999", map[string]any{"foo": "bar"})
	if got != "nonexistent_key_99999" {
		t.Errorf("expected fallback to key for missing message, got %q", got)
	}
}

func TestInit_FailingLoaderDoesNotPublishState(t *testing.T) {
	// 重置内部状态
	mu.Lock()
	initialized.Store(0)
	bundle = nil
	localizer = nil
	mu.Unlock()

	// 注入失败的 loader
	expectedErr := errors.New("simulated load failed")
	err := initWithLoader("zh", func(b *goi18n.Bundle) error {
		return expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}

	// 验证未初始化状态
	if initialized.Load() != 0 {
		t.Errorf("expected initialized to be 0 after failure, got %d", initialized.Load())
	}
	if got := T("root_short"); got != "root_short" {
		t.Errorf("expected fallback to key %q when uninitialized, got %q", "root_short", got)
	}

	// 随后重试正常初始化应成功
	if err := Init("zh"); err != nil {
		t.Fatalf("subsequent Init failed: %v", err)
	}
	if initialized.Load() != 1 {
		t.Errorf("expected initialized to be 1 after successful retry")
	}
	if got := T("root_short"); got == "root_short" {
		t.Errorf("expected translation after successful retry, got raw key %q", got)
	}
}
