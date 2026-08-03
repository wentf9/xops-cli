package i18n

import (
	"testing"
)

func TestInit_DefaultChinese(t *testing.T) {
	t.Setenv("XOPS_LANG", "")
	t.Setenv("LANG", "")
	t.Setenv("LC_ALL", "")

	Init("")
	if Lang() != "zh" {
		t.Errorf("expected default lang 'zh', got %q", Lang())
	}
}

func TestInit_ExplicitEnglish(t *testing.T) {
	Init("en")
	if Lang() != "en" {
		t.Errorf("expected lang 'en', got %q", Lang())
	}
}

func TestInit_FromEnv(t *testing.T) {
	t.Setenv("XOPS_LANG", "en_US.UTF-8")
	Init("")
	if Lang() != "en" {
		t.Errorf("expected lang 'en', got %q", Lang())
	}
}

func TestT_Chinese(t *testing.T) {
	Init("zh")
	got := T("root_short")
	if got == "root_short" {
		t.Errorf("expected translated string, got key %q", got)
	}
	if got != "安全管理和自动化远程主机的命令行工具" {
		t.Errorf("unexpected translation: %q", got)
	}
}

func TestT_English(t *testing.T) {
	Init("en")
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
	Init("zh")
	got := T("nonexistent_key_12345")
	if got != "nonexistent_key_12345" {
		t.Errorf("expected fallback to key, got %q", got)
	}
}

func TestTf_WithData(t *testing.T) {
	Init("zh")
	got := Tf("node_add_success", map[string]any{"Name": "web-01"})
	expected := "成功添加节点: web-01"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestTf_English(t *testing.T) {
	Init("en")
	got := Tf("node_add_success", map[string]any{"Name": "web-01"})
	expected := "Successfully added node: web-01"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestSetLang(t *testing.T) {
	Init("zh")
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
	Init("zh")
	got := Tf("nonexistent_key_99999", map[string]any{"foo": "bar"})
	if got != "nonexistent_key_99999" {
		t.Errorf("expected fallback to key for missing message, got %q", got)
	}
}
