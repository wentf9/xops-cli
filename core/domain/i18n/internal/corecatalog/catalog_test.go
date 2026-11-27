package corecatalog_test

import (
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/i18n/internal/corecatalog"
)

const (
	maxKeyBytes      = 128
	maxTemplateBytes = 4096
	maxPlaceholders  = 16
)

func TestCatalogInvariants(t *testing.T) {
	keys := corecatalog.AllKeys()
	if len(keys) == 0 {
		t.Fatal("AllKeys() 不得为空")
	}
	if !slices.IsSorted(keys) {
		t.Fatal("AllKeys() 必须按字典序严格升序排列")
	}
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if !isValidKey(k) {
			t.Errorf("非法核心键名: %q", k)
		}
		if seen[k] {
			t.Errorf("AllKeys() 包含重复键: %q", k)
		}
		seen[k] = true
		val := corecatalog.Lookup(k)
		assertValidFallbackTemplate(t, k, val)
	}
}

func TestLookupUnknownAndDefensiveCopy(t *testing.T) {
	for _, bad := range []string{"", "unknown.key", "i18n.nonexistent", "UPPER.case"} {
		if got := corecatalog.Lookup(bad); got != "" {
			t.Fatalf("Lookup(%q) = %q, 期望空串", bad, got)
		}
	}
	first := corecatalog.AllKeys()
	orig := first[0]
	first[0] = "mutated.key"
	second := corecatalog.AllKeys()
	if second[0] != orig {
		t.Fatalf("AllKeys() 必须返回独立副本: got=%q want=%q", second[0], orig)
	}
}

func TestLegacyM1M2FallbacksUnchanged(t *testing.T) {
	cases := map[string]string{
		"i18n.locale.invalid":             "i18n: invalid locale",
		"i18n.locale.invalid_value":       "i18n: invalid locale {value}",
		"i18n.nil_receiver":               "i18n: unmarshal target receiver must not be nil",
		"common.nil_context":              "context must not be nil",
		"common.error_join":               "{head}: {tail}",
		"interact.hostkey.title":          "SSH Host Key Verification",
		"interact.hostkey.body":           "Trust unknown SSH host key {algorithm} ({fingerprint}) for {endpoint}?",
		"interact.ssh_challenge.response": "Response:",
		"interact.mux.attach_body":        "Attach to active ControlMaster via DialMux",
	}
	for k, want := range cases {
		if got := corecatalog.Lookup(k); got != want {
			t.Errorf("既有键 %q 兜底发生漂移: got=%q want=%q", k, got, want)
		}
	}
}

func assertValidFallbackTemplate(t *testing.T, key, tmpl string) {
	t.Helper()
	if strings.TrimSpace(tmpl) == "" || len(tmpl) > maxTemplateBytes || !utf8.ValidString(tmpl) {
		t.Errorf("键 %q 兜底模板为空、超长或非法 UTF-8: %q", key, tmpl)
		return
	}
	for _, r := range tmpl {
		if unicode.Is(unicode.Han, r) || (r >= 0x3000 && r <= 0x303F) || (r >= 0xFF00 && r <= 0xFFEF) {
			t.Errorf("键 %q 规范英文兜底禁止含 CJK 或全角字符: %q", key, tmpl)
			return
		}
	}
	ph, ok := extractPlaceholders(tmpl)
	if !ok {
		t.Errorf("键 %q 兜底模板占位符语法非法: %q", key, tmpl)
		return
	}
	if len(ph) > maxPlaceholders {
		t.Errorf("键 %q 兜底模板占位符数量 %d 超出上限 %d", key, len(ph), maxPlaceholders)
	}
}

func isValidKey(s string) bool {
	if len(s) == 0 || len(s) > maxKeyBytes || s[0] < 'a' || s[0] > 'z' || s[len(s)-1] == '.' {
		return false
	}
	prevDot := false
	for i := range len(s) {
		c := s[i]
		if c == '.' {
			if prevDot {
				return false
			}
			prevDot = true
			continue
		}
		prevDot = false
		if !isAllowedKeyChar(c) {
			return false
		}
	}
	return true
}

func isAllowedKeyChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}

func extractPlaceholders(tmpl string) ([]string, bool) {
	var keys []string
	for i := 0; i < len(tmpl); {
		switch tmpl[i] {
		case '{':
			if i+1 < len(tmpl) && tmpl[i+1] == '{' {
				i += 2
				continue
			}
			k, next, ok := readPlaceholder(tmpl, i+1)
			if !ok {
				return nil, false
			}
			keys = append(keys, k)
			i = next
		case '}':
			if i+1 < len(tmpl) && tmpl[i+1] == '}' {
				i += 2
				continue
			}
			return nil, false
		default:
			i++
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys), true
}

func readPlaceholder(tmpl string, start int) (string, int, bool) {
	end := -1
	for j := start; j < len(tmpl); j++ {
		if tmpl[j] == '{' {
			return "", 0, false
		}
		if tmpl[j] == '}' {
			end = j
			break
		}
	}
	if end < 0 {
		return "", 0, false
	}
	key := tmpl[start:end]
	if !isValidPlaceholderKey(key) {
		return "", 0, false
	}
	return key, end + 1, true
}

func isValidPlaceholderKey(k string) bool {
	if len(k) == 0 || len(k) > 64 {
		return false
	}
	for i := range len(k) {
		c := k[i]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if (i == 0 && !isLetter) || (i > 0 && !isLetter && !isDigit) {
			return false
		}
	}
	return true
}
