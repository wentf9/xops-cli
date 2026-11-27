package rootcatalog_test

import (
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/internal/i18n/internal/rootcatalog"
)

const (
	maxKeyBytes      = 128
	maxParamKeyBytes = 64
	maxTemplateBytes = 4096
	maxPlaceholders  = 16
)

func TestCatalogInvariants(t *testing.T) {
	allKeys := rootcatalog.AllKeys()
	errKeys := rootcatalog.ErrorKeys()
	if len(allKeys) == 0 || len(errKeys) == 0 {
		t.Fatalf("AllKeys(%d) 与 ErrorKeys(%d) 均不得为空", len(allKeys), len(errKeys))
	}
	if !slices.IsSorted(allKeys) {
		t.Fatal("AllKeys() 必须按字典序严格升序排列")
	}
	if !slices.IsSorted(errKeys) {
		t.Fatal("ErrorKeys() 必须按字典序严格升序排列")
	}

	allSet := collectValidUniqueKeys(t, "AllKeys()", allKeys)
	errSet := collectValidUniqueKeys(t, "ErrorKeys()", errKeys)

	for _, k := range errKeys {
		if !allSet[k] {
			t.Errorf("ErrorKeys() 包含未在 AllKeys() 登记的键 %q", k)
		}
		assertValidFallbackTemplate(t, k, rootcatalog.Lookup(k))
	}
	for _, k := range allKeys {
		if errSet[k] {
			continue
		}
		if fb := rootcatalog.Lookup(k); fb != "" {
			t.Errorf("非错误展示类键 %q 不应在 Lookup 中登记影子兜底: %q", k, fb)
		}
	}
}

func collectValidUniqueKeys(t *testing.T, label string, keys []string) map[string]bool {
	t.Helper()
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if !isValidKey(k) {
			t.Errorf("%s 包含非法根模块键名: %q", label, k)
		}
		if seen[k] {
			t.Errorf("%s 包含重复键: %q", label, k)
		}
		seen[k] = true
	}
	return seen
}

func TestLookupUnknownAndDefensiveCopies(t *testing.T) {
	for _, bad := range []string{"", "unknown.key", "common.not_found", "cli.help.root", "UPPER.case"} {
		if got := rootcatalog.Lookup(bad); got != "" {
			t.Fatalf("Lookup(%q) = %q, 期望空串", bad, got)
		}
	}

	all1 := rootcatalog.AllKeys()
	origAll := all1[0]
	all1[0] = "mutated.all.key"
	if all2 := rootcatalog.AllKeys(); all2[0] != origAll {
		t.Fatalf("AllKeys() 必须返回独立副本: got=%q want=%q", all2[0], origAll)
	}

	err1 := rootcatalog.ErrorKeys()
	origErr := err1[0]
	err1[0] = "mutated.err.key"
	if err2 := rootcatalog.ErrorKeys(); err2[0] != origErr {
		t.Fatalf("ErrorKeys() 必须返回独立副本: got=%q want=%q", err2[0], origErr)
	}
}

func TestRepresentativeFallbacksUnchanged(t *testing.T) {
	cases := map[string]string{
		"i18n.catalog.corrupt":               "i18n: catalog data is corrupt",
		"std.context.canceled":               "context canceled",
		"conc.panic_value":                   "conc: supervised goroutine panicked: {value}",
		"cli.err.usage":                      "cli: invalid command-line arguments",
		"cmd.comp.offline_aead_vault":        "offline_aead vault {name}",
		"host.audit.corrupt_log":             "audit: audit log record is corrupt or malformed",
		"host.vault.kdf_params_invalid":      "Argon2id parameters out of range (t={time}, m={memory_kib} KiB, p={threads})",
		"sftpshell.err.unknown_option":       "{cmd}: unknown option {option}",
		"mcpcmd.err.invalid_transport_value": "unsupported transport {value} (only stdio or http is supported)",
		"muxdaemon.err.stop_master_failed":   "stop control master {socket} failed",
		"tui.err.config_nil_op_stream":       "OperationStreams[{index}] must not be nil",
		"interact.vault.init.title":          "Vault init",
	}
	for k, want := range cases {
		if got := rootcatalog.Lookup(k); got != want {
			t.Errorf("键 %q 规范英文兜底发生漂移: got=%q want=%q", k, got, want)
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
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
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

// isValidPlaceholderKey 与生产 core/domain/i18n.isValidParamKey 对齐：
// 首字符为 [a-zA-Z0-9_]，后续字符允许 [a-zA-Z0-9_.-]。
func isValidPlaceholderKey(k string) bool {
	if len(k) == 0 || len(k) > maxParamKeyBytes {
		return false
	}
	for i := range len(k) {
		c := k[i]
		isBase := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
		isSep := i > 0 && (c == '.' || c == '-')
		if !isBase && !isSep {
			return false
		}
	}
	return true
}
