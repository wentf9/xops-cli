package i18n

import (
	"errors"
	"testing"
	"testing/fstest"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"go.yaml.in/yaml/v3"
)

type catalogFaultCase struct {
	name   string
	fsys   fstest.MapFS
	wantID domi18n.MessageID
}

func TestLoadCatalogFromFSFaultInjection(t *testing.T) {
	if _, err := LoadCatalogFromFS(nil); !errors.Is(err, ErrCatalogCorrupt) {
		t.Fatalf("nil fs.FS 应返回 ErrCatalogCorrupt, 实际 %v", err)
	}
	for _, tc := range catalogFaultCases() {
		t.Run(tc.name, func(t *testing.T) {
			assertCatalogFaultCase(t, tc)
		})
	}
}

func assertCatalogFaultCase(t *testing.T, tc catalogFaultCase) {
	t.Helper()
	cat, err := LoadCatalogFromFS(tc.fsys)
	if err == nil || cat != nil {
		t.Fatalf("预期加载失败, 实际 cat=%v err=%v", cat, err)
	}
	if !errors.Is(err, ErrCatalogCorrupt) {
		t.Fatalf("预期匹配 ErrCatalogCorrupt, 实际 %v", err)
	}
	if tc.wantID == domi18n.MessageIDInvalid {
		return
	}
	id, ok := domi18n.ErrorID(err)
	if !ok || id != tc.wantID {
		t.Fatalf("ErrorID = (%q, %v), 期望 %q (err=%v)", id, ok, tc.wantID, err)
	}
}

func catalogFaultCases() []catalogFaultCase {
	const okEn = "common.not_found: \"not found\"\n"
	const okZh = "common.not_found: \"不存在\"\n"
	return []catalogFaultCase{
		{
			name:   "missing_zh_locale",
			fsys:   fstest.MapFS{"locales/en/common.yaml": &fstest.MapFile{Data: []byte(okEn)}},
			wantID: KeyCatalogMissingLocale,
		},
		{
			name: "duplicate_key_same_file",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"a\"\ncommon.not_found: \"b\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogDuplicateKey,
		},
		{
			name: "duplicate_key_cross_file",
			fsys: fstest.MapFS{
				"locales/en/a.yaml":      &fstest.MapFile{Data: []byte(okEn)},
				"locales/en/b.yaml":      &fstest.MapFile{Data: []byte(okEn)},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogDuplicateKey,
		},
		{
			name: "unknown_plural_field",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found:\n  other: \"a\"\n  two: \"b\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogInvalidEntry,
		},
		{
			name: "duplicate_plural_field",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found:\n  other: \"a\"\n  other: \"b\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogInvalidEntry,
		},
		{
			name: "plural_missing_other",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found:\n  one: \"only one\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogInvalidEntry,
		},
		{
			name: "empty_scalar_value",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"   \"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogInvalidEntry,
		},
		{
			name: "null_entry_value",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: null\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogInvalidEntry,
		},
		{
			name: "yaml_alias_entry",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: &base \"a\"\ncommon.timeout: *base\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"a\"\ncommon.timeout: \"b\"\n")},
			},
			wantID: KeyCatalogInvalidEntry,
		},
		{
			name: "non_scalar_entry_value",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found:\n  - a\n  - b\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogInvalidEntry,
		},
		{
			name: "malformed_placeholder",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"missing {host\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogInvalidTemplate,
		},
		{
			name: "plural_placeholder_mismatch",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found:\n  one: \"one host\"\n  other: \"{count} hosts\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"{count} 主机\"\n")},
			},
			wantID: KeyCatalogInvalidEntry,
		},
		{
			name: "cross_locale_placeholder_mismatch",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"missing {host}\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"缺少 {node}\"\n")},
			},
			wantID: KeyCatalogPlaceholderMismatch,
		},
		{
			name: "asymmetric_keys_missing_zh",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"a\"\ncommon.timeout: \"b\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogMissingKey,
		},
		{
			name: "asymmetric_keys_missing_en",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte(okEn)},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"a\"\ncommon.timeout: \"b\"\n")},
			},
			wantID: KeyCatalogMissingKey,
		},
		{
			name: "invalid_message_key",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("BadKey: \"a\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte("BadKey: \"a\"\n")},
			},
			wantID: KeyCatalogInvalidKey,
		},
		{
			name: "multi_document_yaml",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("common.not_found: \"a\"\n---\ncommon.timeout: \"b\"\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogInvalidYAML,
		},
		{
			name: "non_mapping_yaml_root",
			fsys: fstest.MapFS{
				"locales/en/common.yaml": &fstest.MapFile{Data: []byte("- item1\n- item2\n")},
				"locales/zh/common.yaml": &fstest.MapFile{Data: []byte(okZh)},
			},
			wantID: KeyCatalogInvalidYAML,
		},
	}
}

func TestEntryDirectUnmarshalYAML(t *testing.T) {
	var nilEntry *Entry
	if err := nilEntry.UnmarshalYAML(&yaml.Node{}); !errors.Is(err, ErrCatalogCorrupt) || !errors.Is(err, domi18n.ErrNilReceiver) {
		t.Fatalf("nil *Entry.UnmarshalYAML 异常: %v", err)
	}

	var entry Entry
	if err := yaml.Unmarshal([]byte(`"hello {name}"`), &entry); err != nil || entry.Other != "hello {name}" || entry.One != "" {
		t.Fatalf("标量 Entry 解码失败: entry=%+v err=%v", entry, err)
	}
	if err := yaml.Unmarshal([]byte("one: \"{count} host\"\nother: \"{count} hosts\"\n"), &entry); err != nil || entry.One != "{count} host" || entry.Other != "{count} hosts" {
		t.Fatalf("复数 Entry 解码失败: entry=%+v err=%v", entry, err)
	}

	nullSeeded := Entry{Other: "seed"}
	if err := nullSeeded.UnmarshalYAML(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}); !errors.Is(err, ErrCatalogCorrupt) || nullSeeded != (Entry{}) {
		t.Fatalf("!!null 节点应失败并清空接收者: entry=%+v err=%v", nullSeeded, err)
	}

	badDocs := []string{
		"123",
		`""`,
		"other: [a, b]",
		"other: 42",
		"other: \"ok\"\nunknown: \"x\"",
		"one: \"only\"",
		"other: \"bad}\"",
	}
	for _, doc := range badDocs {
		seeded := Entry{Other: "seed"}
		if err := yaml.Unmarshal([]byte(doc), &seeded); err == nil || seeded != (Entry{}) {
			t.Fatalf("非法 Entry YAML(%q) 应失败并清空接收者: entry=%+v err=%v", doc, seeded, err)
		}
	}
}
