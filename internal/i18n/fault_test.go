package i18n

import (
	"errors"
	"io/fs"
	"path"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unicode/utf8"

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

// faultCatalogFS 为自定义纯内存 fs.FS 故障桩，支持注入超长与非 UTF-8 文件名及指定读取错误，
// 用于验证 LoadCatalogFromFS 所有报错路径通过 BoundStr 安全净化文件名且绝不退化为 "<invalid>"。
type faultCatalogFS struct {
	dirs    map[string][]string
	files   map[string][]byte
	readErr map[string]error
}

func (f *faultCatalogFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (f *faultCatalogFS) ReadDir(name string) ([]fs.DirEntry, error) {
	names, ok := f.dirs[name]
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	entries := make([]fs.DirEntry, len(names))
	for i, n := range names {
		entries[i] = faultDirEntry{name: n}
	}
	return entries, nil
}

func (f *faultCatalogFS) ReadFile(name string) ([]byte, error) {
	if err, ok := f.readErr[name]; ok {
		return nil, err
	}
	data, ok := f.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: fs.ErrNotExist}
	}
	return data, nil
}

type faultDirEntry struct{ name string }

func (e faultDirEntry) Name() string               { return e.name }
func (e faultDirEntry) IsDir() bool                { return false }
func (e faultDirEntry) Type() fs.FileMode          { return 0 }
func (e faultDirEntry) Info() (fs.FileInfo, error) { return faultFileInfo(e), nil }

type faultFileInfo struct{ name string }

func (i faultFileInfo) Name() string       { return i.name }
func (i faultFileInfo) Size() int64        { return 0 }
func (i faultFileInfo) Mode() fs.FileMode  { return 0o444 }
func (i faultFileInfo) ModTime() time.Time { return time.Time{} }
func (i faultFileInfo) IsDir() bool        { return false }
func (i faultFileInfo) Sys() any           { return nil }

func TestLoadCatalogFromFS_BoundStrOversizedAndNonUTF8FileNames(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)
	oversizedName := strings.Repeat("a", domi18n.MaxParamStringBytes+128) + ".yaml"
	nonUTF8Name := "bad\xff\xfe.yaml"

	cases := []struct {
		name     string
		fileName string
		data     []byte
		readErr  error
		wantID   domi18n.MessageID
		wantEn   string
		wantZh   string
	}{
		{
			name:     "oversized_read_error",
			fileName: oversizedName,
			readErr:  errors.New("io fault"),
			wantID:   KeyCatalogLoadFailed,
			wantEn:   "i18n: failed to load catalog file locales/en/aaaa",
			wantZh:   "加载国际化词库文件 locales/en/aaaa",
		},
		{
			name:     "oversized_invalid_yaml_syntax",
			fileName: oversizedName,
			data:     []byte(":\n  - [\n"),
			wantID:   KeyCatalogInvalidYAML,
			wantEn:   "i18n: invalid YAML catalog in locales/en/aaaa",
			wantZh:   "国际化词库文件 locales/en/aaaa",
		},
		{
			name:     "oversized_multi_document_yaml",
			fileName: oversizedName,
			data:     []byte("common.not_found: \"a\"\n---\ncommon.timeout: \"b\"\n"),
			wantID:   KeyCatalogInvalidYAML,
			wantEn:   "i18n: invalid YAML catalog in locales/en/aaaa",
			wantZh:   "国际化词库文件 locales/en/aaaa",
		},
		{
			name:     "oversized_non_mapping_root",
			fileName: oversizedName,
			data:     []byte("- item1\n- item2\n"),
			wantID:   KeyCatalogInvalidYAML,
			wantEn:   "i18n: invalid YAML catalog in locales/en/aaaa",
			wantZh:   "国际化词库文件 locales/en/aaaa",
		},
		{
			name:     "oversized_non_string_key",
			fileName: oversizedName,
			data:     []byte("123: \"value\"\n"),
			wantID:   KeyCatalogInvalidYAML,
			wantEn:   "i18n: invalid YAML catalog in locales/en/aaaa",
			wantZh:   "国际化词库文件 locales/en/aaaa",
		},
		{
			name:     "non_utf8_read_error",
			fileName: nonUTF8Name,
			readErr:  errors.New("io fault"),
			wantID:   KeyCatalogLoadFailed,
			wantEn:   "i18n: failed to load catalog file locales/en/bad\uFFFD.yaml",
			wantZh:   "加载国际化词库文件 locales/en/bad\uFFFD.yaml 失败",
		},
		{
			name:     "non_utf8_invalid_yaml",
			fileName: nonUTF8Name,
			data:     []byte("- item1\n"),
			wantID:   KeyCatalogInvalidYAML,
			wantEn:   "i18n: invalid YAML catalog in locales/en/bad\uFFFD.yaml",
			wantZh:   "国际化词库文件 locales/en/bad\uFFFD.yaml 的 YAML 格式无效",
		},
		{
			name:     "non_utf8_non_string_key",
			fileName: nonUTF8Name,
			data:     []byte("123: \"value\"\n"),
			wantID:   KeyCatalogInvalidYAML,
			wantEn:   "i18n: invalid YAML catalog in locales/en/bad\uFFFD.yaml",
			wantZh:   "国际化词库文件 locales/en/bad\uFFFD.yaml 的 YAML 格式无效",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := buildSingleFileFaultFS(tc.fileName, tc.data, tc.readErr)
			cat, err := LoadCatalogFromFS(fsys)
			if err == nil || cat != nil {
				t.Fatalf("预期加载失败, 实际 cat=%v err=%v", cat, err)
			}
			assertBoundedFileError(t, err, tc.wantID, tc.wantEn, tc.wantZh, enLoc, zhLoc)
		})
	}
}

func buildSingleFileFaultFS(fileName string, data []byte, readErr error) *faultCatalogFS {
	fullPath := path.Join("locales/en", fileName)
	fsys := &faultCatalogFS{
		dirs: map[string][]string{
			"locales/en": {fileName},
			"locales/zh": {"common.yaml"},
		},
		files: map[string][]byte{
			"locales/zh/common.yaml": []byte("common.not_found: \"不存在\"\n"),
		},
		readErr: map[string]error{},
	}
	if readErr != nil {
		fsys.readErr[fullPath] = readErr
	} else {
		fsys.files[fullPath] = data
	}
	return fsys
}

func assertBoundedFileError(t *testing.T, err error, wantID domi18n.MessageID, wantEn, wantZh string, enLoc, zhLoc *Localizer) {
	t.Helper()
	if !errors.Is(err, ErrCatalogCorrupt) {
		t.Fatalf("预期包装 ErrCatalogCorrupt, 实际 %v", err)
	}
	if id, ok := domi18n.ErrorID(err); !ok || id != wantID {
		t.Fatalf("ErrorID = (%q, %v), 期望 %q", id, ok, wantID)
	}
	enText := enLoc.RenderError(err)
	if enText != err.Error() {
		t.Fatalf("en RenderError 与 err.Error() 不一致:\nRenderError: %q\nerr.Error(): %q", enText, err.Error())
	}
	zhText := zhLoc.RenderError(err)
	for _, out := range []struct{ label, text, want string }{
		{"en", enText, wantEn},
		{"zh", zhText, wantZh},
	} {
		if !utf8.ValidString(out.text) {
			t.Fatalf("%s 渲染输出包含非法 UTF-8: %q", out.label, out.text)
		}
		if strings.Contains(out.text, "<invalid>") || strings.Contains(out.text, "{file}") {
			t.Fatalf("%s 渲染退化为 <invalid> 或残留占位符: %q", out.label, out.text)
		}
		if !strings.Contains(out.text, out.want) {
			t.Fatalf("%s 渲染缺少期望片段 %q: got=%q", out.label, out.want, out.text)
		}
	}
}
