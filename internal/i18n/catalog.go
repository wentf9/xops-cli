package i18n

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"go.yaml.in/yaml/v3"
)

const (
	maxCatalogKeyBytes   = 128
	yamlStringTag        = "!!str"
	localeDirPrefix      = "locales"
	catalogFileExtension = ".yaml"
)

// Entry 表示双语词库中的单条不可变消息模板记录。
// 支持标量字符串简写（仅填充 Other）与复数映射（{one: "...", other: "..."}）。
type Entry struct {
	Other string
	One   string
}

// UnmarshalYAML 实现严格确定性的 yaml.Node 解码：
//   - 同时接受非空字符串标量与仅含 one/other 字段的复数映射；
//   - 手工遍历 MappingNode.Content，确定性拦截重复字段、未知字段、空值、非标量节点、YAML 别名与非法占位符语法；
//   - 解码失败时重置接收者为零值并严格返回包装 ErrCatalogCorrupt 的结构化错误。
func (e *Entry) UnmarshalYAML(value *yaml.Node) error {
	if e == nil {
		return WrapS(ErrCatalogCorrupt, domi18n.ErrNilReceiver, domi18n.KeyNilReceiver)
	}
	*e = Entry{}
	if value == nil {
		return EF(ErrCatalogCorrupt, KeyCatalogInvalidEntryNode)
	}
	switch value.Kind {
	case yaml.ScalarNode:
		return e.unmarshalScalar(value)
	case yaml.MappingNode:
		return e.unmarshalPluralMapping(value)
	default:
		return EF(ErrCatalogCorrupt, KeyCatalogInvalidEntryNode)
	}
}

func (e *Entry) unmarshalScalar(value *yaml.Node) error {
	if value.ShortTag() != yamlStringTag {
		return EF(ErrCatalogCorrupt, KeyCatalogInvalidEntryNode)
	}
	if strings.TrimSpace(value.Value) == "" {
		return EF(ErrCatalogCorrupt, KeyCatalogEmptyEntry)
	}
	if _, err := domi18n.ExtractPlaceholders(value.Value); err != nil {
		return WrapS(ErrCatalogCorrupt, err, KeyCatalogInvalidEntryNode)
	}
	e.Other = value.Value
	return nil
}

func (e *Entry) unmarshalPluralMapping(value *yaml.Node) error {
	if len(value.Content) == 0 || len(value.Content)%2 != 0 {
		return EF(ErrCatalogCorrupt, KeyCatalogInvalidEntryNode)
	}
	var parsed Entry
	var seenOne, seenOther bool
	for i := 0; i < len(value.Content); i += 2 {
		if err := applyPluralField(value.Content[i], value.Content[i+1], &parsed, &seenOne, &seenOther); err != nil {
			return err
		}
	}
	if !seenOther {
		return EF(ErrCatalogCorrupt, KeyCatalogMissingOther)
	}
	if err := validateEntryPlaceholders(parsed, seenOne); err != nil {
		return err
	}
	*e = parsed
	return nil
}

func applyPluralField(kNode, vNode *yaml.Node, dst *Entry, seenOne, seenOther *bool) error {
	if kNode == nil || kNode.Kind != yaml.ScalarNode || kNode.ShortTag() != yamlStringTag {
		return EF(ErrCatalogCorrupt, KeyCatalogInvalidEntryNode)
	}
	field := kNode.Value
	switch field {
	case "one":
		return assignPluralValue("one", vNode, &dst.One, seenOne)
	case "other":
		return assignPluralValue("other", vNode, &dst.Other, seenOther)
	default:
		return EF(ErrCatalogCorrupt, KeyCatalogUnknownField, domi18n.Str("field", boundDisplayText(field, domi18n.MaxParamKeyBytes)))
	}
}

func assignPluralValue(field string, vNode *yaml.Node, target *string, seen *bool) error {
	if *seen {
		return EF(ErrCatalogCorrupt, KeyCatalogDuplicateField, domi18n.Str("field", field))
	}
	if vNode == nil || vNode.Kind != yaml.ScalarNode || vNode.ShortTag() != yamlStringTag || strings.TrimSpace(vNode.Value) == "" {
		return EF(ErrCatalogCorrupt, KeyCatalogNonScalarField, domi18n.Str("field", field))
	}
	*seen = true
	*target = vNode.Value
	return nil
}

func validateEntryPlaceholders(entry Entry, hasOne bool) error {
	otherPH, err := domi18n.ExtractPlaceholders(entry.Other)
	if err != nil {
		return WrapS(ErrCatalogCorrupt, err, KeyCatalogInvalidEntryNode)
	}
	if !hasOne {
		return nil
	}
	onePH, err := domi18n.ExtractPlaceholders(entry.One)
	if err != nil {
		return WrapS(ErrCatalogCorrupt, err, KeyCatalogInvalidEntryNode)
	}
	if !slices.Equal(otherPH, onePH) {
		return EF(ErrCatalogCorrupt, KeyCatalogPluralPlaceholderMismatch)
	}
	return nil
}

// Catalog 持有已通过完整性、对称性与模板语法校验的不可变多语种词库只读快照；
// 零值恒无效并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Catalog struct {
	entries map[domi18n.Locale]map[string]Entry
	valid   bool
}

// LoadCatalog 从内置只读 embed.FS 加载并校验完整的双语词库（纯内存、零触盘、零全局状态）。
// 除校验 YAML 格式、占位符语法与英中对称性外，还会确认 CoreKeys() 与 RootKeys() 100% 存在。
func LoadCatalog() (*Catalog, error) {
	cat, err := LoadCatalogFromFS(localeFiles)
	if err != nil {
		return nil, err
	}
	if err := validateRegisteredKeys(cat); err != nil {
		return nil, err
	}
	return cat, nil
}

// LoadCatalogFromFS 从任意 fs.FS（如内置 embed.FS 或测试用 fstest.MapFS）加载并校验双语词库。
// 确定性拦截缺失语种目录、非映射文档、多文档尾随内容、非法键名、文件内/跨文件重复键、
// 未知字段、空值、非法模板以及英中词条或占位符不对称问题。
func LoadCatalogFromFS(fsys fs.FS) (*Catalog, error) {
	if fsys == nil {
		return nil, EF(ErrCatalogCorrupt, domi18n.KeyCommonInvalidArgument)
	}
	locales := []domi18n.Locale{domi18n.LocaleEn, domi18n.LocaleZh}
	tables := make(map[domi18n.Locale]map[string]Entry, len(locales))
	for _, loc := range locales {
		table, err := loadLocaleDir(fsys, loc)
		if err != nil {
			return nil, err
		}
		tables[loc] = table
	}
	if err := validateLocaleSymmetry(tables[domi18n.LocaleEn], tables[domi18n.LocaleZh]); err != nil {
		return nil, err
	}
	return &Catalog{entries: tables, valid: true}, nil
}

// IsValid 报告 c 是否为已通过完整校验的有效只读词库实例（零值与 nil 恒返回 false）。
func (c *Catalog) IsValid() bool {
	return c != nil && c.valid && len(c.entries) > 0
}

// For 返回绑定到指定语种 locale 的不可变 Localizer；若词库无效或 locale 不受支持则失败关闭返回无效零值 Localizer。
func (c *Catalog) For(locale domi18n.Locale) *Localizer {
	if !c.IsValid() || !locale.IsValid() {
		return &Localizer{}
	}
	if _, ok := c.entries[locale]; !ok {
		return &Localizer{}
	}
	return &Localizer{catalog: c, locale: locale, valid: true}
}

func (c *Catalog) lookupEntry(locale domi18n.Locale, id domi18n.MessageID) (Entry, bool) {
	if !c.IsValid() || !locale.IsValid() || !id.IsValid() {
		return Entry{}, false
	}
	table, ok := c.entries[locale]
	if !ok {
		return Entry{}, false
	}
	entry, found := table[string(id)]
	return entry, found
}

func loadLocaleDir(fsys fs.FS, loc domi18n.Locale) (map[string]Entry, error) {
	dir := path.Join(localeDirPrefix, loc.String())
	dirEntries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, WrapS(ErrCatalogCorrupt, err, KeyCatalogMissingLocale, domi18n.Str("locale", loc.String()))
	}
	var yamlFiles []string
	for _, de := range dirEntries {
		if !de.IsDir() && path.Ext(de.Name()) == catalogFileExtension {
			yamlFiles = append(yamlFiles, de.Name())
		}
	}
	if len(yamlFiles) == 0 {
		return nil, EF(ErrCatalogCorrupt, KeyCatalogMissingLocale, domi18n.Str("locale", loc.String()))
	}
	slices.Sort(yamlFiles)
	table := make(map[string]Entry)
	for _, name := range yamlFiles {
		filePath := path.Join(dir, name)
		data, readErr := fs.ReadFile(fsys, filePath)
		if readErr != nil {
			return nil, WrapS(ErrCatalogCorrupt, readErr, KeyCatalogLoadFailed, domi18n.Str("file", filePath))
		}
		if parseErr := parseCatalogFile(loc, filePath, data, table); parseErr != nil {
			return nil, parseErr
		}
	}
	if len(table) == 0 {
		return nil, EF(ErrCatalogCorrupt, KeyCatalogMissingLocale, domi18n.Str("locale", loc.String()))
	}
	return table, nil
}

func parseCatalogFile(loc domi18n.Locale, filePath string, data []byte, dst map[string]Entry) error {
	root, err := decodeSingleMappingRoot(filePath, data)
	if err != nil {
		return err
	}
	for i := 0; i < len(root.Content); i += 2 {
		if err := parseCatalogPair(loc, filePath, root.Content[i], root.Content[i+1], dst); err != nil {
			return err
		}
	}
	return nil
}

func decodeSingleMappingRoot(filePath string, data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, WrapS(ErrCatalogCorrupt, err, KeyCatalogInvalidYAML, domi18n.Str("file", filePath))
	}
	var trailing yaml.Node
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, EF(ErrCatalogCorrupt, KeyCatalogInvalidYAML, domi18n.Str("file", filePath))
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, EF(ErrCatalogCorrupt, KeyCatalogInvalidYAML, domi18n.Str("file", filePath))
	}
	root := doc.Content[0]
	if root == nil || root.Kind != yaml.MappingNode || len(root.Content)%2 != 0 {
		return nil, EF(ErrCatalogCorrupt, KeyCatalogInvalidYAML, domi18n.Str("file", filePath))
	}
	return root, nil
}

func parseCatalogPair(loc domi18n.Locale, filePath string, kNode, vNode *yaml.Node, dst map[string]Entry) error {
	if kNode == nil || kNode.Kind != yaml.ScalarNode || kNode.ShortTag() != yamlStringTag {
		return EF(ErrCatalogCorrupt, KeyCatalogInvalidYAML, domi18n.Str("file", filePath))
	}
	rawKey := kNode.Value
	if !isValidCatalogKey(rawKey) {
		return EF(ErrCatalogCorrupt, KeyCatalogInvalidKey,
			domi18n.Str("key", boundDisplayText(rawKey, maxCatalogKeyBytes)),
			domi18n.Str("file", filePath),
		)
	}
	if _, exists := dst[rawKey]; exists {
		return EF(ErrCatalogCorrupt, KeyCatalogDuplicateKey,
			domi18n.Str("key", rawKey),
			domi18n.Str("locale", loc.String()),
		)
	}
	var entry Entry
	if err := entry.UnmarshalYAML(vNode); err != nil {
		if errors.Is(err, domi18n.ErrInvalidTemplate) {
			return WrapS(ErrCatalogCorrupt, err, KeyCatalogInvalidTemplate, domi18n.Str("key", rawKey))
		}
		return WrapS(ErrCatalogCorrupt, err, KeyCatalogInvalidEntry, domi18n.Str("key", rawKey))
	}
	dst[rawKey] = entry
	return nil
}

func validateLocaleSymmetry(enTable, zhTable map[string]Entry) error {
	for _, key := range sortedMapKeys(enTable) {
		zhEntry, ok := zhTable[key]
		if !ok {
			return EF(ErrCatalogCorrupt, KeyCatalogMissingKey,
				domi18n.Str("key", key),
				domi18n.Str("locale", domi18n.LocaleZh.String()),
			)
		}
		if err := validatePairPlaceholders(key, enTable[key], zhEntry); err != nil {
			return err
		}
	}
	for _, key := range sortedMapKeys(zhTable) {
		if _, ok := enTable[key]; !ok {
			return EF(ErrCatalogCorrupt, KeyCatalogMissingKey,
				domi18n.Str("key", key),
				domi18n.Str("locale", domi18n.LocaleEn.String()),
			)
		}
	}
	return nil
}

func validatePairPlaceholders(key string, enEntry, zhEntry Entry) error {
	enPH, err := domi18n.ExtractPlaceholders(enEntry.Other)
	if err != nil {
		return WrapS(ErrCatalogCorrupt, err, KeyCatalogInvalidTemplate, domi18n.Str("key", key))
	}
	zhPH, err := domi18n.ExtractPlaceholders(zhEntry.Other)
	if err != nil {
		return WrapS(ErrCatalogCorrupt, err, KeyCatalogInvalidTemplate, domi18n.Str("key", key))
	}
	if !slices.Equal(enPH, zhPH) {
		return EF(ErrCatalogCorrupt, KeyCatalogPlaceholderMismatch, domi18n.Str("key", key))
	}
	return nil
}

func validateRegisteredKeys(cat *Catalog) error {
	enTable := cat.entries[domi18n.LocaleEn]
	for _, id := range domi18n.CoreKeys() {
		if _, ok := enTable[string(id)]; !ok {
			return EF(ErrCatalogCorrupt, KeyCatalogMissingKey,
				domi18n.Str("key", string(id)),
				domi18n.Str("locale", domi18n.LocaleEn.String()),
			)
		}
	}
	for _, id := range RootKeys() {
		if _, ok := enTable[string(id)]; !ok {
			return EF(ErrCatalogCorrupt, KeyCatalogMissingKey,
				domi18n.Str("key", string(id)),
				domi18n.Str("locale", domi18n.LocaleEn.String()),
			)
		}
	}
	return nil
}

func sortedMapKeys(m map[string]Entry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// isValidCatalogKey 校验 YAML 键名符合 [a-z][a-z0-9_.]* 规范（不构造运行时 MessageID，遵守 i18nguard 规则 1）。
func isValidCatalogKey(s string) bool {
	if len(s) == 0 || len(s) > maxCatalogKeyBytes || s[0] < 'a' || s[0] > 'z' || s[len(s)-1] == '.' {
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

// boundDisplayText 将异常输入安全裁剪为有效 UTF-8 有界字符串，用于构造内部诊断错误参数。
func boundDisplayText(raw string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if !utf8.ValidString(raw) {
		raw = strconv.Quote(raw)
	}
	if len(raw) <= maxBytes {
		return raw
	}
	end := 0
	for idx := range raw {
		if idx > maxBytes {
			break
		}
		end = idx
	}
	return raw[:end]
}
