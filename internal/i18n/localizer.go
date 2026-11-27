package i18n

import (
	"strconv"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const maxCatalogRenderDepth = 8

// Localizer 绑定到指定 Catalog 与 Locale 的不可变延迟渲染器；零值与 nil 均严格失败关闭：
//   - Render(msg) 回退输出 msg.Canonical()；
//   - RenderError(err) 回退输出 err.Error()；
//   - T(id) / TPlural(id) 失败关闭返回 string(id)。
//
//xops:opaque
//xops:failclosed
type Localizer struct {
	catalog *Catalog
	locale  domi18n.Locale
	valid   bool
}

// DefaultLocalizer 加载内置只读词库并返回英文默认 Localizer（纯内存、零触盘、零包级 var）。
func DefaultLocalizer() (*Localizer, error) {
	cat, err := LoadCatalog()
	if err != nil {
		return nil, err
	}
	return cat.For(domi18n.LocaleEn), nil
}

// IsValid 报告 l 是否为绑定到有效词库与合法语种的可用 Localizer（零值与 nil 恒返回 false）。
func (l *Localizer) IsValid() bool {
	return l != nil && l.valid && l.catalog != nil && l.catalog.IsValid() && l.locale.IsValid()
}

// Locale 返回当前 Localizer 绑定的语种标识；无效 Localizer 返回 LocaleInvalid。
func (l *Localizer) Locale() domi18n.Locale {
	if !l.IsValid() {
		return domi18n.LocaleInvalid
	}
	return l.locale
}

// Catalog 返回当前 Localizer 关联的只读词库指针；无效 Localizer 返回 nil。
func (l *Localizer) Catalog() *Catalog {
	if !l.IsValid() {
		return nil
	}
	return l.catalog
}

// WithLocale 返回共享同一只读词库但切换到新语种的不可变 Localizer；无效接收者或非法语种失败关闭返回无效零值 Localizer。
func (l *Localizer) WithLocale(locale domi18n.Locale) *Localizer {
	if !l.IsValid() {
		return &Localizer{}
	}
	return l.catalog.For(locale)
}

// T 按当前语种渲染指定 MessageID 与参数；零值或无效 Localizer 严格失败关闭返回 string(id)。
func (l *Localizer) T(id domi18n.MessageID, params ...domi18n.Param) string {
	return l.renderByID(id, false, 0, params, 0)
}

// TPlural 按当前语种与复数计数 count 渲染指定 MessageID 与参数；零值或无效 Localizer 严格失败关闭返回 string(id)。
func (l *Localizer) TPlural(id domi18n.MessageID, count int64, params ...domi18n.Param) string {
	return l.renderByID(id, true, count, params, 0)
}

// Render 按当前语种渲染不可变结构化 Message（递归本地化嵌套 ParamKindMessage 参数）。
// 无效 Message 返回空串；零值或无效 Localizer 严格回退 msg.Canonical()。
func (l *Localizer) Render(msg domi18n.Message) string {
	return l.renderMessage(msg, 0)
}

func (l *Localizer) renderByID(id domi18n.MessageID, hasCount bool, count int64, params []domi18n.Param, depth int) string {
	if !id.IsValid() {
		return ""
	}
	if !l.IsValid() {
		return string(id)
	}
	tmpl, ok := l.lookupTemplate(id, hasCount, count)
	if !ok {
		tmpl = fallbackForID(id)
	}
	if tmpl == "" {
		return string(id)
	}
	return l.formatWithParams(tmpl, hasCount, count, params, depth)
}

func (l *Localizer) renderMessage(msg domi18n.Message, depth int) string {
	if !msg.IsValid() {
		return ""
	}
	if !l.IsValid() || depth > maxCatalogRenderDepth {
		return msg.Canonical()
	}
	count, hasCount := msg.Count()
	tmpl, ok := l.lookupTemplate(msg.ID(), hasCount, count)
	if !ok {
		return msg.Canonical()
	}
	return l.formatWithParams(tmpl, hasCount, count, msg.Params(), depth)
}

func (l *Localizer) lookupTemplate(id domi18n.MessageID, hasCount bool, count int64) (string, bool) {
	if !l.IsValid() {
		return "", false
	}
	entry, ok := l.catalog.lookupEntry(l.locale, id)
	if !ok {
		return "", false
	}
	if hasCount && count == 1 && entry.One != "" {
		return entry.One, true
	}
	return entry.Other, true
}

func (l *Localizer) formatWithParams(tmpl string, hasCount bool, count int64, params []domi18n.Param, depth int) string {
	return domi18n.FormatTemplate(tmpl, func(key string) (string, bool) {
		for _, p := range params {
			if p.IsValid() && p.Key() == key {
				return l.formatParamValue(p, depth), true
			}
		}
		if key == "count" && hasCount {
			return strconv.FormatInt(count, 10), true
		}
		return "", false
	})
}

func (l *Localizer) formatParamValue(p domi18n.Param, depth int) string {
	if p.Kind() == domi18n.ParamKindMessage {
		if nested, ok := p.MessageVal(); ok {
			return l.renderMessage(nested, depth+1)
		}
	}
	return p.FormatCanonical()
}
