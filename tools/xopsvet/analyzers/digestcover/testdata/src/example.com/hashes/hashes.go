package hashes

import (
	"io"
	"reflect"

	"example.com/extbase"
)

type EmbeddedBase struct {
	Host string
	Port int
}

func (b EmbeddedBase) WriteCanonical(w io.Writer) {
	_, _ = io.WriteString(w, b.Host)
	_ = b.Port
}

// 合法：全字段覆盖（含跨文件 WriteCanonical、嵌入直接访问、合法 hash-exclude、空白字段 _）
//xops:canonicalhash
type ValidPlan struct {
	EmbeddedBase
	User  string
	_     int
	Cache string //xops:hash-exclude: ephemeral cache key
}

// 合法：通过提升字段全部覆盖嵌入体 + 同包辅助函数递归 + 接收者别名
//xops:canonicalhash
type PromotedAndHelperPlan struct {
	EmbeddedBase
	Token string
}

func (p *PromotedAndHelperPlan) WriteCanonical(w io.Writer) {
	alias := p
	writePromoted(w, alias)
	alias.writeToken(w)
}

func writePromoted(w io.Writer, p *PromotedAndHelperPlan) {
	_, _ = io.WriteString(w, p.Host)
	if p.Port > 0 {
		_, _ = io.WriteString(w, "port")
	}
}

func (p *PromotedAndHelperPlan) writeToken(w io.Writer) {
	_, _ = io.WriteString(w, p.Token)
}

// 合法：泛型 //xops:canonicalhash 结构体 + 泛型辅助方法
//xops:canonicalhash
type GenericBox[T any] struct {
	Head string
	Body T
}

func (g *GenericBox[T]) WriteCanonical(w io.Writer) {
	_, _ = io.WriteString(w, g.Head)
	g.writeBody(w)
}

func (g *GenericBox[T]) writeBody(w io.Writer) {
	_, _ = w.Write(nil)
	_ = []any{g.Body}
}

// 非法：标注在非结构体上
//xops:canonicalhash
type NotAStruct int // want "digestcover: //xops:canonicalhash 仅适用于结构体类型"

// 非法：缺少 WriteCanonical 方法
//xops:canonicalhash
type MissingMethod struct { // want "digestcover: 标记 //xops:canonicalhash 的结构体 MissingMethod 缺少 WriteCanonical 方法"
	Name string
}

// 非法：hash-exclude 理由为空（即使在非 canonicalhash 结构体上也拦截）
type EmptyExcludeOnPlain struct {
	Tmp string /* xops:hash-exclude: */ // want "digestcover: //xops:hash-exclude 必须提供非空排除理由"
}

// 非法：遗漏字段 + _ = h.Field 空弃反绕过 + 读取同名其他变量 other.Field + LHS 写入
//xops:canonicalhash
type BypassAttempts struct {
	Real    string
	Discard string
	Other   string
	Written string
	EmptyEx string /* xops:hash-exclude */ // want "digestcover: //xops:hash-exclude 必须提供非空排除理由"
}

func (b *BypassAttempts) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 BypassAttempts 的 WriteCanonical 未覆盖字段 Discard" "digestcover: 结构体 BypassAttempts 的 WriteCanonical 未覆盖字段 Other" "digestcover: 结构体 BypassAttempts 的 WriteCanonical 未覆盖字段 Written" "digestcover: 结构体 BypassAttempts 的 WriteCanonical 未覆盖字段 EmptyEx"
	_, _ = io.WriteString(w, b.Real)
	_ = b.Discard
	other := BypassAttempts{}
	_, _ = io.WriteString(w, other.Other)
	b.Written = "x"
}

// 非法：部分提升字段（覆盖 Host 但漏掉 Port）
//xops:canonicalhash
type PartialPromoted struct {
	EmbeddedBase
}

func (p PartialPromoted) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 PartialPromoted 的 WriteCanonical 未覆盖字段 EmbeddedBase"
	_, _ = io.WriteString(w, p.Host)
}

// 非法：WriteCanonical 内使用 reflect
//xops:canonicalhash
type UsesReflect struct {
	Name string
}

func (u UsesReflect) WriteCanonical(w io.Writer) {
	_ = reflect.ValueOf(u.Name) // want "digestcover: WriteCanonical 禁止使用 reflect"
}

// 非法：跨包嵌入含未导出字段时仅访问提升导出字段不够，必须直接访问嵌入体自身
//xops:canonicalhash
type ExtPromotedInsufficient struct {
	extbase.ExtBase
}

func (e ExtPromotedInsufficient) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 ExtPromotedInsufficient 的 WriteCanonical 未覆盖字段 ExtBase"
	_, _ = io.WriteString(w, e.Public)
}

// 合法：跨包嵌入直接调用嵌入体 WriteCanonical
//xops:canonicalhash
type ExtDirectValid struct {
	extbase.ExtBase
}

func (e ExtDirectValid) WriteCanonical(w io.Writer) {
	e.ExtBase.WriteCanonical(w)
}

// Challenge 4: var _ = h.A、_ = &h.B、var _ = &h.C、h.D++、h.E--、h.F += 1 均不得计入覆盖
//xops:canonicalhash
type BypassDiscardForms struct {
	A string
	B string
	C string
	D int
	E int
	F int
}

func (h *BypassDiscardForms) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 BypassDiscardForms 的 WriteCanonical 未覆盖字段 A" "digestcover: 结构体 BypassDiscardForms 的 WriteCanonical 未覆盖字段 B" "digestcover: 结构体 BypassDiscardForms 的 WriteCanonical 未覆盖字段 C" "digestcover: 结构体 BypassDiscardForms 的 WriteCanonical 未覆盖字段 D" "digestcover: 结构体 BypassDiscardForms 的 WriteCanonical 未覆盖字段 E" "digestcover: 结构体 BypassDiscardForms 的 WriteCanonical 未覆盖字段 F"
	var _ = h.A
	_ = &h.B
	var _ = &h.C
	h.D++
	h.E--
	h.F += 1
}

// Challenge 5: 泛型结构体嵌入泛型结构体并通过提升字段全部编码
type GenBase[T any] struct {
	SubVal T
}

//xops:canonicalhash
type GenEmbedPromoted[T any] struct {
	GenBase[T]
	Own string
}

func (g *GenEmbedPromoted[T]) WriteCanonical(w io.Writer) {
	_, _ = io.WriteString(w, g.Own)
	_ = []any{g.SubVal}
}

// Challenge 9: 非接收者值传递辅助函数中调用 reflect 同样拦截
func reflectHelperVal(v string) {
	_ = reflect.TypeOf(v) // want "digestcover: WriteCanonical 禁止使用 reflect"
}

//xops:canonicalhash
type UsesReflectViaValHelper struct {
	A string
}

func (h *UsesReflectViaValHelper) WriteCanonical(w io.Writer) {
	reflectHelperVal(h.A)
	_, _ = io.WriteString(w, h.A)
}

// Unchallenged: >=2 跳多层结构体嵌入（Outer -> Middle -> Inner）
type InnerLeaf struct {
	LeafA string
	LeafB int
}

type MiddleLayer struct {
	InnerLeaf
	MidField string
}

//xops:canonicalhash
type OuterPromotedValid struct {
	MiddleLayer
	OwnField string
}

func (o *OuterPromotedValid) WriteCanonical(w io.Writer) {
	_, _ = io.WriteString(w, o.LeafA)
	if o.LeafB > 0 {
		_, _ = io.WriteString(w, "b")
	}
	_, _ = io.WriteString(w, o.MidField)
	_, _ = io.WriteString(w, o.OwnField)
}

//xops:canonicalhash
type OuterPromotedMissingLeaf struct {
	MiddleLayer
	OwnField string
}

func (o *OuterPromotedMissingLeaf) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 OuterPromotedMissingLeaf 的 WriteCanonical 未覆盖字段 MiddleLayer"
	_, _ = io.WriteString(w, o.LeafA)
	_, _ = io.WriteString(w, o.MidField)
	_, _ = io.WriteString(w, o.OwnField)
}

type MiddleWithExt struct {
	extbase.ExtBase
	MidField string
}

//xops:canonicalhash
type OuterWithExtInvalid struct {
	MiddleWithExt
	OwnField string
}

func (o *OuterWithExtInvalid) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 OuterWithExtInvalid 的 WriteCanonical 未覆盖字段 MiddleWithExt"
	_, _ = io.WriteString(w, o.Public)
	_, _ = io.WriteString(w, o.MidField)
	_, _ = io.WriteString(w, o.OwnField)
}

//xops:canonicalhash
type OuterWithExtValid struct {
	MiddleWithExt
	OwnField string
}

func (o *OuterWithExtValid) WriteCanonical(w io.Writer) {
	o.ExtBase.WriteCanonical(w)
	_, _ = io.WriteString(w, o.MidField)
	_, _ = io.WriteString(w, o.OwnField)
}

func (i InnerLeaf) WriteCanonical(w io.Writer) {
	_, _ = io.WriteString(w, i.LeafA)
	if i.LeafB > 0 {
		_, _ = io.WriteString(w, "b")
	}
}

//xops:canonicalhash
type OuterDirectInnerValid struct {
	MiddleLayer
	OwnField string
}

func (o *OuterDirectInnerValid) WriteCanonical(w io.Writer) {
	o.InnerLeaf.WriteCanonical(w)
	_, _ = io.WriteString(w, o.MidField)
	_, _ = io.WriteString(w, o.OwnField)
}

// Challenger 2 - Challenge 3: o.Middle.LeafA 等显式子字段选择不得将整个嵌入体标记为已覆盖。
//xops:canonicalhash
type OuterDirectMiddleBypass struct {
	MiddleLayer
	OwnField string
}

func (o *OuterDirectMiddleBypass) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 OuterDirectMiddleBypass 的 WriteCanonical 未覆盖字段 MiddleLayer"
	_, _ = io.WriteString(w, o.MiddleLayer.LeafA)
	_, _ = io.WriteString(w, o.OwnField)
}

//xops:canonicalhash
type OuterDirectInnerFieldBypass struct {
	MiddleLayer
	OwnField string
}

func (o *OuterDirectInnerFieldBypass) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 OuterDirectInnerFieldBypass 的 WriteCanonical 未覆盖字段 MiddleLayer"
	_, _ = io.WriteString(w, o.MiddleLayer.InnerLeaf.LeafA)
	_, _ = io.WriteString(w, o.MiddleLayer.MidField)
	_, _ = io.WriteString(w, o.OwnField)
}

//xops:canonicalhash
type OuterPromotedInnerFieldBypass struct {
	MiddleLayer
	OwnField string
}

func (o *OuterPromotedInnerFieldBypass) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 OuterPromotedInnerFieldBypass 的 WriteCanonical 未覆盖字段 MiddleLayer"
	_, _ = io.WriteString(w, o.InnerLeaf.LeafA)
	_, _ = io.WriteString(w, o.MidField)
	_, _ = io.WriteString(w, o.OwnField)
}

//xops:canonicalhash
type OuterDirectMiddleAllFieldsValid struct {
	MiddleLayer
	OwnField string
}

func (o *OuterDirectMiddleAllFieldsValid) WriteCanonical(w io.Writer) {
	_, _ = io.WriteString(w, o.MiddleLayer.MidField)
	_, _ = io.WriteString(w, o.MiddleLayer.LeafA)
	if o.MiddleLayer.LeafB > 0 {
		_, _ = io.WriteString(w, "b")
	}
	_, _ = io.WriteString(w, o.OwnField)
}

func (m MiddleLayer) WriteCanonical(w io.Writer) {
	m.InnerLeaf.WriteCanonical(w)
	_, _ = io.WriteString(w, m.MidField)
}

//xops:canonicalhash
type OuterDirectMiddleMethodValid struct {
	MiddleLayer
	OwnField string
}

func (o *OuterDirectMiddleMethodValid) WriteCanonical(w io.Writer) {
	o.MiddleLayer.WriteCanonical(w)
	_, _ = io.WriteString(w, o.OwnField)
}

func encodeMiddleLayer(w io.Writer, m MiddleLayer) {
	m.WriteCanonical(w)
}

//xops:canonicalhash
type OuterDirectMiddleValueValid struct {
	MiddleLayer
	OwnField string
}

func (o *OuterDirectMiddleValueValid) WriteCanonical(w io.Writer) {
	encodeMiddleLayer(w, o.MiddleLayer)
	_, _ = io.WriteString(w, o.OwnField)
}

//xops:canonicalhash
type OuterExtDirectFieldBypass struct {
	MiddleWithExt
	OwnField string
}

func (o *OuterExtDirectFieldBypass) WriteCanonical(w io.Writer) { // want "digestcover: 结构体 OuterExtDirectFieldBypass 的 WriteCanonical 未覆盖字段 MiddleWithExt"
	_, _ = io.WriteString(w, o.MiddleWithExt.Public)
	_, _ = io.WriteString(w, o.MiddleWithExt.MidField)
	_, _ = io.WriteString(w, o.OwnField)
}
