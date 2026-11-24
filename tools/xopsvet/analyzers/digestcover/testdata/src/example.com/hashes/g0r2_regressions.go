package hashes

import (
	"io"
	"reflect"
)

//xops:canonicalhash
type ReassignAliasPlan struct {
	Host string
	Port int
}

// WriteCanonical 故意重赋 alias 指向伪造零值后再条件覆盖为 p，必须拦截（H7）。
func (p *ReassignAliasPlan) WriteCanonical(w io.Writer) { // want "WriteCanonical 未覆盖字段 Host" "WriteCanonical 未覆盖字段 Port"
	alias := &ReassignAliasPlan{}
	_, _ = io.WriteString(w, alias.Host)
	_ = alias.Port
	if w == nil {
		alias = p
	}
	_ = alias
}

//xops:canonicalhash
type IndirectReflectPlan struct {
	Name string
}

func indirectReflectHelper(v any) {
	_ = reflect.ValueOf(v) // want "WriteCanonical 禁止使用 reflect"
}

func (p *IndirectReflectPlan) WriteCanonical(w io.Writer) {
	_, _ = io.WriteString(w, p.Name)
	fn := indirectReflectHelper
	fn(p)
}

//xops:canonicalhash
type MethodExprPlan struct {
	A string
	B string
}

func (p *MethodExprPlan) writeB(w io.Writer) {
	_, _ = io.WriteString(w, p.B)
}

// WriteCanonical 验证通过方法表达式 (*MethodExprPlan).writeB(p, w) 覆盖字段 B 合法通过（M9）。
func (p *MethodExprPlan) WriteCanonical(w io.Writer) {
	_, _ = io.WriteString(w, p.A)
	(*MethodExprPlan).writeB(p, w)
}
