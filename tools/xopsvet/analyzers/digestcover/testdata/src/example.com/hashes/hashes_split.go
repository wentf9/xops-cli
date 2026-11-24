package hashes

import "io"

// 跨文件定义 ValidPlan.WriteCanonical
func (v ValidPlan) WriteCanonical(w io.Writer) {
	v.EmbeddedBase.WriteCanonical(w)
	_, _ = io.WriteString(w, v.User)
}
