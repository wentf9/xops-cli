package crosspkg

import "example.com/sentinelpkg"

func mutateCrossPkgSentinel() {
	sentinelpkg.ErrShared = nil // want "禁止在运行期修改哨兵错误 ErrShared"
	p := &sentinelpkg.ErrShared // want "禁止对哨兵错误 ErrShared 取地址"
	_ = p

	for _, sentinelpkg.ErrShared = range []error{nil} { // want "禁止在运行期修改哨兵错误 ErrShared"
	}

	var h sentinelpkg.FieldHolder
	h.ErrField = nil
	_ = &h.ErrField
}

func callIndirectContextValue() any {
	c := sentinelpkg.NewOverriding()
	return c.Value("k") // want "禁止调用 ctx.Value"
}
