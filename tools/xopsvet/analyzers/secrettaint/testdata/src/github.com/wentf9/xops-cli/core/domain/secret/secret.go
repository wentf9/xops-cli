package secret

type SecretBox struct {
	raw   []byte
	wiped bool
}

type CleanBoxSlice []*SecretBox

//xops:secretuse
func (b *SecretBox) Use(fn func(plain []byte) error) error {
	if b.wiped {
		return nil
	}
	return fn(b.raw)
}

func (b *SecretBox) IsWiped() bool {
	return b.wiped
}

func WithBytes(raw []byte, fn func(box *SecretBox) error) error {
	cp := append([]byte(nil), raw...)
	clear(raw)
	b := &SecretBox{raw: cp}
	defer func() {
		clear(b.raw)
		b.wiped = true
	}()
	return fn(b)
}

// CrossPkgCallbackOnly 仅回调槽 0 标注 //xops:secretuse，槽 1 extra 不受直接机密审计覆盖。
func CrossPkgCallbackOnly(
	//xops:secretuse
	onSec func(plain []byte) error,
	extra []byte,
) error {
	_ = extra
	return onSec(nil)
}

// CrossPkgPartialDirect 仅槽 1 标注 //xops:secretuse，槽 0 unmarked 不受直接机密审计覆盖。
func CrossPkgPartialDirect(
	unmarked []byte,
	//xops:secretuse
	sec []byte,
) error {
	_ = unmarked
	_ = sec
	return nil
}

// CrossPkgWholeDirect 声明级 //xops:secretuse 覆盖全部明文形参，可合法充当跨包双参回调。
//
//xops:secretuse
func CrossPkgWholeDirect(a, b []byte) error {
	_ = a
	_ = b
	return nil
}
