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
