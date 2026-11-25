package secret

type SecretBox struct {
	raw   []byte
	valid bool
	wiped bool
}

//xops:syncclosure
//xops:borrowed
func WithBytes(raw []byte, fn func(box *SecretBox) error) error {
	cp := append([]byte(nil), raw...)
	clear(raw)
	b := &SecretBox{raw: cp, valid: true}
	defer func() {
		clear(b.raw)
		b.wiped = true
	}()
	return fn(b)
}

//xops:syncclosure
//xops:borrowed
//xops:secretuse
func (b *SecretBox) Use(fn func(plain []byte) error) error {
	if b == nil || !b.valid || b.wiped {
		return nil
	}
	return fn(b.raw)
}
