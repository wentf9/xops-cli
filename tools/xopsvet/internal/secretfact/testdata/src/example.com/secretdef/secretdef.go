package secretdef

//xops:secretuse
type SecretCB func(plain []byte) error // want SecretCB:"secretuse"

//xops:secretuse
func WithKey(fn func(plain []byte) error) error { // want WithKey:"secretuse"
	return fn(nil)
}

type Consumer interface {
	//xops:secretuse
	Consume(plain []byte) error // want Consume:"secretuse"
}
