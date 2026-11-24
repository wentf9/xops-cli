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

	//xops:syncclosure
	WithScope(fn func() error) error // want WithScope:"syncclosure"
}

//xops:secretuse
type AliasCB = func(plain []byte) error // want AliasCB:"secretuse"

type ParamCB func( // want ParamCB:"secretuse"
	//xops:secretuse
	plain []byte,
) error

//xops:syncclosure
func RunSync(fn func() error) error { // want RunSync:"syncclosure"
	return fn()
}
