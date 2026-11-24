package ssh

type AuthMethod interface {
	isAuth()
}

type passwordAuth struct{}

func (passwordAuth) isAuth() {}

type Signer interface {
	PublicKey() string
}

type ClientConfig struct {
	User string
	Auth []AuthMethod
}

func Password(secret string) AuthMethod {
	return passwordAuth{}
}

func ParsePrivateKey(pemBytes []byte) (Signer, error) {
	return nil, nil
}

func ParsePrivateKeyWithPassphrase(pemBytes, passphrase []byte) (Signer, error) {
	return nil, nil
}

func Marshal(msg any) []byte {
	return nil
}

func ParseRawPrivateKey(pemBytes []byte) (any, error) {
	return nil, nil
}
