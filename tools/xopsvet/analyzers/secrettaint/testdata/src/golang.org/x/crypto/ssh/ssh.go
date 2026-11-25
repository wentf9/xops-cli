package ssh

import (
	"crypto"
	"io"
)

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

type KeyboardInteractiveChallenge func(name, instruction string, questions []string, echos []bool) (answers []string, err error)

func KeyboardInteractive(challenge KeyboardInteractiveChallenge) AuthMethod {
	return passwordAuth{}
}

func ParseRawPrivateKey(pemBytes []byte) (any, error) {
	return nil, nil
}

func ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase []byte) (any, error) {
	return nil, nil
}

func NewSignerFromKey(key any) (Signer, error) {
	return nil, nil
}

func NewSignerFromSigner(signer crypto.Signer) (Signer, error) {
	return nil, nil
}

// Channel 对齐真实 golang.org/x/crypto/ssh/channel.go：直接声明 Read/Write/Close/CloseWrite（不嵌入 io.ReadWriteCloser）。
type Channel interface {
	Read(data []byte) (int, error)
	Write(data []byte) (int, error)
	Close() error
	CloseWrite() error
}

type Request struct{}

type NewChannel interface {
	Accept() (Channel, <-chan *Request, error)
}

type Conn interface {
	OpenChannel(name string, data []byte) (Channel, <-chan *Request, error)
}

type Client struct{}

func (*Client) OpenChannel(name string, data []byte) (Channel, <-chan *Request, error) {
	return nil, nil, nil
}

type Session struct{}

func (*Session) StdinPipe() (io.WriteCloser, error) {
	return nil, nil
}
