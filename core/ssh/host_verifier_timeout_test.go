package ssh

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type waitingHostVerifier struct{ started, exited chan struct{} }

func (v waitingHostVerifier) Verify(ctx context.Context, _ HostKeyRequest, _ cryptoSSH.PublicKey) error {
	close(v.started)
	<-ctx.Done()
	close(v.exited)
	return ctx.Err()
}
func TestHostVerifierStopsAtHandshakeDeadline(t *testing.T) {
	signer := newAuthTestSigner(t)
	address, stop := startTestMultiAuthSSHServer(t, signer.PublicKey(), "fixture")
	defer stop()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	v := waitingHostVerifier{started: make(chan struct{}), exited: make(chan struct{})}
	c := NewConnector(&mockConfigStore{cfg: &ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: "fixture"}}, WithHostKeyVerifier(v), WithHandshakeTimeout(50*time.Millisecond))
	defer closePlanConnector(t, c)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := c.Connect(ctx, "node"); err == nil {
		t.Fatal("blocked verification succeeded")
	}
	select {
	case <-v.started:
	default:
		t.Fatal("verifier was not reached")
	}
	select {
	case <-v.exited:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("handshake expired but verifier outlived the connection attempt")
	}
}
