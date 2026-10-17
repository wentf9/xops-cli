package ssh

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptossh "golang.org/x/crypto/ssh"
)

type diagnosticRecorder struct {
	mu     sync.Mutex
	events []corelog.Diagnostic
}

func (r *diagnosticRecorder) ObserveDiagnostic(e corelog.Diagnostic) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}
func (r *diagnosticRecorder) snapshot() []corelog.Diagnostic {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]corelog.Diagnostic(nil), r.events...)
}

func TestAuthenticationDiagnosticsPreserveFallback(t *testing.T) {
	for _, password := range []string{"correct-secret", "wrong-secret"} {
		t.Run(password, func(t *testing.T) {
			recorder := &diagnosticRecorder{}
			callback := newSequentialAuthCallback([]autoAuthCandidate{
				{protocol: "publickey", label: "private-key-label-not-for-output", method: cryptossh.PublicKeys(newAuthTestSigner(t))},
				{protocol: "password", method: cryptossh.Password(password)},
			}, nil, nil, recorder)
			err := runAuthCallbackHandshake(t, callback, newAuthTestSigner(t).PublicKey(), "correct-secret")
			if (err == nil) != (password == "correct-secret") {
				t.Fatalf("authentication changed: %v", err)
			}
			var attempts []string
			for _, e := range recorder.snapshot() {
				if e.Kind == corelog.AuthenticationAttempt {
					attempts = append(attempts, e.Method)
				}
				if e.Kind == corelog.Authenticated {
					t.Fatal("candidate selection claimed authentication success")
				}
			}
			if len(attempts) != 2 || attempts[0] != "publickey" || attempts[1] != "password" {
				t.Fatalf("attempts: %v", attempts)
			}
		})
	}
}

var errDiagnosticTrust = errors.New("fixture host key rejected")

type rejectingDiagnosticVerifier struct{}

func (rejectingDiagnosticVerifier) Verify(context.Context, HostKeyRequest, cryptossh.PublicKey) error {
	return errDiagnosticTrust
}

func TestDiagnosticsDoNotRelaxHostKeyVerification(t *testing.T) {
	address, stop := startTestMultiAuthSSHServer(t, newAuthTestSigner(t).PublicKey(), "fixture")
	defer stop()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &diagnosticRecorder{}
	c := NewConnector(&mockConfigStore{cfg: &ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: "fixture"}}, WithHostKeyVerifier(rejectingDiagnosticVerifier{}), WithDiagnostics(recorder))
	defer closePlanConnector(t, c)
	if _, err := c.Connect(t.Context(), "node"); !errors.Is(err, errDiagnosticTrust) {
		t.Fatalf("host trust error lost: %v", err)
	}
	if err := c.CloseAll(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range recorder.snapshot() {
		if e.Kind == corelog.Authenticated {
			t.Fatal("untrusted connection reported authenticated")
		}
		if e.Kind == corelog.HostKeyChecked {
			found = true
			if e.Accepted || e.Fingerprint == "" {
				t.Fatalf("incorrect host key event: %+v", e)
			}
		}
	}
	if !found {
		t.Fatal("missing rejected host key event")
	}
}

func TestFixedAuthenticationDiagnosticsPreserveResult(t *testing.T) {
	address, stop := startTestMultiAuthSSHServer(t, newAuthTestSigner(t).PublicKey(), "fixture")
	defer stop()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"fixture", "incorrect"} {
		t.Run(password, func(t *testing.T) {
			recorder := &diagnosticRecorder{}
			c := NewConnector(&mockConfigStore{cfg: &ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: password}}, WithHostKeyVerifier(&fixtureTrust{}), WithDiagnostics(recorder))
			defer closePlanConnector(t, c)
			_, err := c.Connect(t.Context(), "node")
			if (err == nil) != (password == "fixture") {
				t.Fatalf("authentication changed: %v", err)
			}
			if err := c.CloseAll(); err != nil {
				t.Fatal(err)
			}
			attempts, authenticated, negotiated := 0, 0, 0
			for _, event := range recorder.snapshot() {
				if event.Kind == corelog.AuthenticationAttempt {
					attempts++
					if event.Method != "password" {
						t.Fatalf("incorrect method: %s", event.Method)
					}
				}
				if event.Kind == corelog.Authenticated {
					authenticated++
				}
				if event.Kind == corelog.Negotiated {
					negotiated++
					if event.KeyExchange == "" || event.ReadCipher == "" || event.ClientVersion == "" || event.ServerVersion == "" {
						t.Fatalf("missing pre-authentication metadata: %+v", event)
					}
				}
			}
			if negotiated != 1 {
				t.Fatalf("negotiation missing or duplicated: %d", negotiated)
			}
			if attempts != 1 || (authenticated == 1) != (password == "fixture") {
				t.Fatalf("attempts=%d authenticated=%d", attempts, authenticated)
			}
		})
	}
}
