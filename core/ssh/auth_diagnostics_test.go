package ssh

import (
	"errors"
	"net"
	"slices"
	"strconv"
	"testing"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptossh "golang.org/x/crypto/ssh"
)

//nolint:gocyclo // Keep each protocol authentication scenario's setup and result assertions together.
func TestAuthenticatedDiagnosticActualMethods(t *testing.T) {
	for _, mode := range []string{"password", "key", "auto-key", "fallback", "none", "multifactor", "multifactor-failure"} {
		t.Run(mode, func(t *testing.T) {
			key, wrong := newAuthTestSigner(t), newAuthTestSigner(t)
			const password = "private-auth-password-marker"
			address, stop := startTestMultiAuthSSHServer(t, key.PublicKey(), password, func(config *cryptossh.ServerConfig) {
				if mode == "none" {
					config.NoClientAuth = true
				}
				if mode == "multifactor" || mode == "multifactor-failure" {
					checkKey, checkPassword := config.PublicKeyCallback, config.PasswordCallback
					config.PublicKeyCallback = func(metadata cryptossh.ConnMetadata, public cryptossh.PublicKey) (*cryptossh.Permissions, error) {
						if _, err := checkKey(metadata, public); err != nil {
							return nil, err
						}
						return nil, &cryptossh.PartialSuccessError{Next: cryptossh.ServerAuthCallbacks{PasswordCallback: checkPassword}}
					}
				}
			})
			defer stop()
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: password}
			selected := key
			want := []string{"password"}
			switch mode {
			case "key":
				cfg.AuthType, cfg.KeyRef = "key", "opaque-key"
				want = []string{"publickey"}
			case "auto-key":
				cfg.AuthType, cfg.KeyRef = "auto", "opaque-key"
				want = []string{"publickey"}
			case "fallback":
				cfg.AuthType, cfg.KeyRef = "auto", "opaque-key"
				selected = wrong
			case "none":
				want = []string{"none"}
			case "multifactor", "multifactor-failure":
				cfg.AuthType, cfg.KeyRef = "auto", "opaque-key"
				want = []string{"publickey", "password"}
			}
			resolved := password
			if mode == "multifactor-failure" {
				resolved = "incorrect"
				want = nil
			}
			recorder := &diagnosticRecorder{}
			connector := NewConnector(&mockConfigStore{cfg: cfg}, WithHostKeyVerifier(&fixtureTrust{}),
				WithKeySource(&fixtureKeySource{lease: &fixtureKeyLease{signer: selected}}),
				WithSecretResolver(&compatSecretResolver{password: resolved}), WithDiagnostics(recorder))
			defer closePlanConnector(t, connector)
			_, err = connector.Connect(t.Context(), "node")
			if (err != nil) != (mode == "multifactor-failure") {
				t.Fatalf("authentication result changed: %v", err)
			}
			successes, attempts := 0, 0
			for _, event := range recorder.snapshot() {
				if event.Kind == corelog.AuthenticationAttempt {
					attempts++
				}
				if event.Kind != corelog.Authenticated {
					continue
				}
				successes++
				if want == nil || !slices.Equal(event.Methods, want) || event.Method != want[len(want)-1] {
					t.Fatalf("wrong authenticated methods: %+v; want %v", event, want)
				}
			}
			if want != nil && successes != 1 {
				t.Fatalf("authentication success reported %d times", successes)
			}
			if want == nil && successes != 0 {
				t.Fatal("failed multifactor exchange claimed success")
			}
			if mode == "none" && attempts != 0 {
				t.Fatal("none authentication invented attempts")
			}
			if mode == "fallback" && attempts != 2 {
				t.Fatalf("fallback did not actually try both methods: %d", attempts)
			}
		})
	}
}

func TestNegotiatedDiagnosticMACMetadata(t *testing.T) {
	for _, cipher := range []string{cryptossh.CipherAES128GCM, cryptossh.CipherAES256GCM, cryptossh.CipherChaCha20Poly1305, cryptossh.CipherAES128CTR} {
		t.Run(cipher, func(t *testing.T) {
			address, stop := startTestMultiAuthSSHServer(t, nil, "fixture", func(config *cryptossh.ServerConfig) {
				config.Ciphers = []string{cipher}
				config.MACs = []string{cryptossh.HMACSHA256}
			})
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
			connector := NewConnector(&mockConfigStore{cfg: &ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: "fixture"}}, WithHostKeyVerifier(&fixtureTrust{}), WithDiagnostics(recorder))
			defer closePlanConnector(t, connector)
			if _, err := connector.Connect(t.Context(), "node"); err != nil {
				t.Fatal(err)
			}
			wantMAC := ""
			if cipher == cryptossh.CipherAES128CTR {
				wantMAC = cryptossh.HMACSHA256
			}
			events := 0
			for _, event := range recorder.snapshot() {
				if event.Kind != corelog.Authenticated && event.Kind != corelog.Negotiated {
					continue
				}
				events++
				if event.ReadCipher != cipher || event.WriteCipher != cipher || event.ReadMAC != wantMAC || event.WriteMAC != wantMAC {
					t.Fatalf("actual negotiated metadata lost: %+v", event)
				}
			}
			if events != 2 {
				t.Fatalf("missing negotiation or authenticated summary: %d", events)
			}
		})
	}
}

func TestAuthenticationTraceDoesNotGuessUnknownSelection(t *testing.T) {
	trace := newAuthenticationTrace(&diagnosticRecorder{}, "node")
	trace.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.AuthenticationAttempt, Method: "password"})
	callback := trace.wrap(func(*cryptossh.ClientAuthContext) (cryptossh.AuthMethod, error) { return nil, errors.New("stop") })
	_, _ = callback(&cryptossh.ClientAuthContext{PartialSuccessMethods: []string{"publickey"}})
	if trace.successfulMethods() != nil {
		t.Fatal("unknown final selection was guessed from partial success")
	}
}
