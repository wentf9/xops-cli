package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type fixtureKeyLease struct {
	signer cryptoSSH.Signer
	closed atomic.Int32
	err    error
}

func (k *fixtureKeyLease) Signer() cryptoSSH.Signer { return k.signer }
func (k *fixtureKeyLease) Close() error             { k.closed.Add(1); return k.err }

type fixtureKeySource struct {
	lease   *fixtureKeyLease
	err     error
	request KeyRequest
}

func (s *fixtureKeySource) OpenKey(_ context.Context, req KeyRequest) (KeyLease, error) {
	s.request = req
	return s.lease, s.err
}

type fixtureTrust struct {
	err     error
	request HostKeyRequest
}

func (v *fixtureTrust) Verify(ctx context.Context, req HostKeyRequest, _ cryptoSSH.PublicKey) error {
	v.request = req
	return errors.Join(ctx.Err(), v.err)
}

func TestExplicitKeyAndTrustSources(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"success", "auto", "trust_rejected", "lease_close_failed"} {
		t.Run(scenario, func(t *testing.T) {
			address, stop := startTestMultiAuthSSHServer(t, signer.PublicKey(), "unused")
			defer stop()
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			marker := errors.New("fixture rejection")
			lease := &fixtureKeyLease{signer: signer}
			keys := &fixtureKeySource{lease: lease}
			trust := &fixtureTrust{}
			if scenario == "trust_rejected" {
				trust.err = marker
			}
			if scenario == "lease_close_failed" {
				lease.err = marker
			}
			provider := &mockConfigStore{cfg: &ClientConfig{
				NodeID: "node", Address: host, Port: port, User: "operator", AuthType: "key",
				KeyRef: "opaque-key", AuthUpdateToken: "key-version", TrustVersion: "trust-version",
			}}
			if scenario == "auto" {
				provider.cfg.AuthType = "auto"
			}
			connector := NewConnector(provider, WithKeySource(keys), WithHostKeyVerifier(trust))
			defer func() {
				if err := connector.CloseAll(); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			client, err := connector.Connect(ctx, "node")
			if scenario == "success" || scenario == "auto" {
				if err != nil {
					t.Fatal(err)
				}
				if got := client.ConnectionConfig(); got.KeyRef != "opaque-key" || got.TrustVersion != "trust-version" {
					t.Fatalf("source binding was lost: %+v", got)
				}
			} else {
				if !errors.Is(err, marker) {
					t.Fatalf("source error lost: %v", err)
				}
				if client != nil || connector.clients.Count() != 0 {
					t.Fatal("failed authentication material published a client")
				}
			}
			if lease.closed.Load() != 1 {
				t.Fatalf("key lease closed %d times", lease.closed.Load())
			}
			assertSourceBindings(t, keys.request, trust.request, host, port)
		})
	}
}

func TestCoreDoesNotDiscoverPersonalTrust(t *testing.T) {
	directory := setTestHome(t)
	provider := &mockConfigStore{cfg: &ClientConfig{NodeID: "node", Address: "127.0.0.1", Port: 22, User: "fixture", AuthType: "password", Password: "synthetic"}}
	connector := NewConnector(provider)
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := connector.Connect(ctx, "node"); !errors.Is(err, ErrInteractionRequired) {
		t.Fatalf("missing explicit trust must fail before dialing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, ".ssh")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("core touched a personal SSH directory: %v", err)
	}
}

func TestKeySourcePartialFailureClosesLease(t *testing.T) {
	marker := errors.New("source unavailable")
	lease := &fixtureKeyLease{}
	connector := NewConnector(nil, WithKeySource(&fixtureKeySource{lease: lease, err: marker}))
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	}()
	_, _, err := connector.sourcedKeyAuth(t.Context(), &ClientConfig{KeyRef: "opaque"})
	if !errors.Is(err, marker) || lease.closed.Load() != 1 {
		t.Fatalf("partial signer acquisition leaked its lease: error=%v closed=%d", err, lease.closed.Load())
	}
}

func TestExplicitAutoKeySourceFailureCannotFallBack(t *testing.T) {
	marker := errors.New("referenced key version unavailable")
	lease := &fixtureKeyLease{}
	var passwordReads atomic.Int32
	provider := &mockConfigStore{cfg: &ClientConfig{
		NodeID: "node", Address: "192.0.2.1", Port: 22, User: "fixture", AuthType: "auto", KeyRef: "selected-key",
	}}
	connector := NewConnector(provider,
		WithKeySource(&fixtureKeySource{lease: lease, err: marker}),
		WithSecretResolver(recoveryResolverFunc(func(context.Context, SecretRequest) ([]byte, error) {
			passwordReads.Add(1)
			return []byte("must-not-fall-back"), nil
		})),
	)
	defer closePlanConnector(t, connector)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := connector.Connect(ctx, "node"); !errors.Is(err, marker) {
		t.Fatalf("explicit key failure was bypassed: %v", err)
	}
	if passwordReads.Load() != 0 || lease.closed.Load() != 1 {
		t.Fatal("failed key source leaked or fell back to a password")
	}
}

func TestKeySourceTypedNilLeaseFailsClosed(t *testing.T) {
	connector := NewConnector(nil, WithKeySource(&fixtureKeySource{}))
	defer closePlanConnector(t, connector)
	if _, _, err := connector.sourcedKeyAuth(t.Context(), &ClientConfig{}); err == nil {
		t.Fatal("typed-nil key lease was accepted")
	}
}

func TestInputCopyCancellationRetainsCleanupError(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	marker := errors.New("input cleanup failed")
	var calls atomic.Int32
	copy, err := NewInputCopy(ctx, func() error { calls.Add(1); done <- nil; return marker }, done)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := copy.Close(); !errors.Is(err, marker) {
			t.Errorf("close error: %v", err)
		}
	}()
	cancel()
	wait, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer stop()
	if err := copy.Wait(wait); !errors.Is(err, marker) {
		t.Fatalf("cleanup error lost: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("cancelled input %d times", calls.Load())
	}
}

func assertSourceBindings(t *testing.T, key KeyRequest, trust HostKeyRequest, host string, port int) {
	t.Helper()
	if key != (KeyRequest{NodeID: "node", Host: host, Port: port, User: "operator", Reference: "opaque-key", VersionToken: "key-version"}) {
		t.Fatalf("unbound key request: %+v", key)
	}
	if trust.VersionToken != "trust-version" || trust.Host != host || trust.Port != port || trust.NodeID != "node" || trust.User != "operator" {
		t.Fatalf("unbound trust request: %+v", trust)
	}
}
