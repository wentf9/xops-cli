package ssh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type pinnedAlgorithmVerifier struct {
	key      cryptoSSH.PublicKey
	selected atomic.Int32
}

func (v *pinnedAlgorithmVerifier) HostKeyAlgorithms(ctx context.Context, req HostKeyRequest) ([]string, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("algorithm source lacks a deadline")
	}
	if req.NodeID != "pinned" || req.VersionToken != "trust-v1" || req.Host == "" || req.Port == 0 || req.User != "fixture" {
		return nil, errors.New("algorithm source lost snapshot binding")
	}
	v.selected.Add(1)
	return []string{v.key.Type()}, ctx.Err()
}
func (v *pinnedAlgorithmVerifier) Verify(ctx context.Context, _ HostKeyRequest, key cryptoSSH.PublicKey) error {
	if !bytes.Equal(v.key.Marshal(), key.Marshal()) {
		return errors.New("unpinned host key negotiated")
	}
	return ctx.Err()
}

type fixturePassword struct{}

func (fixturePassword) ResolveSecret(ctx context.Context, _ SecretRequest) ([]byte, error) {
	return []byte(sshfixture.Password), ctx.Err()
}

func TestPinnedAlgorithmNegotiatedWithMultipleHostKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var signers []cryptoSSH.Signer
	for _, key := range []any{edKey, ecKey} {
		signer, err := cryptoSSH.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		signers = append(signers, signer)
	}
	peer, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{HostKeys: signers})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := peer.Close(); err != nil {
			t.Error(err)
		}
	}()
	host, portText, err := net.SplitHostPort(peer.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &pinnedAlgorithmVerifier{key: peer.HostKey}
	connector := NewConnector(nil, WithSecretResolver(fixturePassword{}), WithHostKeyVerifier(verifier))
	defer closePlanConnector(t, connector)
	plan := ConnectionPlan{Scope: "algorithm-fixture", Hops: []ConnectionConfig{{NodeID: "pinned", Address: host, Port: port, User: "fixture", AuthType: "password", AuthUpdateToken: "auth-v1", TrustVersion: "trust-v1"}}}
	connection, err := connector.ConnectPlan(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := connection.Client.Run(ctx, "hostname"); err != nil {
		t.Fatal(err)
	}
	if verifier.selected.Load() == 0 || peer.Executed.Load() != 1 {
		t.Fatal("pinned algorithm source was not used")
	}
}

type algorithmSourceFunc func(context.Context, HostKeyRequest) ([]string, error)

func (f algorithmSourceFunc) HostKeyAlgorithms(ctx context.Context, req HostKeyRequest) ([]string, error) {
	return f(ctx, req)
}
func (algorithmSourceFunc) Verify(ctx context.Context, _ HostKeyRequest, _ cryptoSSH.PublicKey) error {
	return ctx.Err()
}

func TestHostAlgorithmFailureClosesPrivateKeyLease(t *testing.T) {
	marker := errors.New("trust source unavailable")
	for _, name := range []string{"error", "empty", "unsupported", "timeout"} {
		t.Run(name, func(t *testing.T) {
			lease := &fixtureKeyLease{signer: newAuthTestSigner(t)}
			source := algorithmSourceFunc(func(ctx context.Context, _ HostKeyRequest) ([]string, error) {
				switch name {
				case "error":
					return nil, marker
				case "empty":
					return nil, nil
				case "unsupported":
					return []string{cryptoSSH.KeyAlgoRSA}, nil
				default:
					<-ctx.Done()
					return nil, ctx.Err()
				}
			})
			connector := NewConnector(nil, WithKeySource(&fixtureKeySource{lease: lease}), WithHostKeyVerifier(source), WithHandshakeTimeout(20*time.Millisecond))
			defer closePlanConnector(t, connector)
			config, release, err := connector.buildSSHConfig(t.Context(), &ClientConfig{AuthType: "key", KeyRef: "fixture"}, nil, nil)
			if err == nil || config != nil || release != nil || lease.closed.Load() != 1 {
				t.Fatalf("algorithm failure leaked key or fell back: config=%v err=%v closed=%d", config, err, lease.closed.Load())
			}
			if name == "error" && !errors.Is(err, marker) {
				t.Fatal(err)
			}
			if name == "timeout" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
		})
	}
}

func TestHostAlgorithmListIsCopiedAndLegacyVerifierUnchanged(t *testing.T) {
	algorithms := []string{cryptoSSH.KeyAlgoED25519}
	connector := NewConnector(nil, WithHostKeyVerifier(algorithmSourceFunc(func(context.Context, HostKeyRequest) ([]string, error) { return algorithms, nil })))
	defer closePlanConnector(t, connector)
	selected, err := connector.getHostKeyAlgorithms(t.Context(), nil, &ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	algorithms[0] = "changed"
	if selected[0] != cryptoSSH.KeyAlgoED25519 {
		t.Fatal("source mutated captured algorithm list")
	}
	legacy := NewConnector(nil, WithHostKeyVerifier(&fixtureTrust{}))
	defer closePlanConnector(t, legacy)
	if algorithms, err := legacy.getHostKeyAlgorithms(t.Context(), nil, &ClientConfig{}); err != nil || algorithms != nil {
		t.Fatal("legacy verifier lost default negotiation")
	}
}
