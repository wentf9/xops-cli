package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func writeP7ReproEd25519Key(t *testing.T, dir, name string) (string, cryptoSSH.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	block, err := cryptoSSH.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	keyPath := filepath.Join(dir, name)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key %q: %v", keyPath, err)
	}
	return keyPath, signer
}

type p7StaticProvider struct {
	cfg *ClientConfig
}

func (p p7StaticProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	if p.cfg == nil || p.cfg.NodeID != nodeID {
		return nil, fmt.Errorf("node %q not found", nodeID)
	}
	cp := *p.cfg
	cp.Options = p.cfg.Options.Clone()
	return &cp, nil
}

// TestP7Repro_H3_IdentityFileNone_DefaultIdentitiesOnly_OffersDefaultKeys reproduces H3:
// With IdentityFile=none and default IdentitiesOnly=no, OpenSSH suppresses default
// ~/.ssh/id_* file probing, whereas core/ssh/auth.go buildAutoPubkeyCandidates still
// expands DefaultKeyPaths and offers default private keys during authentication.
func TestP7Repro_H3_IdentityFileNone_DefaultIdentitiesOnly_OffersDefaultKeys(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	defaultKeyPath, defaultSigner := writeP7ReproEd25519Key(t, tmpDir, "id_ed25519")

	t.Run("buildAutoAuthPlan_omits_default_keys_when_IdentityFile_none", func(t *testing.T) {
		t.Parallel()

		plan := buildAutoAuthPlan(t.Context(), AutoAuthOptions{
			DefaultKeyPaths: []string{defaultKeyPath},
			SSHOptions: MustOptions(
				OptionIdentityFile, "none",
				OptionPasswordAuthentication, "no",
				OptionKbdInteractiveAuthentication, "no",
			),
		})
		if plan.cleanup != nil {
			defer plan.cleanup()
		}
		if plan.err != nil {
			t.Fatalf("buildAutoAuthPlan unexpected err: %v", plan.err)
		}
		for _, c := range plan.candidates {
			if c.protocol == autoAuthProtocolPublicKey && strings.Contains(c.label, defaultKeyPath) {
				t.Fatalf("H3: IdentityFile=none with default IdentitiesOnly=no still offered default key candidate %q (all=%+v)", c.label, plan.candidates)
			}
		}
	})

	t.Run("connector_handshake_does_not_offer_default_key_when_IdentityFile_none", func(t *testing.T) {
		t.Parallel()

		_, hostSigner := writeP7ReproEd25519Key(t, tmpDir, "host_ed25519")

		var (
			mu          sync.Mutex
			offeredKeys []string
		)
		serverCfg := &cryptoSSH.ServerConfig{
			PublicKeyCallback: func(_ cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
				mu.Lock()
				offeredKeys = append(offeredKeys, cryptoSSH.FingerprintSHA256(key))
				mu.Unlock()
				if string(key.Marshal()) == string(defaultSigner.PublicKey().Marshal()) {
					return &cryptoSSH.Permissions{}, nil
				}
				return nil, errors.New("rejected key")
			},
		}
		serverCfg.AddHostKey(hostSigner)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen loopback: %v", err)
		}
		var serverWG sync.WaitGroup
		t.Cleanup(func() {
			_ = ln.Close()
			serverWG.Wait()
		})

		serverWG.Add(1)
		go func() {
			defer serverWG.Done()
			for {
				conn, accErr := ln.Accept()
				if accErr != nil {
					return
				}
				serverWG.Add(1)
				go func(c net.Conn) {
					defer serverWG.Done()
					defer func() { _ = c.Close() }()
					sConn, chans, reqs, hsErr := cryptoSSH.NewServerConn(c, serverCfg)
					if hsErr != nil {
						return
					}
					defer func() { _ = sConn.Close() }()
					go cryptoSSH.DiscardRequests(reqs)
					for newCh := range chans {
						_ = newCh.Reject(cryptoSSH.Prohibited, "test server rejects channels")
					}
				}(conn)
			}
		}()

		host, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("split listen addr: %v", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("parse listen port: %v", err)
		}

		provider := p7StaticProvider{
			cfg: &ClientConfig{
				NodeID:   "h3-idnone-node",
				Address:  host,
				Port:     port,
				User:     "ops",
				AuthType: "auto",
				Options: MustOptions(
					OptionIdentityFile, "none",
					OptionStrictHostKeyChecking, "no",
					OptionUserKnownHostsFile, "none",
					OptionPasswordAuthentication, "no",
					OptionKbdInteractiveAuthentication, "no",
				),
			},
		}

		connector := NewConnector(
			provider,
			WithEnvironment(Environment{
				HomeDir:         tmpDir,
				DefaultKeyPaths: []string{defaultKeyPath},
			}),
			WithHandshakeTimeout(3*time.Second),
		)
		defer func() { _ = connector.CloseAll() }()

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		client, connErr := connector.Connect(ctx, "h3-idnone-node")
		if client != nil {
			_ = client.Close()
		}

		mu.Lock()
		gotOffered := append([]string(nil), offeredKeys...)
		mu.Unlock()

		if connErr == nil {
			t.Fatalf("H3: Connector authenticated using default key despite IdentityFile=none (offered=%v)", gotOffered)
		}
		if len(gotOffered) > 0 {
			t.Fatalf("H3: Connector offered default key(s) %v despite IdentityFile=none and default IdentitiesOnly=no", gotOffered)
		}
	})
}
