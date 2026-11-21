package adapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptossh "golang.org/x/crypto/ssh"
)

func writePass10Ed25519Key(t *testing.T, path, passphrase string) cryptossh.PublicKey {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase != "" {
		block, err = cryptossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	} else {
		block, err = cryptossh.MarshalPrivateKey(priv, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func startPass10PubkeySSHServer(t *testing.T, acceptedKey cryptossh.PublicKey) (string, int) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := cryptossh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &cryptossh.ServerConfig{
		PublicKeyCallback: func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			if bytes.Equal(key.Marshal(), acceptedKey.Marshal()) {
				return &cryptossh.Permissions{}, nil
			}
			return nil, errors.New("rejected key")
		},
	}
	srvCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				sConn, chans, reqs, err := cryptossh.NewServerConn(c, srvCfg)
				if err != nil {
					return
				}
				defer func() { _ = sConn.Close() }()
				go cryptossh.DiscardRequests(reqs)
				for newCh := range chans {
					_ = newCh.Reject(cryptossh.Prohibited, "no channels needed")
				}
			}(conn)
		}
	}()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func newPass10RepoAndService(
	t *testing.T,
	dir string,
	host string,
	port int,
	nodeID string,
	initialKeyPath string,
	globalIdentityFiles []string,
) (*config.Repository, *credential.Registry, *credential.Service) {
	t.Helper()
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SchemaVersion = 2
	cfg.Credential = config.DefaultCredentialConfig()
	cfg.Credential.DefaultStore = "file"
	cfg.Hosts.Set("h1", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id1", models.Identity{User: "alice", AuthType: "auto", KeyPath: initialKeyPath})
	cfg.Nodes.Set(nodeID, models.Node{HostRef: "h1", IdentityRef: "id1", SudoMode: models.SudoModeAuto})
	if len(globalIdentityFiles) > 0 {
		globalOpts := &ssh.Options{}
		for _, kf := range globalIdentityFiles {
			if err := globalOpts.Append(ssh.OptionIdentityFile, kf); err != nil {
				t.Fatalf("globalOpts.Append(IdentityFile, %q): %v", kf, err)
			}
		}
		cfg.SSHOptions = globalOpts
	}

	store := config.NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "xops.key"))
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, &config.OpenSSHParser{})
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	registry := credential.NewRegistry()
	if err := registry.Register("file", &adapterCredentialStore{data: make(map[string]credential.Secret)}); err != nil {
		t.Fatal(err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := credential.NewService(registry, journal, repo.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return repo, registry, svc
}

func TestPass10_H1_RememberPassphraseScenarios(t *testing.T) {
	const pass2 = "secret-pass-k2"

	runScenario := func(
		t *testing.T,
		name string,
		setup func(t *testing.T, dir string, k1, k2, kOld string, port int) (nodeID string, adp *SSHAdapter, repo *config.Repository, k2Abs string),
	) {
		t.Run(name, func(t *testing.T) {
			home := setTestHome(t)
			t.Setenv("XOPS_HOME", home)
			sshDir := filepath.Join(home, ".ssh")
			k1 := filepath.Join(sshDir, "id_k1")
			k2 := filepath.Join(sshDir, "id_k2")
			kOld := filepath.Join(sshDir, "id_old")
			writePass10Ed25519Key(t, k1, "")
			pub2 := writePass10Ed25519Key(t, k2, pass2)
			writePass10Ed25519Key(t, kOld, "")
			host, port := startPass10PubkeySSHServer(t, pub2)
			_ = host

			nodeID, adp, repo, k2Abs := setup(t, home, k1, k2, kOld, port)
			prompter := &testAdapterPrompter{returnSecret: pass2}
			conn := ssh.NewConnector(
				adp,
				ssh.WithEnvironment(sshenv.Discover()),
				ssh.WithSecretResolver(adp),
				ssh.WithSecretPrompter(prompter),
				ssh.WithCredentialRecorder(adp),
			)
			conn.AcceptNewHostKey.Store(true)
			t.Cleanup(func() { _ = conn.CloseAll() })

			client, err := conn.Connect(t.Context(), nodeID)
			if err != nil {
				t.Fatalf("Connect(%s): %v", name, err)
			}
			snap, err := repo.ResolveConnection(nodeID)
			if err != nil {
				t.Fatalf("ResolveConnection: %v", err)
			}
			if snap.Identity.KeyPath != k2Abs {
				t.Errorf("persisted Identity.KeyPath = %q, want %q", snap.Identity.KeyPath, k2Abs)
			}
			if snap.Identity.PassphraseRef == nil || snap.Identity.PassphraseRef.IsEmpty() {
				t.Fatal("expected PassphraseRef to be persisted")
			}
			liveCfg := client.ConnectionConfig()
			if liveCfg.AuthUpdateToken != string(snap.UpdateRef.AuthVersion[:]) {
				t.Errorf("AuthUpdateToken = %q, want %q", liveCfg.AuthUpdateToken, string(snap.UpdateRef.AuthVersion[:]))
			}
			sec, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
				Kind:         ssh.SecretKindPrivateKeyPassphrase,
				NodeID:       nodeID,
				Host:         liveCfg.Address,
				Port:         liveCfg.Port,
				User:         liveCfg.User,
				VersionToken: liveCfg.AuthUpdateToken,
			})
			if err != nil {
				t.Fatalf("ResolveSecret after connect: %v", err)
			}
			if string(sec) != pass2 {
				t.Errorf("resolved remembered passphrase = %q, want %q", string(sec), pass2)
			}
		})
	}

	// Scenario A1: multiple CLI -i keys with empty initial KeyPath
	runScenario(t, "A1_multi_CLI_i_empty_initial", func(t *testing.T, dir, k1, k2, _ string, port int) (string, *SSHAdapter, *config.Repository, string) {
		repo, reg, svc := newPass10RepoAndService(t, dir, "127.0.0.1", port, "node-a1", "", nil)
		adp := NewSSHAdapter(
			repo,
			WithCredentialSource(reg),
			WithCredentialService(svc),
			WithSessionAuthOverride("node-a1", SessionAuth{KeyPath: k1, KeyPaths: []string{k1, k2}, Remember: true}),
		)
		return "node-a1", adp, repo, k2
	})

	// Scenario A2: multiple CLI -i keys replacing previously saved unrelated KeyPath
	runScenario(t, "A2_multi_CLI_i_replace_old_initial", func(t *testing.T, dir, k1, k2, kOld string, port int) (string, *SSHAdapter, *config.Repository, string) {
		repo, reg, svc := newPass10RepoAndService(t, dir, "127.0.0.1", port, "node-a2", kOld, nil)
		adp := NewSSHAdapter(
			repo,
			WithCredentialSource(reg),
			WithCredentialService(svc),
			WithSessionAuthOverride("node-a2", SessionAuth{KeyPath: k1, KeyPaths: []string{k1, k2}, Remember: true}),
		)
		return "node-a2", adp, repo, k2
	})

	// Scenario B: concrete IdentityFile followed by -o IdentityFile=none truncating lower-tier keys
	runScenario(t, "B_identityfile_k2_then_none", func(t *testing.T, dir, _, k2, kOld string, port int) (string, *SSHAdapter, *config.Repository, string) {
		repo, reg, svc := newPass10RepoAndService(t, dir, "127.0.0.1", port, "node-b", kOld, nil)
		ctrlOpts, err := ParseSessionOptions([]string{"IdentityFile=" + k2, "IdentityFile=none"}, "")
		if err != nil {
			t.Fatalf("ParseSessionOptions: %v", err)
		}
		adp := NewSSHAdapter(
			repo,
			WithCredentialSource(reg),
			WithCredentialService(svc),
			WithSessionAuthOverride("node-b", SessionAuth{KeyPaths: []string{k2, "none"}, Remember: true}),
			WithSessionControlOverride("node-b", ctrlOpts),
		)
		cfgBefore, err := adp.GetConfig("node-b")
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		if cfgBefore.KeyPath != k2 {
			t.Fatalf("pre-connect KeyPath = %q, want %q", cfgBefore.KeyPath, k2)
		}
		return "node-b", adp, repo, k2
	})

	// Scenario C: %d template token in IdentityFile
	runScenario(t, "C_percent_token_template_key", func(t *testing.T, dir, _, k2, _ string, port int) (string, *SSHAdapter, *config.Repository, string) {
		repo, reg, svc := newPass10RepoAndService(t, dir, "127.0.0.1", port, "node-c", "", nil)
		adp := NewSSHAdapter(
			repo,
			WithCredentialSource(reg),
			WithCredentialService(svc),
			WithSessionAuthOverride("node-c", SessionAuth{KeyPath: "%d/.ssh/id_k2", KeyPaths: []string{"%d/.ssh/id_k2"}, Remember: true}),
		)
		return "node-c", adp, repo, k2
	})

	// Scenario D: saved node with empty KeyPath inheriting keys from SSHOptions (global/node IdentityFile)
	runScenario(t, "D_ssh_options_keys_empty_saved_key", func(t *testing.T, dir, k1, k2, _ string, port int) (string, *SSHAdapter, *config.Repository, string) {
		_ = k1
		repo, reg, svc := newPass10RepoAndService(t, dir, "127.0.0.1", port, "node-d", "", []string{"~/.ssh/id_k1", "~/.ssh/id_k2"})
		adp := NewSSHAdapter(
			repo,
			WithCredentialSource(reg),
			WithCredentialService(svc),
			WithSessionAuthOverride("node-d", SessionAuth{Remember: true}),
		)
		return "node-d", adp, repo, k2
	})

	// Scenario E: saved node with empty KeyPath using DefaultKeyPaths ~/.ssh/id_ed25519
	t.Run("E_default_key_path_remember", func(t *testing.T) {
		home := setTestHome(t)
		t.Setenv("XOPS_HOME", home)
		defKey := filepath.Join(home, ".ssh", "id_ed25519")
		pubDef := writePass10Ed25519Key(t, defKey, pass2)
		host, port := startPass10PubkeySSHServer(t, pubDef)

		repo, reg, svc := newPass10RepoAndService(t, home, host, port, "node-e", "", nil)
		adp := NewSSHAdapter(
			repo,
			WithCredentialSource(reg),
			WithCredentialService(svc),
			WithSessionAuthOverride("node-e", SessionAuth{Remember: true}),
		)
		prompter := &testAdapterPrompter{returnSecret: pass2}
		conn := ssh.NewConnector(
			adp,
			ssh.WithEnvironment(sshenv.Discover()),
			ssh.WithSecretResolver(adp),
			ssh.WithSecretPrompter(prompter),
			ssh.WithCredentialRecorder(adp),
		)
		conn.AcceptNewHostKey.Store(true)
		t.Cleanup(func() { _ = conn.CloseAll() })
		if _, err := conn.Connect(t.Context(), "node-e"); err != nil {
			t.Fatalf("Connect(E): %v", err)
		}
		snap, err := repo.ResolveConnection("node-e")
		if err != nil {
			t.Fatalf("ResolveConnection: %v", err)
		}
		if snap.Identity.KeyPath != defKey {
			t.Errorf("persisted KeyPath = %q, want %q", snap.Identity.KeyPath, defKey)
		}
	})

	// Negative check: concurrent unrelated target drift during passphrase save must still return ErrSnapshotMismatch.
	t.Run("negative_concurrent_port_drift_still_fails_closed", func(t *testing.T) {
		home := setTestHome(t)
		t.Setenv("XOPS_HOME", home)
		k2 := filepath.Join(home, ".ssh", "id_k2")
		pub2 := writePass10Ed25519Key(t, k2, pass2)
		_, port := startPass10PubkeySSHServer(t, pub2)

		repo, reg, svc := newPass10RepoAndService(t, home, "127.0.0.1", port, "node-neg", "", nil)
		adp := NewSSHAdapter(
			repo,
			WithCredentialSource(reg),
			WithCredentialService(svc),
			WithSessionAuthOverride("node-neg", SessionAuth{KeyPaths: []string{k2}, Remember: true}),
		)
		recorder := &pass10TamperingRecorder{
			inner: adp,
			onUpdate: func() {
				view := repo.View()
				ref := view.NodeRefs["node-neg"]
				n, h, id, _ := repo.Resolve("node-neg")
				h.Port = uint16(port + 1)
				_ = repo.ReplaceNodeAtRefContext(context.Background(), ref, "node-neg", n, h, id)
			},
		}
		prompter := &testAdapterPrompter{returnSecret: pass2}
		conn := ssh.NewConnector(
			adp,
			ssh.WithEnvironment(sshenv.Discover()),
			ssh.WithSecretResolver(adp),
			ssh.WithSecretPrompter(prompter),
			ssh.WithCredentialRecorder(recorder),
		)
		conn.AcceptNewHostKey.Store(true)
		t.Cleanup(func() { _ = conn.CloseAll() })
		if _, err := conn.Connect(t.Context(), "node-neg"); !errors.Is(err, ssh.ErrSnapshotMismatch) {
			t.Fatalf("expected ErrSnapshotMismatch on concurrent port drift, got %v", err)
		}
	})
}

type pass10TamperingRecorder struct {
	inner    ssh.CredentialRecorder
	onUpdate func()
}

func (r *pass10TamperingRecorder) UpdateAuth(ctx context.Context, nodeID, token, password, keyPath, passphrase string) (string, error) {
	newTok, err := r.inner.UpdateAuth(ctx, nodeID, token, password, keyPath, passphrase)
	if err == nil && r.onUpdate != nil {
		r.onUpdate()
	}
	return newTok, err
}

func (r *pass10TamperingRecorder) UpdateSudo(ctx context.Context, nodeID, token string, mode ssh.SudoMode, suPwd string) (string, error) {
	return r.inner.UpdateSudo(ctx, nodeID, token, mode, suPwd)
}
