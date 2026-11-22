package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// TestP7W4d_EFG_M1_SharedIdentityRefFinalizePendingConnection verifies EFG-M1
// end-to-end: two saved nodes sharing an IdentityRef + interactive auth +
// --remember=always -i <encrypted-key> stages the forked IdentityRef during
// WithPendingNode so FinalizePendingConnection commits the forked ref and
// flushes deferred auth without hitting ErrConfigConflict.
func writeEncryptedEd25519Key(t *testing.T, passphrase string) (string, cryptoSSH.PublicKey) {
	t.Helper()
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(client): %v", err)
	}
	clientSSHPub, err := cryptoSSH.NewPublicKey(clientPub)
	if err != nil {
		t.Fatalf("NewPublicKey(client): %v", err)
	}
	encBlock, err := cryptoSSH.MarshalPrivateKeyWithPassphrase(clientPriv, "efg-m1", []byte(passphrase))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(encBlock), 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}
	return keyPath, clientSSHPub
}

func startPubKeyOnlySSHServer(t *testing.T, allowedPub cryptoSSH.PublicKey) uint16 {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(host): %v", err)
	}
	hostSigner, err := cryptoSSH.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(host): %v", err)
	}
	serverCfg := &cryptoSSH.ServerConfig{
		PublicKeyCallback: func(_ cryptoSSH.ConnMetadata, pub cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			if string(pub.Marshal()) == string(allowedPub.Marshal()) {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, fmt.Errorf("unexpected public key")
		},
	}
	serverCfg.AddHostKey(hostSigner)

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	var srvWg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		srvWg.Wait()
	})
	srvWg.Add(1)
	go func() {
		defer srvWg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			srvWg.Add(1)
			go func(c net.Conn) {
				defer srvWg.Done()
				defer func() { _ = c.Close() }()
				sConn, chans, reqs, srvErr := cryptoSSH.NewServerConn(c, serverCfg)
				if srvErr != nil {
					return
				}
				defer func() { _ = sConn.Close() }()
				go cryptoSSH.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(cryptoSSH.Prohibited, "unused")
				}
			}(conn)
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func setupSharedIdentityRefRepo(t *testing.T, ctx context.Context, port uint16) *config.Repository {
	t.Helper()
	diskStore := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	baseCfg, err := diskStore.Load()
	if err != nil {
		t.Fatalf("diskStore.Load: %v", err)
	}
	baseCfg.SchemaVersion = 2
	baseCfg.Credential.RememberPrompted = "always"
	if err := diskStore.Save(baseCfg); err != nil {
		t.Fatalf("Save(baseCfg): %v", err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(baseCfg, diskStore)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	for _, n := range []struct {
		id, hostRef, addr string
	}{
		{"node-a", "h-a", "127.0.0.1"},
		{"node-b", "h-b", "127.0.0.2"},
	} {
		if _, err := repo.CreateNodeContext(ctx, n.id,
			models.Node{HostRef: n.hostRef, IdentityRef: "id-shared"},
			models.Host{Address: n.addr, Port: port},
			models.Identity{User: "ops", AuthType: "auto"},
		); err != nil {
			t.Fatalf("CreateNodeContext(%s): %v", n.id, err)
		}
	}
	return repo
}

func TestP7W4d_EFG_M1_SharedIdentityRefFinalizeSucceeds(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const keyPassphrase = "efg-m1-key-passphrase"
	keyPath, clientSSHPub := writeEncryptedEd25519Key(t, keyPassphrase)
	port := startPubKeyOnlySSHServer(t, clientSSHPub)
	repo := setupSharedIdentityRefRepo(t, ctx, port)

	credSvc, err := utils.GetCredentialService(repo, repo.Snapshot())
	if err != nil {
		t.Fatalf("GetCredentialService: %v", err)
	}
	reg, err := utils.GetCredentialRegistry(repo.Snapshot())
	if err != nil {
		t.Fatalf("GetCredentialRegistry: %v", err)
	}

	req := config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "node-a"},
		ExistingUpdate: config.PendingNodeUpdate{
			Enabled:      true,
			RememberAuth: true,
			IdentityFile: keyPath,
		},
	}

	err = repo.WithPendingNode(ctx, req, func(lease config.PendingLease) error {
		adp := adapter.NewSSHAdapter(
			repo,
			adapter.WithCredentialService(credSvc),
			adapter.WithCredentialSource(reg),
			adapter.WithSessionAuthOverride(lease.NodeID(), adapter.SessionAuth{
				KeyPath:  keyPath,
				KeyPaths: []string{keyPath},
				Remember: true,
			}),
			adapter.WithSessionControlOverride(lease.NodeID(), adapter.SessionControlOptions{
				Options: func() *ssh.Options {
					o, _ := ssh.NewOptions()
					_ = o.Set(ssh.OptionStrictHostKeyChecking, "no")
					_ = o.Set(ssh.OptionIdentityAgent, "none")
					_ = o.Set(ssh.OptionIdentitiesOnly, "yes")
					return o
				}(),
			}),
		)
		connector := ssh.NewConnector(
			adp,
			ssh.WithHostKeyVerifier(staticHostKeyTrust{}),
			ssh.WithCredentialRecorder(adp),
			ssh.WithSecretPrompter(staticPassphrasePrompter(keyPassphrase)),
		)
		defer func() { _ = connector.CloseAll() }()

		client, connErr := connector.Connect(ctx, lease.NodeID())
		if connErr != nil {
			return fmt.Errorf("Connect: %w", connErr)
		}
		if finErr := adp.FinalizePendingConnection(ctx, lease, client); finErr != nil {
			return fmt.Errorf("FinalizePendingConnection: %w", finErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("EFG-M1 shared IdentityRef staged update + FinalizePendingConnection failed: %v", err)
	}

	nodeA, _, identA, err := repo.Resolve("node-a")
	if err != nil {
		t.Fatalf("Resolve(node-a): %v", err)
	}
	if nodeA.IdentityRef == "id-shared" {
		t.Fatalf("node-a IdentityRef remained shared %q, expected private forked ref", nodeA.IdentityRef)
	}
	if identA.KeyPath != keyPath || identA.PassphraseRef == nil {
		t.Fatalf("node-a persisted identity = %+v, want KeyPath=%q and non-nil PassphraseRef", identA, keyPath)
	}
	savedPass, err := reg.Resolve(ctx, *identA.PassphraseRef)
	if err != nil || string(savedPass.Value) != keyPassphrase {
		t.Fatalf("saved passphrase = (%q, %v), want (%q, nil)", string(savedPass.Value), err, keyPassphrase)
	}

	nodeB, _, identB, err := repo.Resolve("node-b")
	if err != nil {
		t.Fatalf("Resolve(node-b): %v", err)
	}
	if nodeB.IdentityRef != "id-shared" || identB.KeyPath != "" || identB.PassphraseRef != nil {
		t.Fatalf("sibling node-b was mutated: node=%+v ident=%+v", nodeB, identB)
	}
}

type staticPassphrasePrompter string

func (p staticPassphrasePrompter) PromptSecret(_ context.Context, req ssh.SecretRequest) (string, error) {
	if req.Kind == ssh.SecretKindPrivateKeyPassphrase {
		return string(p), nil
	}
	return "", fmt.Errorf("unexpected secret prompt kind %v", req.Kind)
}

// scpHandoffObserverProvider wraps a -F override provider to verify EFG-M2:
// the active WithPendingNode lease remains open during handoffConnectorMasters
// (after transfer completion) so OpenSSHAlias and ProxyCommand remain
// resolvable, and is discarded only after connector.CloseAll().
type scpHandoffObserverProvider struct {
	config.ConfigProvider
	pnp              config.PendingNodeProvider
	uploadedPath     string
	pendingOpen      atomic.Bool
	ephemeralNodeID  atomic.Value // string
	sawActiveInPhase atomic.Bool
	sawAliasInPhase  atomic.Bool
	mu               sync.Mutex
	resolveActiveLog []bool
	resolveAliasLog  []string
}

func (p *scpHandoffObserverProvider) WithPendingNode(ctx context.Context, req config.EnsureNodeOptions, fn func(config.PendingLease) error) error {
	return p.pnp.WithPendingNode(ctx, req, func(lease config.PendingLease) error {
		p.ephemeralNodeID.Store(lease.NodeID())
		p.pendingOpen.Store(true)
		defer p.pendingOpen.Store(false)
		return fn(lease)
	})
}

func (p *scpHandoffObserverProvider) IsPendingNode(nodeID string) bool {
	if checker, ok := p.ConfigProvider.(interface{ IsPendingNode(string) bool }); ok {
		return checker.IsPendingNode(nodeID)
	}
	return false
}

func (p *scpHandoffObserverProvider) GetOpenSSHParser() *config.OpenSSHParser {
	if src, ok := p.ConfigProvider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok {
		return src.GetOpenSSHParser()
	}
	return nil
}

func (p *scpHandoffObserverProvider) ResolveConnection(nodeID string) (config.ConnectionSnapshot, error) {
	snap, err := p.ConfigProvider.ResolveConnection(nodeID)
	_, uploadDoneErr := os.Stat(p.uploadedPath)
	postTransfer := uploadDoneErr == nil
	wantID, _ := p.ephemeralNodeID.Load().(string)
	active := p.pendingOpen.Load() && p.IsPendingNode(nodeID)
	if wantID != "" && nodeID == wantID {
		p.mu.Lock()
		p.resolveActiveLog = append(p.resolveActiveLog, active)
		p.resolveAliasLog = append(p.resolveAliasLog, snap.Node.OpenSSHAlias)
		p.mu.Unlock()
	}
	if postTransfer {
		if wantID != "" && nodeID == wantID {
			if active {
				p.sawActiveInPhase.Store(true)
			}
			if err == nil && snap.Node.OpenSSHAlias == "scp-efg-m2" {
				p.sawAliasInPhase.Store(true)
			}
		}
		// Inject ProxyCommand during post-transfer handoff inspection so
		// handoffConnectorMasters exercises resolveOwnedMasterNodeID and
		// hasActiveProxyCommandForMaster without spawning a detached go-test
		// daemon subprocess.
		if err == nil && (nodeID == config.OpenSSHNodePrefix+"scp-efg-m2" || snap.Node.OpenSSHAlias == "scp-efg-m2") {
			opts := snap.Node.SSHOptions.Clone()
			if opts == nil {
				opts, _ = ssh.NewOptions()
			}
			_ = opts.Set(ssh.OptionProxyCommand, "false")
			snap.Node.SSHOptions = opts
		}
	}
	return snap, err
}

// TestP7W4d_EFG_M2_ScpPendingLeaseHeldAcrossHandoff verifies EFG-M2:
// ScpOptions.runWithProvider keeps WithPendingNode open across transfer AND
// handoffConnectorMasters + connector.CloseAll(), so -F ephemeral nodes remain
// resolvable with OpenSSHAlias during handoff and are discarded afterward.
func TestP7W4d_EFG_M2_ScpPendingLeaseHeldAcrossHandoff(t *testing.T) {
	fixture := newSCPTransferFixture(t)
	_, portStr, err := net.SplitHostPort(fixture.address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", fixture.address, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}

	sockPath := filepath.Join(shortControlTempDir(t), "efg-m2.sock")
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host scp-efg-m2",
		"  HostName 127.0.0.1",
		fmt.Sprintf("  Port %d", portNum),
		"  User otheruser",
		"  StrictHostKeyChecking no",
		"  ControlMaster auto",
		"  ControlPath " + sockPath,
		"  ControlPersist 30s",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("WriteFile(ssh_config): %v", err)
	}

	baseRepo, cfg := newP6PendingTestRepo(t, "")
	overrideProv, err := config.WithOpenSSHConfigOverride(baseRepo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	pnp, ok := overrideProv.(config.PendingNodeProvider)
	if !ok {
		t.Fatalf("override provider %T does not implement PendingNodeProvider", overrideProv)
	}
	uploadedPath := filepath.Join(fixture.home, "efg-m2-uploaded.txt")
	observer := &scpHandoffObserverProvider{
		ConfigProvider: overrideProv,
		pnp:            pnp,
		uploadedPath:   uploadedPath,
	}

	localFile := filepath.Join(t.TempDir(), "payload.txt")
	writeSCPTestFile(t, localFile, "efg-m2-payload")

	opts := NewScpOptions()
	opts.Source = localFile
	opts.Dest = "test@scp-efg-m2:~/efg-m2-uploaded.txt"
	opts.Password = "password"
	opts.Force = true
	opts.Quiet = true
	opts.control.ConfigFile = sshCfgPath
	opts.control.Options = []string{"ControlMaster=auto", "ControlPath=" + sockPath, "ControlPersist=30s"}

	if err := opts.runWithProvider(fixture.ctx, cfg, observer); err != nil {
		t.Fatalf("runWithProvider(-F ControlPersist): %v", err)
	}
	assertSCPTestFile(t, uploadedPath, "efg-m2-payload")

	ephemeralID, _ := observer.ephemeralNodeID.Load().(string)
	if ephemeralID == "" {
		t.Fatal("expected ephemeral pending nodeID to be prepared")
	}
	if !observer.sawActiveInPhase.Load() {
		t.Fatalf("expected ephemeral pending lease %q to remain active during handoffConnectorMasters", ephemeralID)
	}
	observer.mu.Lock()
	activeLog := slices.Clone(observer.resolveActiveLog)
	aliasLog := slices.Clone(observer.resolveAliasLog)
	observer.mu.Unlock()
	if !observer.sawAliasInPhase.Load() {
		t.Fatalf("expected OpenSSHAlias %q to remain resolvable on %q during handoffConnectorMasters (aliases=%v)", "scp-efg-m2", ephemeralID, aliasLog)
	}
	if len(activeLog) < 2 {
		t.Fatalf("expected >= 2 ResolveConnection calls on %q (connect + handoff), got %d", ephemeralID, len(activeLog))
	}
	for i, active := range activeLog {
		if !active {
			t.Fatalf("ResolveConnection call #%d on %q observed prematurely discarded pending lease", i, ephemeralID)
		}
	}
	if observer.IsPendingNode(ephemeralID) {
		t.Fatalf("ephemeral pending lease %q leaked after runWithProvider returned", ephemeralID)
	}
}

// TestP7W4d_EFG_L2_ScpBuildEnsureOptionsSetsExistingUpdateAlias verifies EFG-L2:
// buildScpEnsureOptions populates ExistingUpdate.Alias from ScpOptions.Alias so
// confirming an existing saved node persists the requested alias.
func TestP7W4d_EFG_L2_ScpBuildEnsureOptionsSetsExistingUpdateAlias(t *testing.T) {
	repo, _ := newP6PendingTestRepo(t, "")
	if _, err := repo.CreateNodeContext(t.Context(), "saved-scp",
		models.Node{HostRef: "h-scp", IdentityRef: "id-scp"},
		models.Host{Address: "10.0.0.50", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	opts := NewScpOptions()
	opts.Alias = "scp-new-alias"
	opts.Remember = "always"
	req, err := opts.buildScpEnsureOptions(repo, PathInfo{
		IsRemote: true,
		Host:     "saved-scp",
		Path:     "/tmp/out",
	}, "")
	if err != nil {
		t.Fatalf("buildScpEnsureOptions: %v", err)
	}
	if !req.ExistingUpdate.Enabled {
		t.Fatal("expected ExistingUpdate.Enabled == true")
	}
	if req.ExistingUpdate.Alias != "scp-new-alias" {
		t.Fatalf("ExistingUpdate.Alias = %q, want %q", req.ExistingUpdate.Alias, "scp-new-alias")
	}

	if err := repo.WithPendingNode(t.Context(), req, func(lease config.PendingLease) error {
		return lease.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("WithPendingNode/Confirm: %v", err)
	}
	node, _, _, err := repo.Resolve("saved-scp")
	if err != nil {
		t.Fatalf("Resolve(saved-scp): %v", err)
	}
	if !slices.Contains(node.Alias, "scp-new-alias") {
		t.Fatalf("saved-scp aliases = %v, want %q persisted", node.Alias, "scp-new-alias")
	}
}

// TestP7W4d_EFG_M3_ScpCaseInsensitiveOpenSSHPrefix verifies EFG-M3:
// scp parsePath and parseOpenSSHPath match "openssh:" case-insensitively and
// reject case-insensitive double prefixes.
func TestP7W4d_EFG_M3_ScpCaseInsensitiveOpenSSHPrefix(t *testing.T) {
	validCases := []struct {
		raw      string
		wantUser string
		wantHost string
		wantPath string
	}{
		{
			raw:      "OPENSSH:bastion:/etc/hosts",
			wantHost: "openssh:bastion",
			wantPath: "/etc/hosts",
		},
		{
			raw:      "OpenSSH:alice@bastion:/tmp/data.bin",
			wantUser: "alice",
			wantHost: "openssh:bastion",
			wantPath: "/tmp/data.bin",
		},
		{
			raw:      "OpEnSsH:[::1]:/var/log/app.log",
			wantHost: "openssh:::1",
			wantPath: "/var/log/app.log",
		},
	}
	for _, tc := range validCases {
		t.Run("valid_"+tc.raw, func(t *testing.T) {
			got, err := parsePath(tc.raw)
			if err != nil {
				t.Fatalf("parsePath(%q) error = %v", tc.raw, err)
			}
			if !got.IsRemote || got.User != tc.wantUser || got.Host != tc.wantHost || got.Path != tc.wantPath {
				t.Fatalf("parsePath(%q) = %+v, want IsRemote=true User=%q Host=%q Path=%q",
					tc.raw, got, tc.wantUser, tc.wantHost, tc.wantPath)
			}
		})
	}

	invalidCases := []string{
		"openssh:OPENSSH:22:/path",
		"OPENSSH:openssh:bastion:/path",
		"OPENSSH:OPENSSH:bastion:/path",
		"OpenSSH:",
		"OPENSSH:bastion",
	}
	for _, raw := range invalidCases {
		t.Run("reject_"+raw, func(t *testing.T) {
			if got, err := parsePath(raw); err == nil {
				t.Fatalf("parsePath(%q) unexpectedly succeeded as %+v, want error", raw, got)
			}
		})
	}
}

type failingResolveProvider struct {
	config.ConfigProvider
	resolveErr error
}

func (p *failingResolveProvider) ResolveConnection(string) (config.ConnectionSnapshot, error) {
	return config.ConnectionSnapshot{}, p.resolveErr
}

// TestP7W4d_EFG_M5_ProxyCommandAndBackgroundSessionFailClosed verifies EFG-M5:
//  1. checkNode / hasActiveProxyCommandInPath / hasActiveProxyCommandForMaster /
//     shouldSkipMasterHandoff / validateBackgroundProxyCommand fail closed on
//     Resolve errors (treating the path as unsafe to detach/handoff).
//  2. canConfigSupplyBackgroundSession / loadBackgroundSessionProbeProvider fail
//     closed on corrupt xops_config.yaml or corrupt -F OpenSSH config instead of
//     failing open.
func TestP7W4d_EFG_M5_ProxyCommandAndBackgroundSessionFailClosed(t *testing.T) {
	t.Run("proxy_command_predicates_fail_closed_on_resolve_error", func(t *testing.T) {
		baseRepo, _ := newP6PendingTestRepo(t, "")
		boom := errors.New("corrupt node snapshot")
		badProv := &failingResolveProvider{ConfigProvider: baseRepo, resolveErr: boom}

		opts := NewSshOptions()
		opts.BgRun = true

		hasProxy, err := opts.hasActiveProxyCommandInPath(badProv, "web-01", nil)
		if err == nil || !hasProxy {
			t.Fatalf("hasActiveProxyCommandInPath(error) = (%v, %v), want (true, non-nil err)", hasProxy, err)
		}

		hasMasterProxy, err := opts.hasActiveProxyCommandForMaster(badProv, "web-01", "web-01")
		if err == nil || !hasMasterProxy {
			t.Fatalf("hasActiveProxyCommandForMaster(error) = (%v, %v), want (true, non-nil err)", hasMasterProxy, err)
		}

		if err := opts.validateBackgroundProxyCommand(badProv, "web-01"); err == nil {
			t.Fatal("validateBackgroundProxyCommand unexpectedly succeeded on Resolve error")
		}

		handoffOpts := NewSshOptions()
		skip, err := handoffOpts.shouldSkipMasterHandoff(t.Context(), nil, badProv, "web-01")
		if err == nil || !skip {
			t.Fatalf("shouldSkipMasterHandoff(error) = (%v, %v), want (true, non-nil err)", skip, err)
		}
	})

	t.Run("background_session_probe_fails_closed_on_corrupt_xops_config", func(t *testing.T) {
		cfgDir := t.TempDir()
		t.Setenv("XOPS_CONFIG_DIR", cfgDir)
		corruptYAML := "schema_version: 2\n: [not valid yaml\n"
		if err := os.WriteFile(filepath.Join(cfgDir, "xops_config.yaml"), []byte(corruptYAML), 0o600); err != nil {
			t.Fatalf("WriteFile(corrupt config): %v", err)
		}

		opts := NewSshOptions()
		opts.BgRun = true
		opts.control.ConfigFile = "none"
		opts.args = []string{"10.0.0.1"}

		v, err := opts.canConfigSupplyBackgroundSession()
		if err == nil || v.Allowed() {
			t.Fatalf("canConfigSupplyBackgroundSession(corrupt xops_config.yaml) = (%v, %v), want (Deny, error)", v, err)
		}
		if valErr := opts.Validate(); valErr == nil {
			t.Fatal("Validate(-f) unexpectedly succeeded (failed open) on corrupt xops_config.yaml")
		}
	})

	t.Run("background_session_probe_fails_closed_on_missing_or_corrupt_F_config", func(t *testing.T) {
		cfgDir := t.TempDir()
		t.Setenv("XOPS_CONFIG_DIR", cfgDir)

		missingPath := filepath.Join(t.TempDir(), "does-not-exist-ssh-config")
		opts := NewSshOptions()
		opts.BgRun = true
		opts.control.ConfigFile = missingPath
		opts.args = []string{"10.0.0.1"}

		v, err := opts.canConfigSupplyBackgroundSession()
		if err == nil || v.Allowed() {
			t.Fatalf("canConfigSupplyBackgroundSession(missing -F) = (%v, %v), want (Deny, error)", v, err)
		}
		if valErr := opts.Validate(); valErr == nil {
			t.Fatal("Validate(-f -F missing) unexpectedly succeeded (failed open)")
		}
	})
}

func TestP7W4d_ExecOutDir_OpenAppendRegularRejectsSymlinkAndAppendsRegular(t *testing.T) {
	ctx, connector, _ := newExecCombinationFixture(t, nil)

	t.Run("appends_to_existing_regular_log_file", func(t *testing.T) {
		outDir := t.TempDir()
		logPath := filepath.Join(outDir, "fixture.log")
		if err := os.WriteFile(logPath, []byte("prior-line\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(logPath): %v", err)
		}

		o := NewExecOptions()
		o.OutDir = outDir
		o.Command = "echo appended"
		o.stdout = &bytes.Buffer{}
		o.stderr = &bytes.Buffer{}

		var mu sync.Mutex
		task := execHostTask{nodeID: "fixture", host: "fixture", outLogName: "fixture.log"}
		if err := o.executeTask(ctx, connector, task, o.Command, false, 1, &mu); err != nil {
			t.Fatalf("executeTask(regular append): %v", err)
		}

		got, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("ReadFile(logPath): %v", err)
		}
		if !strings.HasPrefix(string(got), "prior-line\n") || len(got) <= len("prior-line\n") {
			t.Fatalf("expected appended output after prior-line, got %q", string(got))
		}
	})

	t.Run("rejects_symlink_log_file_without_modifying_target", func(t *testing.T) {
		outDir := t.TempDir()
		victimDir := t.TempDir()
		victim := filepath.Join(victimDir, "victim.txt")
		if err := os.WriteFile(victim, []byte("untouched\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(victim): %v", err)
		}
		linkPath := filepath.Join(outDir, "fixture.log")
		if err := os.Symlink(victim, linkPath); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink creation unavailable on Windows without privilege: %v", err)
			}
			t.Fatalf("os.Symlink: %v", err)
		}

		o := NewExecOptions()
		o.OutDir = outDir
		o.Command = "echo should-not-write"
		o.stdout = &bytes.Buffer{}
		o.stderr = &bytes.Buffer{}

		var mu sync.Mutex
		task := execHostTask{nodeID: "fixture", host: "fixture", outLogName: "fixture.log"}
		err := o.executeTask(ctx, connector, task, o.Command, false, 1, &mu)
		if err == nil {
			t.Fatal("executeTask unexpectedly succeeded when log file is a symlink")
		}
		if !errors.Is(err, fsx.ErrSymlink) {
			t.Fatalf("expected fsx.ErrSymlink, got %v", err)
		}
		gotVictim, readErr := os.ReadFile(victim)
		if readErr != nil {
			t.Fatalf("ReadFile(victim): %v", readErr)
		}
		if string(gotVictim) != "untouched\n" {
			t.Fatalf("symlink target modified: got %q, want %q", string(gotVictim), "untouched\n")
		}
	})
}
