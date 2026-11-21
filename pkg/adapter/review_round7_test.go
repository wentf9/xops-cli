package adapter

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

type round7StubCredentialResolver struct {
	secrets map[string]string
}

func (r round7StubCredentialResolver) Resolve(_ context.Context, ref credential.Ref) (credential.Secret, error) {
	if val, ok := r.secrets[ref.StoreID+"/"+ref.ItemID]; ok {
		return credential.Secret{Value: []byte(val)}, nil
	}
	return credential.Secret{}, errors.New("missing secret")
}

func TestRound7_P1_3_SnapshotValidationCanonicalIPv6CaseAndHostNameMutation(t *testing.T) {
	t.Parallel()

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	creds := round7StubCredentialResolver{
		secrets: map[string]string{
			"file/v6": "pw-v6",
			"file/ov": "pw-ov",
		},
	}

	// 1. Saved node with bracketed uppercase IPv6: GetConfig strips brackets, ResolveSecret accepts canonical match.
	mutV6, err := repo.CreateNodeContext(t.Context(), "v6-node",
		models.Node{HostRef: "hv6", IdentityRef: "idv6"},
		models.Host{Address: "[2001:0DB8::1]", Port: 22},
		models.Identity{User: "ops", AuthType: "password", LoginPasswordRef: &credential.Ref{StoreID: "file", ItemID: "v6"}},
	)
	if err != nil {
		t.Fatalf("CreateNodeContext(v6): %v", err)
	}
	adpV6 := NewSSHAdapter(repo, WithCredentialSource(creds))
	cfgV6, err := adpV6.GetConfig("v6-node")
	if err != nil {
		t.Fatalf("GetConfig(v6-node): %v", err)
	}
	if cfgV6.Address != "2001:0DB8::1" {
		t.Fatalf("cfgV6.Address = %q, want 2001:0DB8::1", cfgV6.Address)
	}
	secV6, err := adpV6.ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID:       "v6-node",
		Host:         "2001:db8::1",
		Port:         22,
		User:         "ops",
		Kind:         ssh.SecretKindLoginPassword,
		VersionToken: mutV6.AuthVersion,
	})
	if err != nil || string(secV6) != "pw-v6" {
		t.Fatalf("ResolveSecret(v6 canonical) = (%q, %v), want (pw-v6, nil)", string(secV6), err)
	}

	// 2. Saved node with -o HostName override: ResolveSecret works normally AND still detects concurrent
	// on-disk Host.Address mutations (which AuthVersion alone does NOT hash!).
	_, err = repo.CreateNodeContext(t.Context(), "override-node",
		models.Node{HostRef: "hov", IdentityRef: "idov"},
		models.Host{Address: "10.77.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "password", LoginPasswordRef: &credential.Ref{StoreID: "file", ItemID: "ov"}},
	)
	if err != nil {
		t.Fatalf("CreateNodeContext(override-node): %v", err)
	}
	adpOv := NewSSHAdapter(repo,
		WithCredentialSource(creds),
		WithSessionAuthOverride("override-node", SessionAuth{HostName: "override.internal"}),
	)
	cfgOv, err := adpOv.GetConfig("override-node")
	if err != nil {
		t.Fatalf("GetConfig(override-node): %v", err)
	}
	if cfgOv.Address != "override.internal" || cfgOv.BaseHost != "10.77.0.1" {
		t.Fatalf("cfgOv.Address=%q BaseHost=%q, want override.internal / 10.77.0.1", cfgOv.Address, cfgOv.BaseHost)
	}
	secOv, err := adpOv.ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID:       "override-node",
		Host:         cfgOv.Address,
		BaseHost:     cfgOv.BaseHost,
		Port:         cfgOv.Port,
		User:         cfgOv.User,
		Kind:         ssh.SecretKindLoginPassword,
		VersionToken: cfgOv.AuthUpdateToken,
	})
	if err != nil || string(secOv) != "pw-ov" {
		t.Fatalf("ResolveSecret(-o HostName) = (%q, %v), want (pw-ov, nil)", string(secOv), err)
	}

	// Mutate Host.Address on disk while keeping AuthVersion identical.
	snapCfg := repo.Snapshot()
	refOv := repo.View().NodeRefs["override-node"]
	nOv, _ := snapCfg.Nodes.Get("override-node")
	idOv, _ := snapCfg.Identities.Get(nOv.IdentityRef)
	if err := repo.ReplaceNodeAtRefContext(t.Context(), refOv, "override-node", nOv, models.Host{
		Address: "10.77.0.99",
		Port:    22,
	}, idOv); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext: %v", err)
	}
	if _, err := adpOv.ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID:       "override-node",
		Host:         cfgOv.Address,
		BaseHost:     cfgOv.BaseHost,
		Port:         cfgOv.Port,
		User:         cfgOv.User,
		Kind:         ssh.SecretKindLoginPassword,
		VersionToken: cfgOv.AuthUpdateToken,
	}); !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Fatalf("ResolveSecret after underlying Host.Address mutation under -o HostName = %v, want ErrSnapshotMismatch", err)
	}
}

func TestRound7_P2_3_SessionOriginDoesNotFallbackToSideMapWhenCanonicalOmitted(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host short",
		"  ConnectTimeout 11",
		"",
		"Host *.corp.example.com",
		"  HostName 10.78.0.1",
		"  ServerAliveInterval 33",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.78.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.78.0.1:22", models.Node{HostRef: "h1", IdentityRef: "id1"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)
	prov.SetNodeOpenSSHOrigin("ops@10.78.0.1:22", config.OpenSSHOrigin{
		Alias:         "short",
		CanonicalHost: "short.corp.example.com",
	})

	// Explicit session without CanonicalHost (e.g. CanonicalizeHostname=no):
	// must NOT read shared CanonicalHost or Pass-2 ServerAliveInterval=33.
	adpNoCanon := NewSSHAdapter(prov, WithSessionAuthOverride("ops@10.78.0.1:22", SessionAuth{
		OriginalHost: "short",
	}))
	clientCfg, err := adpNoCanon.GetConfig("ops@10.78.0.1:22")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if clientCfg.CanonicalHost != "" {
		t.Fatalf("non-canonicalized session leaked CanonicalHost=%q", clientCfg.CanonicalHost)
	}
	if clientCfg.Options != nil && clientCfg.Options.Get(ssh.OptionServerAliveInterval) != "" {
		t.Fatalf("non-canonicalized session leaked Pass-2 ServerAliveInterval=%q", clientCfg.Options.Get(ssh.OptionServerAliveInterval))
	}
}

func TestRound7_P2_4_SavedNodeProxyJumpMasksT2ProxyCommandAndUnpersistedMasksT4(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host bastion-t4",
		"  HostName 10.79.0.254",
		"  User ops",
		"",
		"Host edge-v",
		"  HostName 10.79.0.5",
		"  User ops",
		"  ProxyJump bastion-t4",
		"",
		"Host *",
		"  ProxyCommand t4-wildcard %h %p",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "saved-jump",
		models.Node{
			HostRef:     "h1",
			IdentityRef: "id1",
			ProxyJump:   "bastion",
			SSHOptions:  ssh.MustOptions(ssh.OptionProxyCommand, "shadowed-t2 %h %p"),
		},
		models.Host{Address: "10.79.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(saved-jump): %v", err)
	}

	verifyRound7SavedJumpPrecedence(t, repo)
	verifyRound7UnpersistedJumpPrecedence(t, repo)
}

func verifyRound7SavedJumpPrecedence(t *testing.T, repo *config.Repository) {
	t.Helper()
	// Non-interactive/MCP mode on saved-jump: ProxyJump masks T2 ProxyCommand, so no ErrLocalExecutionDisabled!
	adpMCP := NewNonInteractiveSSHAdapter(repo)
	cfgSaved, err := adpMCP.GetConfig("saved-jump")
	if err != nil {
		t.Fatalf("GetConfig(saved-jump non-interactive): %v", err)
	}
	if cfgSaved.Options != nil && cfgSaved.Options.ActiveProxyCommand() != "" {
		t.Fatalf("saved-jump leaked T2 ProxyCommand=%q", cfgSaved.Options.ActiveProxyCommand())
	}

	// Tier-1 CLI ProxyCommand still overrides saved ProxyJump when local execution is enabled.
	var t1Opts SessionControlOptions
	t1SSH, _ := ssh.NewOptions()
	_ = t1SSH.Set(ssh.OptionProxyCommand, "cli-cmd %h %p")
	t1Opts.Options = t1SSH
	adpCLI := NewSSHAdapter(repo, WithLocalExecution(true), WithSessionControlOverride("saved-jump", t1Opts))
	cfgCLI, err := adpCLI.GetConfig("saved-jump")
	if err != nil {
		t.Fatalf("GetConfig(saved-jump CLI ProxyCommand): %v", err)
	}
	if cfgCLI.ProxyJump != "" || cfgCLI.Options == nil || cfgCLI.Options.ActiveProxyCommand() != "cli-cmd %h %p" {
		t.Fatalf("Tier-1 ProxyCommand override failed: jump=%q cmd=%q", cfgCLI.ProxyJump, cfgCLI.Options.ActiveProxyCommand())
	}
}

func verifyRound7UnpersistedJumpPrecedence(t *testing.T, repo *config.Repository) {
	t.Helper()
	adpMCP := NewNonInteractiveSSHAdapter(repo)

	// End-to-end ProvenanceOpenSSHVirtual with Host edge-v ProxyJump and Host * ProxyCommand:
	// T4 ProxyJump must mask T4 ProxyCommand (no ErrLocalExecutionDisabled, ActiveProxyCommand() == "").
	cfgVirtual, err := adpMCP.GetConfig("openssh:edge-v")
	if err != nil {
		t.Fatalf("GetConfig(openssh:edge-v non-interactive): %v", err)
	}
	if cfgVirtual.ProxyJump != "openssh:bastion-t4" || (cfgVirtual.Options != nil && cfgVirtual.Options.ActiveProxyCommand() != "") {
		t.Fatalf("openssh:edge-v unexpected proxy resolution: jump=%q cmd=%q", cfgVirtual.ProxyJump, cfgVirtual.Options.ActiveProxyCommand())
	}

	// End-to-end ProvenanceOpenSSHDerived via PrepareNodeContext with composite admin@edge-v:
	prepDerived, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "edge-v", User: "admin", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(admin@edge-v): %v", err)
	}
	if snapDerived, err := repo.ResolveConnection(prepDerived.NodeID); err != nil || snapDerived.Provenance != config.ProvenanceOpenSSHDerived {
		t.Fatalf("ResolveConnection(%q) = (%v, %v), want ProvenanceOpenSSHDerived", prepDerived.NodeID, snapDerived.Provenance, err)
	}
	cfgDerived, err := adpMCP.GetConfig(prepDerived.NodeID)
	if err != nil {
		t.Fatalf("GetConfig(%q non-interactive): %v", prepDerived.NodeID, err)
	}
	if cfgDerived.ProxyJump != "openssh:bastion-t4" || (cfgDerived.Options != nil && cfgDerived.Options.ActiveProxyCommand() != "") {
		t.Fatalf("ProvenanceOpenSSHDerived %q leaked T4 ProxyCommand: jump=%q cmd=%q", prepDerived.NodeID, cfgDerived.ProxyJump, cfgDerived.Options.ActiveProxyCommand())
	}

	// Pure unit check on resolveFourTierProxySetting as well.
	t4Only, _ := ssh.NewOptions()
	_ = t4Only.Set(ssh.OptionProxyCommand, "t4-shadow %h %p")
	effProxy, _ := resolveFourTierProxySetting(false, SessionAuth{}, nil, config.ConnectionSnapshot{
		Node:       models.Node{ProxyJump: "openssh:bastion-t4"},
		Provenance: config.ProvenanceOpenSSHDerived,
	}, true, nil, nil, t4Only)
	if effProxy.Kind() != ssh.ProxyJump {
		t.Fatalf("unpersisted OpenSSH ProxyJump leaked T4 ProxyCommand: effProxy=%v", effProxy)
	}
}

func TestRound7_P2_8_SessionControlLiteralPathPreservedAcrossMerge(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "fe80::1%eth0", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "root", AuthType: "auto"})
	cfg.Nodes.Set("v6-zone", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		SSHOptions:  ssh.MustOptions(ssh.OptionControlPath, "/tmp/template-%r@%h"),
	})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	literalSock := "/tmp/cm-root@fe80::1%eth0:22-${KEEP}"
	var sessCtrl SessionControlOptions
	sessCtrl.SetMaster(ssh.ControlMasterYes)
	sessCtrl.SetLiteralPath(literalSock)

	adp := NewSSHAdapter(prov)
	pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "v6-zone", SessionControl: &sessCtrl})
	if err != nil {
		t.Fatalf("Resolve(literal): %v", err)
	}
	ctrl := pol.Control()
	if ctrl == nil || !ctrl.LiteralPath || ctrl.Path != literalSock {
		t.Fatalf("Resolve = %+v, want LiteralPath=true Path=%q", ctrl, literalSock)
	}
	resolved, err := ctrl.ResolvePath(ssh.Environment{}, ssh.TargetContext{Host: "fe80::1%eth0", Port: 22, User: "root"})
	if err != nil || resolved != literalSock {
		t.Fatalf("ctrl.ResolvePath = (%q, %v), want %q", resolved, err, literalSock)
	}
	if err := sessCtrl.ToSSHOptions().Validate(); err != nil {
		t.Fatalf("sessCtrl.ToSSHOptions().Validate() failed: %v", err)
	}
}
