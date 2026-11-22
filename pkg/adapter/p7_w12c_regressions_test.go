package adapter

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W12c_FG12M1_Tier1ProxyCommandCancelsLowerTierCycleInControlAndPolicy(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	const sshCfg = `
Host loop
    HostName 10.219.0.1
    User ops
    ProxyJump loop
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-saved", models.Host{Address: "10.219.0.2", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-loop", models.Node{
		HostRef:     "h-saved",
		IdentityRef: "id-ops",
		ProxyJump:   "openssh:loop",
	})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	muxBase := []string{"ControlMaster=auto", "ControlPath=/tmp/cm-w12c-%h-%p-%r-%j-%C"}
	cancelCases := []struct {
		name         string
		rawOpts      []string
		cliJump      string
		wantAuthJump string
	}{
		{"ProxyCommand_active", append(append([]string(nil), muxBase...), "ProxyCommand=nc %h %p"), "", ""},
		{"ProxyCommand_none", append(append([]string(nil), muxBase...), "ProxyCommand=none"), "", ""},
		{"ProxyJump_none_opt", append(append([]string(nil), muxBase...), "ProxyJump=none"), "", "none"},
		{"ProxyJump_none_cli", muxBase, "none", "none"},
		{"ProxyCommand_before_cyclic_ProxyJump", append(append([]string(nil), muxBase...), "ProxyCommand=nc %h %p", "ProxyJump=loop"), "", ""},
	}

	for _, tc := range cancelCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertW12cTier1ProxyCancelsLowerTierCycle(t, prov, &env, tc.name, tc.rawOpts, tc.cliJump, tc.wantAuthJump)
		})
	}

	// Control: without Tier-1 proxy cancellation, loop and saved-loop MUST still fail closed with *ssh.ProxyCycleError.
	plainMux, err := ParseSessionOptions(muxBase, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(plainMux): %v", err)
	}
	for _, selector := range []string{"loop", "saved-loop"} {
		var cycleErr *ssh.ProxyCycleError
		if _, err := ResolveControlTarget(ControlTargetRequest{
			Provider:       prov,
			Target:         config.ConnectionTarget{Selector: selector},
			SessionControl: plainMux,
			Environment:    &env,
		}); !errors.As(err, &cycleErr) {
			t.Errorf("ResolveControlTarget(%s, no override) = %v, want *ssh.ProxyCycleError", selector, err)
		}
	}
}

func assertW12cTier1ProxyCancelsLowerTierCycle(
	t *testing.T,
	prov config.ConfigProvider,
	env *ssh.Environment,
	name string,
	rawOpts []string,
	cliJump string,
	wantAuthJump string,
) {
	t.Helper()
	jump, hasJump, jErr := EffectiveCLIProxyJumpOverride(rawOpts, cliJump)
	if jErr != nil || !hasJump || jump != "none" {
		t.Fatalf("EffectiveCLIProxyJumpOverride(%v, %q) = (%q, %v, %v), want (\"none\", true, nil)",
			rawOpts, cliJump, jump, hasJump, jErr)
	}
	sessionOpts, err := ParseSessionOptions(rawOpts, cliJump)
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	for _, selector := range []string{"loop", "openssh:loop", "saved-loop"} {
		req := ControlTargetRequest{
			Provider:       prov,
			Target:         config.ConnectionTarget{Selector: selector},
			SessionControl: sessionOpts,
			Environment:    env,
		}
		res, err := ResolveControlTarget(req)
		if err != nil {
			t.Fatalf("ResolveControlTarget(%s, %s) failed: %v", name, selector, err)
		}
		if res.Target.JumpHost != "" {
			t.Errorf("ResolveControlTarget(%s, %s).Target.JumpHost = %q, want empty", name, selector, res.Target.JumpHost)
		}
		if res.SessionAuth.ProxyJump != wantAuthJump {
			t.Errorf("ResolveControlTarget(%s, %s).SessionAuth.ProxyJump = %q, want %q",
				name, selector, res.SessionAuth.ProxyJump, wantAuthJump)
		}

		sock, sockRes, sockErr := ResolveControlSocketPath(req)
		if sockErr != nil || sock == "" || sockRes.Target.JumpHost != "" {
			t.Fatalf("ResolveControlSocketPath(%s, %s) = (%q, %+v, %v), want valid socket without jump",
				name, selector, sock, sockRes, sockErr)
		}

		lk, auth := ResolveControlSessionLookup(req, res.Target)
		if lk == "" || auth.ProxyJump != wantAuthJump {
			t.Errorf("ResolveControlSessionLookup(%s, %s) = (%q, %+v), want auth.ProxyJump=%q",
				name, selector, lk, auth, wantAuthJump)
		}

		adp := NewSSHAdapter(prov,
			WithLocalExecution(true),
			WithSessionControlOverride(res.LookupKey, sessionOpts),
		)
		pol, pErr := adp.Resolve(t.Context(), ResolveRequest{NodeID: res.LookupKey, ResolveProxy: true})
		if pErr != nil || pol.EffectiveJump() != "" {
			t.Fatalf("SSHAdapter.Resolve(%s, %s) = (jump=%q, err=%v), want no error and empty jump",
				name, selector, pol.EffectiveJump(), pErr)
		}
	}
}

func TestP7W12c_DE12M1_PolicySolverOpenSSHMetadataAndSavedVsOpenSSHEndpointCycle(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host web
    HostName 10.214.0.1
    Port 22
    User ops

Host web-bob
    HostName 10.214.0.1
    Port 22
    User bob

Host short
    User ops

Host short.corp.example.com
    HostName 10.214.0.5
    Port 22
    User ops
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web", models.Host{Address: "10.214.0.1", Port: 22})
	cfg.Hosts.Set("h-short", models.Host{Address: "10.214.0.5", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Identities.Set("id-alice", models.Identity{User: "alice", AuthType: "auto"})
	cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-short", models.Node{HostRef: "h-short", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-alice", models.Node{HostRef: "h-web", IdentityRef: "id-alice"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	// 1. Saved node (ops@10.214.0.1:22) jumping via concrete OpenSSH stanza Host web (ops@10.214.0.1:22)
	//    must fail closed with *ssh.ProxyCycleError even though both have isDirect == false.
	var cycleErr *ssh.ProxyCycleError
	adpSavedCycle := NewSSHAdapter(prov, WithSessionAuthOverride("saved-web", SessionAuth{ProxyJump: "openssh:web"}))
	if _, err := adpSavedCycle.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web", ResolveProxy: true}); !errors.As(err, &cycleErr) {
		t.Errorf("SSHAdapter.Resolve(saved-web via openssh:web) = %v, want *ssh.ProxyCycleError", err)
	}
	if _, err := adpSavedCycle.GetConfig("saved-web"); !errors.As(err, &cycleErr) {
		t.Errorf("SSHAdapter.GetConfig(saved-web via openssh:web) = %v, want *ssh.ProxyCycleError", err)
	}

	// 1b. Saved node with hasSnapshot == true and empty persisted OpenSSHAlias must receive
	//     (openSSHAlias, canonHost) from resolveSessionOpenSSHMetadata so jumping via Host short
	//     (which has no HostName of its own) still detects the alias cycle.
	adpSavedMeta := NewSSHAdapter(prov, WithSessionAuthOverride("saved-short", SessionAuth{
		OriginalHost:  "short",
		CanonicalHost: "short.corp.example.com",
		ProxyJump:     "openssh:short",
	}))
	if _, err := adpSavedMeta.Resolve(t.Context(), ResolveRequest{NodeID: "saved-short", ResolveProxy: true}); !errors.As(err, &cycleErr) {
		t.Errorf("SSHAdapter.Resolve(saved-short with session OriginalHost=short -> openssh:short) = %v, want *ssh.ProxyCycleError", err)
	}

	// 2. Missing-snapshot (!hasSnapshot) ad-hoc node with SessionAuth OriginalHost/CanonicalHost must
	//    thread (openSSHAlias, canonHost) into buildPolicyProxyJumpTarget and detect alias/canonical cycles.
	for _, jump := range []string{"openssh:short", "openssh:short.corp.example.com"} {
		adpNoSnap := NewSSHAdapter(prov, WithSessionAuthOverride("unlisted-node", SessionAuth{
			OriginalHost:  "short",
			CanonicalHost: "short.corp.example.com",
			ProxyJump:     jump,
		}))
		if _, err := adpNoSnap.Resolve(t.Context(), ResolveRequest{NodeID: "unlisted-node", ResolveProxy: true}); !errors.As(err, &cycleErr) {
			t.Errorf("SSHAdapter.Resolve(!hasSnapshot short -> %s) = %v, want *ssh.ProxyCycleError", jump, err)
		}
	}
	// Distinct user on !hasSnapshot OpenSSH alias (bob != ops) remains allowed.
	adpNoSnapDistinct := NewSSHAdapter(prov, WithSessionAuthOverride("unlisted-node", SessionAuth{
		OriginalHost:  "short",
		CanonicalHost: "short.corp.example.com",
		ProxyJump:     "openssh:bob@short",
	}))
	if pol, err := adpNoSnapDistinct.Resolve(t.Context(), ResolveRequest{NodeID: "unlisted-node", ResolveProxy: true}); err != nil || pol.EffectiveJump() != "openssh:bob@short" {
		t.Fatalf("SSHAdapter.Resolve(!hasSnapshot short -> openssh:bob@short) = (%q, %v), want openssh:bob@short", pol.EffectiveJump(), err)
	}

	// 3. Distinct-user same-endpoint (alice@10.214.0.1:22 via bob@10.214.0.1:22) remains allowed.
	adpDistinct := NewSSHAdapter(prov, WithSessionAuthOverride("saved-alice", SessionAuth{ProxyJump: "openssh:web-bob"}))
	if pol, err := adpDistinct.Resolve(t.Context(), ResolveRequest{NodeID: "saved-alice", ResolveProxy: true}); err != nil || pol.EffectiveJump() != "openssh:web-bob" {
		t.Fatalf("SSHAdapter.Resolve(saved-alice via openssh:web-bob) = (%q, %v), want openssh:web-bob", pol.EffectiveJump(), err)
	}
}

func TestP7W12c_DE12L1_ParseSessionOptionsAndGetControlConfigFailClosedOnRawOpenSSHJump(t *testing.T) {
	t.Parallel()

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host web\n  HostName 10.217.0.2\n  User ops\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	badJumps := []string{
		" openssh:web",
		"\u00a0openssh:web",
		"bastion1, openssh:web",
		"openssh:openssh:web",
		"openssh:web ",
		" OPENSSH:web",
	}

	for _, bad := range badJumps {
		if _, err := ParseSessionOptions(nil, bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ParseSessionOptions(nil, %q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
		if _, err := ParseSessionOptions([]string{"ProxyJump=" + bad}, ""); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ParseSessionOptions([ProxyJump=%q], \"\") = %v, want ErrSSHOptionsValidation", bad, err)
		}

		// Saved node carrying malformed/padded openssh jump must fail closed even in GetControlConfig (ResolveProxy=false).
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("h-web", models.Host{Address: "10.217.0.1", Port: 22})
		cfg.Hosts.Set("h-b1", models.Host{Address: "10.217.0.10", Port: 22})
		cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("bastion1", models.Node{HostRef: "h-b1", IdentityRef: "id-ops"})
		cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops", ProxyJump: bad})
		prov := config.NewProviderWithOpenSSHParser(cfg, parser)

		adp := NewSSHAdapter(prov)
		if _, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web", ResolveProxy: false}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("SSHAdapter.Resolve(ResolveProxy=false, node.ProxyJump=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
		if _, err := adp.GetControlConfig("saved-web"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("SSHAdapter.GetControlConfig(node.ProxyJump=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}

		// SessionAuth override with bad jump must also fail closed in GetControlConfig (ResolveProxy=false).
		cfgClean := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfgClean.Hosts.Set("h-web", models.Host{Address: "10.217.0.1", Port: 22})
		cfgClean.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
		cfgClean.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops"})
		provClean := config.NewProviderWithOpenSSHParser(cfgClean, parser)

		adpSess := NewSSHAdapter(provClean, WithSessionAuthOverride("saved-web", SessionAuth{ProxyJump: bad}))
		if _, err := adpSess.GetControlConfig("saved-web"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("SSHAdapter.GetControlConfig(SessionAuth.ProxyJump=%q) = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}

	// Valid unpadded openssh: hop via -J, -o Key=Value, and -o Key Value must continue to succeed.
	for _, tc := range []struct {
		opts []string
		jump string
	}{
		{nil, "openssh:web"},
		{[]string{"ProxyJump=openssh:web"}, ""},
		{[]string{"ProxyJump = openssh:web"}, ""},
		{[]string{"ProxyJump openssh:web"}, ""},
		{[]string{"ProxyJump=bastion1,openssh:web"}, ""},
	} {
		if _, err := ParseSessionOptions(tc.opts, tc.jump); err != nil {
			t.Errorf("ParseSessionOptions(%v, %q) unexpected error: %v", tc.opts, tc.jump, err)
		}
	}
}
