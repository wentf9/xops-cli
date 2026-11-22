package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func startW14cLoopbackFixturePair(t *testing.T, ctx context.Context) (*sshfixture.Server, *sshfixture.Server, string, uint16, uint16) {
	t.Helper()
	bastionSrv, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New(bastion): %v", err)
	}
	t.Cleanup(func() { _ = bastionSrv.Close() })

	targetSrv, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New(target): %v", err)
	}
	t.Cleanup(func() { _ = targetSrv.Close() })

	bastionHost, bastionPortStr, err := net.SplitHostPort(bastionSrv.Address)
	if err != nil {
		t.Fatalf("SplitHostPort(bastion): %v", err)
	}
	bastionPort64, err := strconv.ParseUint(bastionPortStr, 10, 16)
	if err != nil {
		t.Fatalf("ParseUint(bastionPort): %v", err)
	}
	targetHost, targetPortStr, err := net.SplitHostPort(targetSrv.Address)
	if err != nil {
		t.Fatalf("SplitHostPort(target): %v", err)
	}
	targetPort64, err := strconv.ParseUint(targetPortStr, 10, 16)
	if err != nil {
		t.Fatalf("ParseUint(targetPort): %v", err)
	}
	if bastionHost != targetHost || bastionPort64 == targetPort64 {
		t.Fatalf("expected same loopback host with distinct ports: bastion=%s target=%s", bastionSrv.Address, targetSrv.Address)
	}
	return bastionSrv, targetSrv, bastionHost, uint16(bastionPort64), uint16(targetPort64)
}

func TestP7W14c_L3_14_M1_ClientConfigConnectorAndSecretSnapshotHonorSessionPortUser(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv, targetSrv, bastionHost, bastionPort, targetPort := startW14cLoopbackFixturePair(t, ctx)

	sshCfg := fmt.Sprintf(`
Host web
    HostName %s
    Port %d
    User ops
`, bastionHost, bastionPort)
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web", models.Host{Address: bastionHost, Port: bastionPort})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("saved-web", models.Node{HostRef: "h-web", IdentityRef: "id-ops"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	override := SessionAuth{
		Port:      targetPort,
		User:      "alice",
		ProxyJump: "openssh:web",
		Password:  sshfixture.Password,
	}
	adpOpts := []Option{
		WithSessionAuthOverride("saved-web", override),
		WithSessionAuthOverride("openssh:web", SessionAuth{Password: sshfixture.Password}),
	}
	connector, adp := NewConnectorAndAdapter(prov, adpOpts, ssh.WithHandshakeTimeout(5*time.Second))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = connector.CloseAll() })

	// 1. Policy Resolve + ClientConfig + GetConfig must all honor SessionAuth.{Port, User}.
	pol, err := adp.Resolve(ctx, ResolveRequest{NodeID: "saved-web", RequireSnapshot: true, ResolveProxy: true})
	if err != nil {
		t.Fatalf("adp.Resolve(saved-web): %v", err)
	}
	clientCfg, err := pol.ClientConfig()
	if err != nil {
		t.Fatalf("pol.ClientConfig(): %v", err)
	}
	if clientCfg.Port != int(targetPort) || clientCfg.User != "alice" || clientCfg.ProxyJump != "openssh:web" {
		t.Fatalf("pol.ClientConfig() = (port=%d user=%q jump=%q), want (port=%d user=%q jump=%q)",
			clientCfg.Port, clientCfg.User, clientCfg.ProxyJump, targetPort, "alice", "openssh:web")
	}
	getCfg, err := adp.GetConfig("saved-web")
	if err != nil {
		t.Fatalf("adp.GetConfig(saved-web): %v", err)
	}
	if getCfg.Port != int(targetPort) || getCfg.User != "alice" {
		t.Fatalf("adp.GetConfig(saved-web) = (port=%d user=%q), want (port=%d user=%q)",
			getCfg.Port, getCfg.User, targetPort, "alice")
	}
	env := w10cTestEnv()
	polTarget := pol.controlTargetContextWithEnv("saved-web", env)
	dialTarget := ssh.BuildClientTargetContext("saved-web", clientCfg, env, nil)
	if polTarget != dialTarget {
		t.Fatalf("TargetContext mismatch between pol and ClientConfig:\n  pol  = %+v\n  dial = %+v", polTarget, dialTarget)
	}

	// 2. Live Connector.Connect must dial bastionSrv (openssh:web on bastionPort) once and
	//    forward via direct-tcpip to targetSrv (saved-web overridden to alice@host:targetPort),
	//    rather than self-looping into ops@host:bastionPort!
	client, err := connector.Connect(ctx, "saved-web")
	if err != nil {
		t.Fatalf("connector.Connect(saved-web): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if got := bastionSrv.Authenticated.Load(); got != 1 {
		t.Errorf("bastionSrv.Authenticated = %d, want 1 (must not self-loop into bastion port)", got)
	}
	if got := targetSrv.Authenticated.Load(); got != 1 {
		t.Errorf("targetSrv.Authenticated = %d, want 1 (must dial overridden SessionAuth.Port)", got)
	}
	if client.Config().Port != int(targetPort) || client.Config().User != "alice" {
		t.Errorf("connected client.Config() = (port=%d user=%q), want (port=%d user=%q)",
			client.Config().Port, client.Config().User, targetPort, "alice")
	}

	// 3. ResolveSecret / validateSecretRequestSnapshot must validate against overridden
	//    effectivePort/effectiveUser while keeping basePort for observedBaseHost checks.
	assertW14cSecretSnapshotValidation(t, prov, adp, bastionHost, bastionPort, targetPort)
}

func assertW14cSecretSnapshotValidation(
	t *testing.T,
	prov config.ConfigProvider,
	adp *SSHAdapter,
	bastionHost string,
	bastionPort, targetPort uint16,
) {
	t.Helper()

	sec, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID: "saved-web",
		Kind:   ssh.SecretKindLoginPassword,
		Host:   bastionHost,
		Port:   int(targetPort),
		User:   "alice",
	})
	if err != nil || string(sec) != sshfixture.Password {
		t.Fatalf("ResolveSecret(overridden port/user) = (%q, %v), want password", string(sec), err)
	}

	// Stale base port or stale base user must be rejected with ErrSnapshotMismatch.
	if _, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID: "saved-web",
		Kind:   ssh.SecretKindLoginPassword,
		Host:   bastionHost,
		Port:   int(bastionPort),
		User:   "alice",
	}); !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Errorf("ResolveSecret(stale base port %d) = %v, want ErrSnapshotMismatch", bastionPort, err)
	}
	if _, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID: "saved-web",
		Kind:   ssh.SecretKindLoginPassword,
		Host:   bastionHost,
		Port:   int(targetPort),
		User:   "ops",
	}); !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Errorf("ResolveSecret(stale base user ops) = %v, want ErrSnapshotMismatch", err)
	}

	// Combined HostName + Port + User override checks observedBaseHost against snapshot base host/port.
	snap, err := prov.ResolveConnection("saved-web")
	if err != nil {
		t.Fatalf("ResolveConnection(saved-web): %v", err)
	}
	combinedOverride := SessionAuth{HostName: "10.240.0.99", Port: targetPort, User: "alice"}
	okReq := ssh.SecretRequest{
		NodeID:   "saved-web",
		Kind:     ssh.SecretKindLoginPassword,
		Host:     "10.240.0.99",
		BaseHost: bastionHost,
		Port:     int(targetPort),
		User:     "alice",
	}
	if err := validateSecretRequestSnapshotWithState(snap, true, combinedOverride, okReq.BaseHost, okReq); err != nil {
		t.Errorf("validateSecretRequestSnapshotWithState(valid HostName+Port+User) = %v, want nil", err)
	}
	if err := validateSecretRequestSnapshotWithState(snap, true, combinedOverride, "10.240.0.88", okReq); !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Errorf("validateSecretRequestSnapshotWithState(changed BaseHost) = %v, want ErrSnapshotMismatch", err)
	}
}

func TestP7W14c_L3_14_M2_HostNameOverrideCycleAndDistinctHostParity(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	const sshCfg = `
Host web
    HostName 10.235.0.1
    Port 22
    User ops

Host short
    User ops

Host short.corp.example.com
    HostName 10.235.0.1
    Port 22
    User ops
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.235.0.10", Port: 22})
	cfg.Hosts.Set("h-app", models.Host{Address: "10.235.0.20", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-app", models.Node{HostRef: "h-app", IdentityRef: "id-ops"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)
	noSnapProv := w13cNoSnapshotProvider{ConfigProvider: prov}

	muxOpts, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-w14c-%r@%h:%p-%j"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	// 1. Control-plane fail-open fixed: -o HostName=10.235.0.10 -J saved-bastion saved-app
	//    must fail closed with *ssh.ProxyCycleError in both ResolveControlTarget and ResolveControlSocketPath.
	var cycleErr *ssh.ProxyCycleError
	cycleCtrlReq := ControlTargetRequest{
		Provider:                 prov,
		Target:                   config.ConnectionTarget{Selector: "saved-app", ProxyJump: "saved-bastion", HasProxyJump: true},
		ApplyTargetNodeOverrides: true,
		OverrideExpandedHost:     "10.235.0.10",
		SessionControl:           muxOpts,
		Environment:              &env,
	}
	if _, err := ResolveControlTarget(cycleCtrlReq); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlTarget(saved-app -o HostName=10.235.0.10 -J saved-bastion) = %v, want *ssh.ProxyCycleError", err)
	}
	if _, _, err := ResolveControlSocketPath(cycleCtrlReq); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlSocketPath(saved-app -o HostName=10.235.0.10 -J saved-bastion) = %v, want *ssh.ProxyCycleError", err)
	}

	// 2. Control-plane SessionAuth.HostName propagation on distinct host override (and OpenSSH distinct host allowed).
	okCtrlReq := ControlTargetRequest{
		Provider:                 prov,
		NodeID:                   "openssh:web",
		Target:                   config.ConnectionTarget{Selector: "openssh:web", ProxyJump: "openssh:web", HasProxyJump: true},
		ApplyTargetNodeOverrides: true,
		OverrideExpandedHost:     "[2001:db8::99]",
		SessionControl:           muxOpts,
		Environment:              &env,
	}
	sock, res, err := ResolveControlSocketPath(okCtrlReq)
	if err != nil || sock == "" || res.SessionAuth.HostName != "2001:db8::99" {
		t.Fatalf("ResolveControlSocketPath(openssh:web -o HostName=[2001:db8::99] -J openssh:web) = (sock=%q host=%q err=%v), want valid socket and HostName=2001:db8::99",
			sock, res.SessionAuth.HostName, err)
	}

	// Same host override on openssh:web (10.235.0.1) must still fail closed.
	sameHostCtrlReq := okCtrlReq
	sameHostCtrlReq.OverrideExpandedHost = "10.235.0.1"
	if _, _, err := ResolveControlSocketPath(sameHostCtrlReq); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlSocketPath(openssh:web -o HostName=10.235.0.1 -J openssh:web) = %v, want *ssh.ProxyCycleError", err)
	}

	// 3. Policy solver (both hasSnapshot and !hasSnapshot):
	//    - Distinct HostName override clears OpenSSH alias identity and succeeds.
	//    - Same HostName or HostName colliding with saved-bastion fails closed.
	for _, tc := range []struct {
		name     string
		provider config.ConfigProvider
		nodeID   string
		auth     SessionAuth
		wantErr  bool
	}{
		{"hasSnap_openssh_distinct_host_allowed", prov, "openssh:web", SessionAuth{HostName: "10.235.0.99", ProxyJump: "openssh:web"}, false},
		{"noSnap_openssh_distinct_host_allowed", noSnapProv, "openssh:web", SessionAuth{HostName: "10.235.0.99", ProxyJump: "openssh:web"}, false},
		{"hasSnap_openssh_same_host_cycle", prov, "openssh:web", SessionAuth{HostName: "10.235.0.1", ProxyJump: "openssh:web"}, true},
		{"noSnap_openssh_same_host_cycle", noSnapProv, "openssh:web", SessionAuth{HostName: "10.235.0.1", ProxyJump: "openssh:web"}, true},
		{"hasSnap_openssh_override_to_saved_bastion_cycle", prov, "openssh:web", SessionAuth{HostName: "10.235.0.10", ProxyJump: "saved-bastion"}, true},
		{"noSnap_openssh_override_to_saved_bastion_cycle", noSnapProv, "openssh:web", SessionAuth{HostName: "10.235.0.10", ProxyJump: "saved-bastion"}, true},
		{"hasSnap_saved_app_override_to_saved_bastion_cycle", prov, "saved-app", SessionAuth{HostName: "10.235.0.10", ProxyJump: "saved-bastion"}, true},
		// Two-pass CanonicalizeHostname alias cycle without HostName override must still fail closed.
		{"twopass_canonical_alias_cycle_preserved", prov, "unlisted-node", SessionAuth{OriginalHost: "short", CanonicalHost: "short.corp.example.com", ProxyJump: "openssh:short"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			adp := NewSSHAdapter(tc.provider, WithSessionAuthOverride(tc.nodeID, tc.auth))
			pol, pErr := adp.Resolve(t.Context(), ResolveRequest{NodeID: tc.nodeID, ResolveProxy: true})
			var ce *ssh.ProxyCycleError
			if tc.wantErr {
				if !errors.As(pErr, &ce) {
					t.Errorf("SSHAdapter.Resolve(%s) = %v, want *ssh.ProxyCycleError", tc.name, pErr)
				}
				return
			}
			if pErr != nil || pol.EffectiveJump() != tc.auth.ProxyJump {
				t.Errorf("SSHAdapter.Resolve(%s) = (jump=%q, err=%v), want %q", tc.name, pol.EffectiveJump(), pErr, tc.auth.ProxyJump)
			}
		})
	}
}

func TestP7W14c_L3_14_M3_NilProviderAndNoSnapshotSavedAliasOverrides(t *testing.T) {
	t.Parallel()

	env := w10cTestEnv()
	muxOpts, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-w14c-nil-%r@%h:%p-%j"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	// 1. Provider == nil parity between ResolveControlSocketPath and ResolveControlConfig.
	nilCases := []struct {
		name      string
		nodeID    string
		selector  string
		auth      SessionAuth
		wantCycle bool
	}{
		{"openssh_port_2222_allowed", "openssh:web", "openssh:web", SessionAuth{Port: 2222, ProxyJump: "openssh:web"}, false},
		{"direct_port_2222_allowed", "alice@10.235.0.1:22", "alice@10.235.0.1:22", SessionAuth{Port: 2222, ProxyJump: "alice@10.235.0.1:22"}, false},
		{"direct_user_bob_allowed", "alice@10.235.0.1:22", "alice@10.235.0.1:22", SessionAuth{User: "bob", ProxyJump: "alice@10.235.0.1:22"}, false},
		{"openssh_distinct_host_allowed", "openssh:web", "openssh:web", SessionAuth{HostName: "10.235.0.99", ProxyJump: "openssh:web"}, false},
		{"openssh_port_2222_true_cycle", "openssh:web", "openssh:web", SessionAuth{Port: 2222, ProxyJump: "openssh:web:2222"}, true},
		{"direct_port_2222_true_cycle", "alice@10.235.0.1:22", "alice@10.235.0.1:22", SessionAuth{Port: 2222, ProxyJump: "alice@10.235.0.1:2222"}, true},
		{"direct_same_port_22_true_cycle", "alice@10.235.0.1:22", "alice@10.235.0.1:22", SessionAuth{Port: 22, ProxyJump: "alice@10.235.0.1:22"}, true},
		{"direct_host_override_true_cycle", "alice@10.235.0.1:22", "alice@10.235.0.1:22", SessionAuth{HostName: "10.235.0.10", ProxyJump: "alice@10.235.0.10:22"}, true},
	}
	for _, tc := range nilCases {
		t.Run("nil_provider_"+tc.name, func(t *testing.T) {
			t.Parallel()
			req := ControlTargetRequest{
				Provider: nil,
				NodeID:   tc.nodeID,
				Target: config.ConnectionTarget{
					Selector:     tc.selector,
					User:         tc.auth.User,
					HasUser:      tc.auth.User != "",
					Port:         tc.auth.Port,
					HasPort:      tc.auth.Port > 0,
					ProxyJump:    tc.auth.ProxyJump,
					HasProxyJump: true,
				},
				ApplyTargetNodeOverrides: tc.auth.HostName != "",
				OverrideExpandedHost:     tc.auth.HostName,
				SessionControl:           muxOpts,
				Environment:              &env,
			}
			sock, _, sockErr := ResolveControlSocketPath(req)
			ctrl, ctrlErr := ResolveControlConfig(nil, tc.nodeID, tc.selector, tc.auth, SessionControlOptions{})
			ctrlMux, ctrlMuxErr := ResolveControlConfig(nil, tc.nodeID, tc.selector, tc.auth, muxOpts)

			var ce *ssh.ProxyCycleError
			if tc.wantCycle {
				if !errors.As(sockErr, &ce) {
					t.Errorf("ResolveControlSocketPath(nil, %s) = %v, want *ssh.ProxyCycleError", tc.name, sockErr)
				}
				if !errors.As(ctrlErr, &ce) {
					t.Errorf("ResolveControlConfig(nil, empty opts, %s) = %v, want *ssh.ProxyCycleError", tc.name, ctrlErr)
				}
				if !errors.As(ctrlMuxErr, &ce) {
					t.Errorf("ResolveControlConfig(nil, mux opts, %s) = %v, want *ssh.ProxyCycleError", tc.name, ctrlMuxErr)
				}
				return
			}
			if sockErr != nil || sock == "" {
				t.Errorf("ResolveControlSocketPath(nil, %s) = (%q, %v), want non-empty socket", tc.name, sock, sockErr)
			}
			if ctrlErr != nil || ctrl != nil {
				t.Errorf("ResolveControlConfig(nil, empty opts, %s) = (%+v, %v), want (nil, nil)", tc.name, ctrl, ctrlErr)
			}
			if ctrlMuxErr != nil || !ctrlMux.IsEnabled() {
				t.Errorf("ResolveControlConfig(nil, mux opts, %s) = (%+v, %v), want enabled ControlConfig", tc.name, ctrlMux, ctrlMuxErr)
			}
		})
	}

	// 2. !hasSnapshot saved-node alias NodeIDs with Port/User/HostName overrides.
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-web-22", models.Host{Address: "10.235.0.1", Port: 22})
	cfg.Hosts.Set("h-web-2222", models.Host{Address: "10.235.0.1", Port: 2222})
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.235.0.10", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Identities.Set("id-alice", models.Identity{User: "alice", AuthType: "auto"})
	cfg.Nodes.Set("node-1", models.Node{HostRef: "h-web-22", IdentityRef: "id-ops", Alias: []string{"web-alias"}})
	cfg.Nodes.Set("saved-2222", models.Node{HostRef: "h-web-2222", IdentityRef: "id-ops"})
	cfg.Nodes.Set("saved-alice", models.Node{HostRef: "h-web-22", IdentityRef: "id-alice"})
	cfg.Nodes.Set("saved-bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops"})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	aliasCases := []struct {
		name      string
		auth      SessionAuth
		wantJump  string
		wantCycle bool
	}{
		{"port_2222_via_self_alias_allowed", SessionAuth{Port: 2222, ProxyJump: "web-alias"}, "node-1", false},
		{"user_alice_via_self_alias_allowed", SessionAuth{User: "alice", ProxyJump: "web-alias"}, "node-1", false},
		{"host_override_via_self_alias_allowed", SessionAuth{HostName: "10.235.0.99", ProxyJump: "web-alias"}, "node-1", false},
		{"same_port_22_via_self_alias_cycle", SessionAuth{Port: 22, ProxyJump: "web-alias"}, "", true},
		{"same_user_ops_via_self_alias_cycle", SessionAuth{User: "ops", ProxyJump: "web-alias"}, "", true},
		{"port_2222_via_saved_2222_cycle", SessionAuth{Port: 2222, ProxyJump: "saved-2222"}, "", true},
		{"user_alice_via_saved_alice_cycle", SessionAuth{User: "alice", ProxyJump: "saved-alice"}, "", true},
		{"host_override_via_saved_bastion_cycle", SessionAuth{HostName: "10.235.0.10", ProxyJump: "saved-bastion"}, "", true},
	}
	for _, tc := range aliasCases {
		t.Run("saved_alias_"+tc.name, func(t *testing.T) {
			t.Parallel()
			adp := NewSSHAdapter(prov, WithSessionAuthOverride("web-alias", tc.auth))
			pol, pErr := adp.Resolve(t.Context(), ResolveRequest{NodeID: "web-alias", ResolveProxy: true})
			var ce *ssh.ProxyCycleError
			if tc.wantCycle {
				if !errors.As(pErr, &ce) {
					t.Errorf("SSHAdapter.Resolve(web-alias, %s) = %v, want *ssh.ProxyCycleError", tc.name, pErr)
				}
				return
			}
			if pErr != nil || pol.EffectiveJump() != tc.wantJump {
				t.Errorf("SSHAdapter.Resolve(web-alias, %s) = (jump=%q, err=%v), want %q", tc.name, pol.EffectiveJump(), pErr, tc.wantJump)
			}
		})
	}
}

func TestP7W14c_L3_14_L1_FormatOverriddenOpenSSHHostNamedOpenSSH(t *testing.T) {
	t.Parallel()

	formatted := formatOverriddenOpenSSHNodeID("openssh:openssh", "openssh", "", 2222)
	if strings.HasPrefix(strings.ToLower(formatted), "openssh:openssh:") {
		t.Fatalf("formatOverriddenOpenSSHNodeID produced invalid double-prefixed selector %q", formatted)
	}
	ref, err := config.ParseTargetRef(formatted)
	if err != nil {
		t.Fatalf("ParseTargetRef(%q) failed: %v", formatted, err)
	}
	if err := ref.Validate(); err != nil {
		t.Fatalf("ref.Validate(%q) failed: %v", formatted, err)
	}
	if !ref.OpenSSH || ref.Host != "openssh" || !ref.HasPort || ref.Port != 2222 || ref.User == "" {
		t.Fatalf("unexpected parsed TargetRef for %q: %+v", formatted, ref)
	}

	// End-to-end !hasSnapshot Resolve on "openssh:openssh" (Host openssh without User) with Port: 2222
	// must succeed when jumping via "openssh:openssh" (port 22) and fail closed on the exact overridden target.
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host openssh\n  HostName 10.235.0.5\n  Port 22\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	noSnapWithOpenSSH := w13cNoSnapshotProvider{
		ConfigProvider: config.NewProviderWithOpenSSHParser(config.NewProviderWithoutOpenSSH(nil).Snapshot(), parser),
	}
	adpAllow := NewSSHAdapter(noSnapWithOpenSSH, WithSessionAuthOverride("openssh:openssh", SessionAuth{
		Port:      2222,
		ProxyJump: "openssh:openssh",
	}))
	pol, err := adpAllow.Resolve(t.Context(), ResolveRequest{NodeID: "openssh:openssh", ResolveProxy: true})
	if err != nil || pol.EffectiveJump() != "openssh:openssh" {
		t.Fatalf("SSHAdapter.Resolve(openssh:openssh + Port 2222 via openssh:openssh) = (jump=%q, err=%v), want openssh:openssh",
			pol.EffectiveJump(), err)
	}

	var cycleErr *ssh.ProxyCycleError
	adpCycle := NewSSHAdapter(noSnapWithOpenSSH, WithSessionAuthOverride("openssh:openssh", SessionAuth{
		Port:      2222,
		ProxyJump: formatted,
	}))
	if _, err := adpCycle.Resolve(t.Context(), ResolveRequest{NodeID: "openssh:openssh", ResolveProxy: true}); !errors.As(err, &cycleErr) {
		t.Errorf("SSHAdapter.Resolve(openssh:openssh + Port 2222 via %q) = %v, want *ssh.ProxyCycleError", formatted, err)
	}

	// Nil-provider ResolveControlConfig on "openssh:openssh" + Port: 2222 also succeeds without invalid double-prefix.
	if ctrl, err := ResolveControlConfig(nil, "openssh:openssh", "openssh:openssh", SessionAuth{Port: 2222, ProxyJump: "openssh:openssh"}, SessionControlOptions{}); err != nil || ctrl != nil {
		t.Errorf("ResolveControlConfig(nil, openssh:openssh + Port 2222) = (%+v, %v), want (nil, nil)", ctrl, err)
	}
	if _, err := ResolveControlConfig(nil, "openssh:openssh", "openssh:openssh", SessionAuth{Port: 2222, ProxyJump: formatted}, SessionControlOptions{}); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlConfig(nil, openssh:openssh + Port 2222 via %q) = %v, want *ssh.ProxyCycleError", formatted, err)
	}
}
