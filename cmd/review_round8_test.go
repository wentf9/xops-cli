package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound8_P2_15_ControlProxyAndLookupAtomicOriginNoChimera(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host app-a",
		"  HostName 10.95.0.1",
		"  User ops",
		"",
		"Host app-a.corp.example.com",
		"  HostName 10.95.0.1",
		"  User ops",
		"  ServerAliveInterval 44",
		"",
		"Host app-b",
		"  HostName 10.95.0.1",
		"  User ops",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.95.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-shared", models.Node{HostRef: "h1", IdentityRef: "id1"})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)
	prov.SetNodeOpenSSHOrigin("saved-shared", config.OpenSSHOrigin{
		Alias:         "app-a",
		CanonicalHost: "app-a.corp.example.com",
	})

	// 1. buildControlProxyAdapterOptionsWithLookup: when o.originalHost is preset to "app-b"
	// while lookupAuth carries ("app-a", "app-a.corp.example.com"), MUST NOT synthesize chimera
	// ("app-b", "app-a.corp.example.com").
	o := &SshOptions{originalHost: "app-b"}
	adpOpts := buildControlProxyAdapterOptionsWithLookup(
		cfg, "saved-shared", "saved-shared",
		adapter.SessionAuth{OriginalHost: "app-a", CanonicalHost: "app-a.corp.example.com"},
		o,
	)
	adp := adapter.NewSSHAdapter(prov, adpOpts...)
	clientCfg, err := adp.GetConfig("saved-shared")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if clientCfg.OriginalHost != "app-b" {
		t.Fatalf("OriginalHost = %q, want app-b", clientCfg.OriginalHost)
	}
	if clientCfg.CanonicalHost != "" {
		t.Fatalf("chimera leaked CanonicalHost = %q from app-a onto app-b", clientCfg.CanonicalHost)
	}

	// 2. resolveSavedControlSessionLookup first branch: non-canonicalized alias "app-b"
	// with explicit port matching "saved-shared" MUST replace stale snap.Node.CanonicalHost with "".
	key, auth, handled, _ := resolveSavedControlSessionLookup(
		prov, "saved-shared", "saved-shared",
		config.ConnectionTarget{Selector: "app-b", Port: 22, HasPort: true},
		"", "", "app-b", "",
	)
	if !handled || key != "saved-shared" {
		t.Fatalf("resolveSavedControlSessionLookup #1 = (%q, %+v, %v), want handled saved-shared", key, auth, handled)
	}
	if auth.OriginalHost != "app-b" || auth.CanonicalHost != "" {
		t.Fatalf("first branch leaked stale origin: got (%q, %q), want (\"app-b\", \"\")", auth.OriginalHost, auth.CanonicalHost)
	}

	// 3. resolveSavedControlSessionLookup second branch: when origHost is explicitly set without
	// canonHost (non-canonicalized session), MUST NOT inherit resolved.CanonicalHost.
	_, auth2, handled2, _ := resolveSavedControlSessionLookup(
		prov, "", "openssh:app-b",
		config.ConnectionTarget{Selector: "saved-shared"},
		"app-b", "", "app-b", "",
	)
	if !handled2 {
		t.Fatal("expected second branch to resolve saved-shared")
	}
	if auth2.CanonicalHost != "" {
		t.Fatalf("second branch leaked CanonicalHost = %q onto non-canonicalized origHost=app-b", auth2.CanonicalHost)
	}
}

func TestRound8_P3_5_MuxDaemonSpecValidateAndLiteralControlSocketPath(t *testing.T) {
	t.Parallel()

	// MuxDaemonSpec.Validate rejects control characters and overlong literal paths.
	badCtrl := MuxDaemonSpec{
		Version:            muxDaemonSpecVersion,
		TargetHost:         "app",
		ControlPath:        "/tmp/bad\rsock",
		ControlPathLiteral: true,
		ControlMaster:      ssh.ControlMasterYes,
	}
	if err := badCtrl.Validate(); err == nil {
		t.Fatal("MuxDaemonSpec.Validate accepted literal ControlPath with CR")
	}
	tooLong := MuxDaemonSpec{
		Version:            muxDaemonSpecVersion,
		TargetHost:         "app",
		ControlPath:        "/" + strings.Repeat("a", ssh.MaxControlPathLength()+10),
		ControlPathLiteral: true,
		ControlMaster:      ssh.ControlMasterYes,
	}
	if err := tooLong.Validate(); err == nil {
		t.Fatal("MuxDaemonSpec.Validate accepted overlong literal ControlPath")
	}

	// expandControlSocketPath must NOT TrimSpace a literal ControlPath (so leading/trailing CR fails closed).
	var stderr bytes.Buffer
	o := &SshOptions{
		control: SSHControlFlags{
			ControlPath:        "\r/tmp/literal.sock",
			controlPathLiteral: true,
		},
	}
	if _, err := expandControlSocketPath(o, nil, "node", ssh.TargetContext{Host: "10.0.0.1"}, &stderr); err == nil {
		t.Fatal("expandControlSocketPath trimmed leading CR from literal ControlPath instead of rejecting")
	}

	// expandControlSocketPath with literal valid path containing spaces preserves exact spaces.
	stderr.Reset()
	oSpace := &SshOptions{
		control: SSHControlFlags{
			ControlPath:        "/tmp/sock with space ",
			controlPathLiteral: true,
		},
	}
	got, err := expandControlSocketPath(oSpace, nil, "node", ssh.TargetContext{Host: "10.0.0.1"}, &stderr)
	if err != nil {
		t.Fatalf("expandControlSocketPath(literal with trailing space): %v", err)
	}
	if got != "/tmp/sock with space " {
		t.Fatalf("expandControlSocketPath trimmed literal path: got %q, want %q", got, "/tmp/sock with space ")
	}
}
