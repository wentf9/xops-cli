package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W6c_TrimOpenSSHNodePrefixCaseInsensitive(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in       string
		wantRest string
		wantOK   bool
	}{
		{"openssh:alice@bastion:2222", "alice@bastion:2222", true},
		{"OPENSSH:alice@bastion:2222", "alice@bastion:2222", true},
		{"OpenSSH:web", "web", true},
		{"OPENSSH:", "", true},
		{"alice@bastion:2222", "alice@bastion:2222", false},
		{"", "", false},
	}
	for _, tc := range cases {
		gotRest, gotOK := TrimOpenSSHNodePrefix(tc.in)
		if gotRest != tc.wantRest || gotOK != tc.wantOK {
			t.Errorf("TrimOpenSSHNodePrefix(%q) = (%q, %v), want (%q, %v)", tc.in, gotRest, gotOK, tc.wantRest, tc.wantOK)
		}
	}
}

func TestP7W6c_DEF6M1_CanonicalizeHostRejectsControlAndWhitespaceCLIProxyJump(t *testing.T) {
	t.Parallel()

	parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host *\n  CanonicalizeHostname yes\n  CanonicalDomains corp.example\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := NewProviderWithOpenSSHParser(nil, parser)
	res := &fakeCanonicalResolver{hosts: map[string][]string{"web.corp.example": {"10.0.0.1"}}}

	for _, bad := range []string{"none\n", "bastion\n", "\n", "\t", "\r\n", "\u0085", "   "} {
		if _, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:     prov,
			Host:         "web",
			CLIProxyJump: bad,
			Resolver:     res,
		}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("CanonicalizeHost(CLIProxyJump=%q) err = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}

	got, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
		Provider:     prov,
		Host:         "web",
		CLIProxyJump: "",
		Resolver:     res,
	})
	if err != nil || !got.Canonicalized || got.CanonicalHost != "web.corp.example" {
		t.Fatalf("CanonicalizeHost(empty CLIProxyJump) = (%+v, %v), want canonicalized web.corp.example", got, err)
	}
}

func TestP7W6c_DEF6M3_ImportOpenSSHAndResolveProxyJumpChain(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host bastion
    HostName 10.0.0.1
    User ops

Host app
    HostName 10.0.0.2
    User root
    ProxyJump alice@bastion
`
	hosts, err := ParseOpenSSHHosts(strings.NewReader(sshCfg), "ops")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts: %v", err)
	}
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "xops.yaml"), filepath.Join(dir, "xops.key"))
	repo, err := NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	if _, err := repo.ImportOpenSSHHostsContext(t.Context(), hosts); err != nil {
		t.Fatalf("ImportOpenSSHHostsContext: %v", err)
	}

	appNode, ok := repo.GetNode("app")
	if !ok || appNode.ProxyJump != "alice@bastion" {
		t.Fatalf("imported app node = (%+v, %v), want ProxyJump=alice@bastion", appNode, ok)
	}
	resolved, err := repo.ResolveProxyJumpChain(appNode.ProxyJump)
	if err != nil {
		t.Fatalf("ResolveProxyJumpChain(alice@bastion): %v", err)
	}
	if resolved != "openssh:alice@10.0.0.1:22" {
		t.Fatalf("ResolveProxyJumpChain(alice@bastion) = %q, want openssh:alice@10.0.0.1:22", resolved)
	}

	// Saved node alias resolution.
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{
		HostRef:     "h-bastion",
		IdentityRef: "id-ops",
		Alias:       []string{"bastion"},
	})
	prov := NewProviderWithoutOpenSSH(cfg)
	gotAlias, err := prov.ResolveProxyJumpChain("bastion")
	if err != nil || gotAlias != "ops@10.0.0.1:22" {
		t.Fatalf("ResolveProxyJumpChain(bastion) = (%q, %v), want (ops@10.0.0.1:22, nil)", gotAlias, err)
	}
}
