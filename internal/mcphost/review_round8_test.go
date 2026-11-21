package mcphost

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestRound8_P1_3_P2_6_CanonicalOpenSSHSelectorAndPolicyBypassPrevention(t *testing.T) {
	f := tunnelOpenSSHFixture(t, &corepolicy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDeny,
		NodeOverrides: map[string]corepolicy.NodeConfig{
			// Policy ONLY names canonical "openssh:web".
			"openssh:web": {ApprovalThreshold: "safe"},
		},
	})
	h := newHost(Config{Provider: f.provider})
	_, webHost, _, err := f.provider.Resolve("openssh:web")
	if err != nil {
		t.Fatalf("Resolve(openssh:web): %v", err)
	}
	webPort := webHost.Port

	// 1. Redundant explicit default user/port variants MUST collapse to "openssh:web".
	for _, variant := range []string{
		"openssh:fixture@web",
		fmt.Sprintf("openssh:web:%d", webPort),
		fmt.Sprintf("openssh:fixture@web:%d", webPort),
	} {
		got, err := resolveTestNode(t.Context(), h, variant)
		if err != nil || got != "openssh:web" {
			t.Fatalf("resolveTestNode(%q) = (%q, %v), want (\"openssh:web\", nil)", variant, got, err)
		}
	}

	// 2. Leading-zero ports, case-variant OpenSSH prefixes, U+2028/U+2029, and interior whitespace
	// around @/: on non-exact selectors MUST be rejected.
	for _, rejected := range []string{
		fmt.Sprintf("openssh:web:0%d", webPort),
		"openssh:web:0022",
		"OpenSSH:web",
		"OPENSSH:web",
		"openssh:web\u2028",
		"openssh:web\u2029",
		"web\u2028",
		"web\u2029",
		"ops @web",
		"ops@ web",
		"web :22",
	} {
		if got, err := resolveSelector(f.provider, rejected); err == nil {
			t.Fatalf("resolveSelector(%q) unexpectedly succeeded with %q", rejected, got)
		}
	}

	// 3. IPv6 literals and non-concrete DNS hostnames canonicalize cleanly.
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"openssh:[2001:0DB8::1]", "openssh:2001:db8::1"},
		{"openssh:[2001:0DB8::1]:22", "openssh:2001:db8::1"},
		{"openssh:[2001:0DB8::1]:2222", "openssh:[2001:db8::1]:2222"},
		{"openssh:PROD.EXAMPLE.COM", "openssh:prod.example.com"},
		{"openssh:prod.example.com.", "openssh:prod.example.com"},
		{"PROD.EXAMPLE.COM", "openssh:prod.example.com"},
		{"prod.example.com.", "openssh:prod.example.com"},
	} {
		got, err := resolveSelector(f.provider, tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("resolveSelector(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
	}

	// 4. End-to-end tunnel policy test: redundant default user/port & leading-zero variants
	// MUST NOT bypass NodeOverrides["openssh:web"].
	r := newTunnelRuntime(t, f)
	client := tunnelListPolicyClient(t, r, "2026-07-28", nil)
	target := startTunnelEcho(t)
	for i, nodeID := range []string{
		"openssh:fixture@web",
		fmt.Sprintf("openssh:web:%d", webPort),
		fmt.Sprintf("openssh:fixture@web:%d", webPort),
		fmt.Sprintf("openssh:web:0%d", webPort),
		"OpenSSH:web",
	} {
		input := tunnelTestInput(t, target, "local", fmt.Sprintf("r8-bypass-%d", i))
		input.NodeID = nodeID
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "tunnel", Arguments: input})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatalf("node %q bypassed NodeOverrides[\"openssh:web\"]: %+v", nodeID, result.StructuredContent)
		}
	}
	if f.server.Forwards.Load() != 0 {
		t.Fatal("denied variant opened a forward")
	}
}

func TestRound8_P2_5_P3_3_ExpandMCPBindingPathAnd3HopJumpAndTruncatedCert(t *testing.T) {
	t.Parallel()

	// P2-5: expandMCPBindingPath delegates to ssh.ExpandIdentityPath (trims env var spaces, works with HomeDir=="", fails closed on unset var).
	env := ssh.Environment{
		HomeDir: "",
		LookupEnv: func(k string) (string, bool) {
			if k == "CERT_FILE" {
				return "  /etc/ssh/user-cert.pub  ", true
			}
			return "", false
		},
	}
	target := ssh.TargetContext{Host: "app.example.com", Port: 22, User: "ops"}
	if got := expandMCPBindingPath("${CERT_FILE}", env, target); got != filepath.Clean("/etc/ssh/user-cert.pub") {
		t.Fatalf("expandMCPBindingPath(${CERT_FILE}) = %q, want %q", got, filepath.Clean("/etc/ssh/user-cert.pub"))
	}
	if got := expandMCPBindingPath("${MISSING_VAR}/cert.pub", env, target); got != "" {
		t.Fatalf("expandMCPBindingPath(unset env) = %q, want empty (fail closed)", got)
	}

	// P3-3: inspectCertificateBinding reads maxMCPCertBindingBytes+1 to set Truncated without stat race.
	dir := t.TempDir()
	exactPath := filepath.Join(dir, "exact.pub")
	overPath := filepath.Join(dir, "over.pub")
	if err := os.WriteFile(exactPath, make([]byte, maxMCPCertBindingBytes), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overPath, make([]byte, maxMCPCertBindingBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	bExact, ok := inspectCertificateBinding(exactPath, true)
	if !ok || bExact.Truncated {
		t.Fatalf("exact-size binding = (%+v, %v), want Truncated=false", bExact, ok)
	}
	bOver, ok := inspectCertificateBinding(overPath, true)
	if !ok || !bOver.Truncated {
		t.Fatalf("over-size binding = (%+v, %v), want Truncated=true", bOver, ok)
	}

	// P3-3: 3-hop chain j1 -> j2 -> target binds CertificateFile containing %j against cumulative upstream chain.
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "j1,j2-cert.pub")
	writeDummyUserCert(t, certFile, 1)

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Guardrail = &corepolicy.Config{Disabled: true}
	cfg.Hosts.Set("h1", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Hosts.Set("h2", models.Host{Address: "192.0.2.2", Port: 22})
	cfg.Hosts.Set("h3", models.Host{Address: "192.0.2.3", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "key"})
	cfg.Nodes.Set("j1", models.Node{HostRef: "h1", IdentityRef: "id1"})
	cfg.Nodes.Set("j2", models.Node{HostRef: "h2", IdentityRef: "id1", ProxyJump: "j1"})
	cfg.Nodes.Set("target", models.Node{
		HostRef:     "h3",
		IdentityRef: "id1",
		ProxyJump:   "j2",
		SSHOptions:  ssh.MustOptions(ssh.OptionCertificateFile, filepath.Join(certDir, "%j-cert.pub")),
	})
	h := credentialBindingHost(cfg, false)
	view1, err := h.Resolve(t.Context(), ports.ResolveRequest{Selectors: []string{"target"}})
	if err != nil {
		t.Fatalf("Resolve(target) #1: %v", err)
	}
	// Mutate the cumulative %j cert file (serial 1 -> 2): credentialVersion MUST change!
	writeDummyUserCert(t, certFile, 2)
	view2, err := h.Resolve(t.Context(), ports.ResolveRequest{Selectors: []string{"target"}})
	if err != nil {
		t.Fatalf("Resolve(target) #2: %v", err)
	}
	if view1.Targets["target"].Version == view2.Targets["target"].Version {
		t.Fatal("credentialVersion did not change when 3-hop cumulative %j CertificateFile mutated")
	}
}

func writeDummyUserCert(t *testing.T, path string, serial uint64) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := cryptoSSH.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := cryptoSSH.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	cert := &cryptoSSH.Certificate{
		Key:         sshPub,
		Serial:      serial,
		CertType:    cryptoSSH.UserCert,
		KeyId:       "test-cert",
		ValidAfter:  1,
		ValidBefore: cryptoSSH.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, cryptoSSH.MarshalAuthorizedKey(cert), 0600); err != nil {
		t.Fatal(err)
	}
}

var _ = strings.Contains
