package mcphost

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestP7W7c_DEF7M4_MCPRejectsDoubleOpenSSHPrefixAndCaseVariants(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host openssh",
		"  HostName 10.99.0.1",
		"  User ops",
		"  Port 22",
		"",
		"Host web",
		"  HostName 10.99.0.2",
		"  User fixture",
		"  Port 2222",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := runtimeTestProvider("node").Snapshot()
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)
	h := newHost(Config{Provider: prov})

	rejected := []string{
		"openssh:openssh:22",
		"openssh:OPENSSH:22",
		"openssh:openssh:0022",
		"openssh:openssh:web",
		"OPENSSH:openssh:22",
		"OpenSSH:web",
		"OPENSSH:web",
		"openssh:",
		"openssh:web:65536",
		"openssh:web:0022",
	}

	for _, sel := range rejected {
		if got, err := resolveSelector(prov, sel); err == nil {
			t.Errorf("resolveSelector(%q) unexpectedly succeeded with %q, want fail-closed error", sel, got)
		}
		if got, err := canonicalizeOpenSSHSelector(prov, sel); err == nil {
			// Note: "OpenSSH:web" and "OPENSSH:web" are rejected by resolveSelector's lowercase
			// prefix check, while malformed/double-prefixed specs are rejected by canonicalizeOpenSSHSelector itself.
			if sel != "OpenSSH:web" && sel != "OPENSSH:web" {
				t.Errorf("canonicalizeOpenSSHSelector(%q) unexpectedly succeeded with %q, want fail-closed error", sel, got)
			}
		}
		if _, err := h.Resolve(t.Context(), ports.ResolveRequest{Selectors: []string{sel}}); err == nil {
			t.Errorf("host.Resolve(%q) unexpectedly succeeded, want fail-closed error", sel)
		}
	}

	// Leading-zero detection must treat uppercase OPENSSH: case-insensitively.
	upperRef, err := config.ParseTargetRef("OPENSSH:web:0022")
	if err != nil {
		t.Fatalf("ParseTargetRef(OPENSSH:web:0022): %v", err)
	}
	if !hasLeadingZeroPortInOpenSSHSpec("OPENSSH:web:0022", upperRef) {
		t.Fatal("hasLeadingZeroPortInOpenSSHSpec failed to detect leading-zero port on uppercase OPENSSH: prefix")
	}

	// Valid single-prefixed host named "openssh" and user-qualified non-default port must round-trip cleanly.
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"openssh:openssh", "openssh:openssh"},
		{"openssh:ops@openssh", "openssh:openssh"},
		{"openssh:ops@openssh:22", "openssh:openssh"},
		{"openssh:ops@openssh:2222", "openssh:ops@openssh:2222"},
		{"openssh:web", "openssh:web"},
	} {
		got, err := resolveSelector(prov, tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("resolveSelector(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
		if _, parseErr := config.ParseTargetRef(got); parseErr != nil {
			t.Fatalf("canonicalized selector %q failed ParseTargetRef round-trip: %v", got, parseErr)
		}
	}
}
