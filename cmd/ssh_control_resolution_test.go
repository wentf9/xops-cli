package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
)

const controlResolutionConfig = `schema_version: 2
control:
  master: auto
  path: "%s"
nodes:
  web-01:
    host_ref: host-web-01
    identity_ref: id-web-01
    sudo_mode: none
hosts:
  host-web-01:
    address: 10.20.30.40
    port: 2222
identities:
  id-web-01:
    user: deploy
    auth_type: auto
`

// writeControlTestConfig installs a schema v2 configuration in a temporary
// XOPS_CONFIG_DIR and returns the expected expanded control path.
func writeControlTestConfig(t *testing.T, pattern string) string {
	t.Helper()
	directory := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", directory)

	expanded, err := ssh.ExpandControlPath(pattern, sshenv.Discover(), ssh.TargetContext{
		Host: "10.20.30.40",
		Port: 2222,
		User: "deploy",
	})
	if err != nil {
		t.Fatalf("ExpandControlPath failed: %v", err)
	}
	content := fmt.Sprintf(controlResolutionConfig, pattern)
	if err := os.WriteFile(filepath.Join(directory, "xops_config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}
	return expanded
}

// TestControlCommandExpandsResolvedTargetTokens verifies that -O expands %h/%p/%r
// from the resolved node instead of the raw CLI fields. A mismatch silently
// targets a socket the master never created.
func TestControlCommandExpandsResolvedTargetTokens(t *testing.T) {
	pattern := "~/.ssh/cm-%r@%h:%p-%C"
	expected := writeControlTestConfig(t, pattern)

	var stderr bytes.Buffer
	options := &SshOptions{
		Host: "web-01",
		Target: config.ConnectionTarget{
			Selector: "web-01",
		},
		control: SSHControlFlags{CtlCmd: "check"},
	}

	path, err := resolveControlSocketPath(context.Background(), options, &stderr)
	if err != nil {
		t.Fatalf("resolveControlSocketPath failed: %v", err)
	}
	if path != expected {
		t.Fatalf("expected resolved control path %q, got %q", expected, path)
	}
	if strings.Contains(path, "web-01") {
		t.Fatalf("control path %q still contains the node selector instead of the resolved host", path)
	}
}

// TestControlCommandDoesNotPersistNodes verifies that a read-only -O query never
// creates or rewrites configuration entries.
func TestControlCommandDoesNotPersistNodes(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", directory)

	configPath := filepath.Join(directory, "xops_config.yaml")
	original := `schema_version: 2
nodes: {}
hosts: {}
identities: {}
`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	var stderr bytes.Buffer
	options := &SshOptions{
		Host: "unconfigured-host",
		Target: config.ConnectionTarget{
			Selector: "unconfigured-host",
		},
		control: SSHControlFlags{CtlCmd: "check"},
	}

	if _, err := resolveControlSocketPath(context.Background(), options, &stderr); err == nil {
		t.Fatal("expected a missing ControlPath error")
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config failed: %v", err)
	}
	if string(after) != original {
		t.Fatalf("-O mutated the configuration file:\n%s", after)
	}
}

// TestControlCommandAmbiguousSelectorFails verifies that selector ambiguity is
// reported as an error instead of silently resolving to an empty node.
func TestControlCommandAmbiguousSelectorFails(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", directory)
	content := `schema_version: 2
nodes:
  node-a:
    alias: [shared]
    host_ref: host-a
    identity_ref: id
    sudo_mode: none
  node-b:
    alias: [shared]
    host_ref: host-a
    identity_ref: id
    sudo_mode: none
hosts:
  host-a:
    address: 10.0.0.1
    port: 22
identities:
  id:
    user: deploy
    auth_type: auto
`
	if err := os.WriteFile(filepath.Join(directory, "xops_config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	var stderr bytes.Buffer
	options := &SshOptions{
		Host:    "shared",
		Target:  config.ConnectionTarget{Selector: "shared"},
		control: SSHControlFlags{CtlCmd: "check", ControlPath: "/tmp/explicit.sock"},
	}

	if _, err := resolveControlSocketPath(context.Background(), options, &stderr); err == nil {
		t.Fatal("expected an ambiguous selector error")
	}
	if !strings.Contains(stderr.String(), "resolve target") {
		t.Fatalf("expected a resolution error on stderr, got %q", stderr.String())
	}
}

// TestControlCommandExplicitPathUsesResolvedTarget verifies that an explicit -S
// pattern still expands against the resolved node, not the raw selector.
func TestControlCommandExplicitPathUsesResolvedTarget(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", directory)
	content := fmt.Sprintf(controlResolutionConfig, "~/.ssh/ignored-%C")
	if err := os.WriteFile(filepath.Join(directory, "xops_config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	explicitPattern := "/tmp/explicit-%r@%h:%p.sock"
	expected, err := ssh.ExpandControlPath(explicitPattern, sshenv.Discover(), ssh.TargetContext{
		Host: "10.20.30.40",
		Port: 2222,
		User: "deploy",
	})
	if err != nil {
		t.Fatalf("ExpandControlPath failed: %v", err)
	}

	var stderr bytes.Buffer
	options := &SshOptions{
		Host: "web-01",
		Target: config.ConnectionTarget{
			Selector: "web-01",
		},
		control: SSHControlFlags{CtlCmd: "check", ControlPath: explicitPattern},
	}

	path, err := resolveControlSocketPath(context.Background(), options, &stderr)
	if err != nil {
		t.Fatalf("resolveControlSocketPath failed: %v", err)
	}
	if path != expected {
		t.Fatalf("expected %q, got %q", expected, path)
	}
}

// TestControlCommandAdHocHostUsesOptionControlPath verifies that an ad-hoc host
// (no inventory node) still resolves a control path supplied through -o. Without
// it `-O check` on such a host wrongly reports "ControlPath must be specified".
func TestControlCommandAdHocHostUsesOptionControlPath(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", directory)
	if err := os.WriteFile(filepath.Join(directory, "xops_config.yaml"), []byte("schema_version: 2\nnodes: {}\nhosts: {}\nidentities: {}\n"), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	pattern := "/tmp/adhoc-%r@%h-%p.sock"
	expected, err := ssh.ExpandControlPath(pattern, sshenv.Discover(), ssh.TargetContext{
		Host: "192.0.2.10",
		Port: 2222,
		User: "ops",
	})
	if err != nil {
		t.Fatalf("ExpandControlPath failed: %v", err)
	}

	var stderr bytes.Buffer
	options := &SshOptions{
		Host: "192.0.2.10",
		Target: config.ConnectionTarget{
			Selector: "192.0.2.10",
			User:     "ops",
			HasUser:  true,
			Port:     2222,
			HasPort:  true,
		},
		control: SSHControlFlags{
			CtlCmd:  "check",
			Options: []string{"ControlPath=" + pattern},
		},
	}

	path, err := resolveControlSocketPath(context.Background(), options, &stderr)
	if err != nil {
		t.Fatalf("resolveControlSocketPath failed: %v (stderr %q)", err, stderr.String())
	}
	if path != expected {
		t.Fatalf("expected %q, got %q", expected, path)
	}
}

// TestControlCommandGlobalDefaultHonorsCLIOverrides verifies that a control path
// from the global default expands with the CLI -l/-p overrides, matching what the
// connector used when it created the master.
func TestControlCommandGlobalDefaultHonorsCLIOverrides(t *testing.T) {
	pattern := "~/.ssh/cm-%r@%h-%p"
	directory := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", directory)
	content := fmt.Sprintf(`schema_version: 2
control:
  master: auto
  path: "%s"
nodes:
  web-01:
    host_ref: host-web-01
    identity_ref: id-web-01
    sudo_mode: none
hosts:
  host-web-01:
    address: 10.20.30.40
    port: 2222
identities:
  id-web-01:
    user: deploy
    auth_type: auto
`, pattern)
	if err := os.WriteFile(filepath.Join(directory, "xops_config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	var stderr bytes.Buffer
	options := &SshOptions{
		Host: "web-01",
		User: "override",
		Port: 2200,
		Target: config.ConnectionTarget{
			Selector: "web-01",
			User:     "override",
			HasUser:  true,
			Port:     2200,
			HasPort:  true,
		},
		control: SSHControlFlags{CtlCmd: "check"},
	}

	path, err := resolveControlSocketPath(context.Background(), options, &stderr)
	if err != nil {
		t.Fatalf("resolveControlSocketPath failed: %v (stderr %q)", err, stderr.String())
	}
	expected, err := ssh.ExpandControlPath(pattern, sshenv.Discover(), ssh.TargetContext{
		Host: "10.20.30.40",
		Port: 2200,
		User: "override",
	})
	if err != nil {
		t.Fatalf("ExpandControlPath failed: %v", err)
	}
	if path != expected {
		t.Fatalf("expected %q, got %q", expected, path)
	}
}

// TestControlCommandAppliesOptionPortAndUser verifies that -o Port/User reach the
// control path expansion for an ad-hoc host even without a primary flag.
func TestControlCommandAppliesOptionPortAndUser(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", directory)
	if err := os.WriteFile(filepath.Join(directory, "xops_config.yaml"), []byte("schema_version: 2\nnodes: {}\nhosts: {}\nidentities: {}\n"), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	pattern := "/tmp/opt-%r-%p.sock"
	var stderr bytes.Buffer
	options := &SshOptions{
		Host: "192.0.2.20",
		Target: config.ConnectionTarget{
			Selector: "192.0.2.20",
		},
		control: SSHControlFlags{
			CtlCmd:  "check",
			Options: []string{"ControlPath=" + pattern, "Port=2222", "User=ops"},
		},
	}

	// The CLI applies -o target options during Complete, before any control query.
	if err := ApplyGeneralOptions(options, options.control.Options, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions failed: %v", err)
	}
	options.Target.User, options.Target.HasUser = options.User, true
	options.Target.Port, options.Target.HasPort = options.Port, true

	path, err := resolveControlSocketPath(context.Background(), options, &stderr)
	if err != nil {
		t.Fatalf("resolveControlSocketPath failed: %v (stderr %q)", err, stderr.String())
	}
	if path != "/tmp/opt-ops-2222.sock" {
		t.Fatalf("expected /tmp/opt-ops-2222.sock, got %q", path)
	}
}

// TestControlSocketPathAdHocHostUsesOpenSSHConfig verifies that an ad-hoc host
// with no inventory node still resolves ~/.ssh/config control options. The
// connector uses the same Tier 4 source when it creates the master, so skipping
// it here would compute a different socket than the one the master owns.
func TestControlSocketPathAdHocHostUsesOpenSSHConfig(t *testing.T) {
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(`
Host 192.0.2.77
    HostName 192.0.2.77
    ControlMaster auto
    ControlPath ~/.ssh/adhoc-%r@%h-%p.sock
    ControlPersist 10m
`))
	if err != nil {
		t.Fatalf("parse openssh config failed: %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(&config.Configuration{}, parser)

	options := NewSshOptions()
	options.Host = "192.0.2.77"
	options.User = "ops"
	options.Target = config.ConnectionTarget{
		Selector: "192.0.2.77",
		User:     "ops",
		HasUser:  true,
	}

	path, err := controlSocketPath(options, provider, "")
	if err != nil {
		t.Fatalf("controlSocketPath failed: %v", err)
	}
	expected, err := ssh.ExpandControlPath("~/.ssh/adhoc-%r@%h-%p.sock", sshenv.Discover(), ssh.TargetContext{
		Host:         "192.0.2.77",
		Port:         22,
		User:         "ops",
		OriginalHost: "192.0.2.77",
	})
	if err != nil {
		t.Fatalf("ExpandControlPath failed: %v", err)
	}
	if path != expected {
		t.Fatalf("expected %q, got %q", expected, path)
	}
}

// TestControlSocketPathValidatesAdHocSessionOptions verifies that ad-hoc hosts go
// through the same merged-control validation as inventory nodes: an active master
// mode without any ControlPath must fail instead of silently disabling sharing.
func TestControlSocketPathValidatesAdHocSessionOptions(t *testing.T) {
	provider := config.NewProviderWithOpenSSHParser(&config.Configuration{}, &config.OpenSSHParser{})

	options := NewSshOptions()
	options.Host = "192.0.2.99"
	options.Target = config.ConnectionTarget{Selector: "192.0.2.99"}
	options.control.Options = []string{"ControlMaster=yes"}

	if _, err := controlSocketPath(options, provider, ""); err == nil {
		t.Fatal("expected ControlPath validation to reject an active master without a path")
	}
}

// TestControlCommandDisambiguatesMultiPortHostAndDefaultLocalUser verifies that:
// 1. -O resolves a multi-port/multi-user host when user@ or :port is supplied.
// 2. controlTarget defaults %r to the local user on ad-hoc hosts without -l.
func TestControlCommandDisambiguatesMultiPortHostAndDefaultLocalUser(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", directory)
	content := `schema_version: 2
control:
  master: auto
  path: "/tmp/cm-%r@%h-%p.sock"
nodes:
  root@10.0.0.1:22:
    host_ref: h-22
    identity_ref: id-root
    sudo_mode: none
  ops@10.0.0.1:2222:
    host_ref: h-2222
    identity_ref: id-ops
    sudo_mode: none
hosts:
  h-22:
    address: 10.0.0.1
    port: 22
  h-2222:
    address: 10.0.0.1
    port: 2222
identities:
  id-root:
    user: root
    auth_type: auto
  id-ops:
    user: ops
    auth_type: auto
`
	if err := os.WriteFile(filepath.Join(directory, "xops_config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	var stderr bytes.Buffer
	opts := NewSshOptions()
	opts.args = []string{"ops@10.0.0.1:2222"}
	opts.control = SSHControlFlags{CtlCmd: "check"}
	if err := opts.parseArgs(); err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}

	path, err := resolveControlSocketPath(context.Background(), opts, &stderr)
	if err != nil {
		t.Fatalf("resolveControlSocketPath failed on disambiguated host: %v (stderr: %q)", err, stderr.String())
	}
	if path != "/tmp/cm-ops@10.0.0.1-2222.sock" {
		t.Fatalf("expected /tmp/cm-ops@10.0.0.1-2222.sock, got %q", path)
	}

	// Ad-hoc host without explicit -l must default %r to sshenv.Discover().LocalUser
	adhocOpts := NewSshOptions()
	adhocOpts.args = []string{"192.0.2.55"}
	adhocOpts.control = SSHControlFlags{CtlCmd: "check", ControlPath: "/tmp/adhoc-%r@%h:%p.sock"}
	if err := adhocOpts.parseArgs(); err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}
	adhocPath, err := resolveControlSocketPath(context.Background(), adhocOpts, &stderr)
	if err != nil {
		t.Fatalf("resolveControlSocketPath failed on ad-hoc host: %v", err)
	}
	localUser := sshenv.Discover().LocalUser
	wantAdhoc := fmt.Sprintf("/tmp/adhoc-%s@192.0.2.55:22.sock", localUser)
	if adhocPath != wantAdhoc {
		t.Fatalf("expected %q, got %q", wantAdhoc, adhocPath)
	}
}

// TestControlCommandSelectsDerivedUserNodeOverBaseNode verifies that when the
// configuration contains both a base node keyed by address ("10.0.0.5") and a
// derived user node ("test@10.0.0.5:2222"), `xops ssh -O check test@10.0.0.5`
// resolves the derived node's control configuration rather than the base node's.
func TestControlCommandSelectsDerivedUserNodeOverBaseNode(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", directory)
	content := `schema_version: 2
nodes:
  "10.0.0.5":
    host_ref: h-base
    identity_ref: id-root
    sudo_mode: none
    control:
      master: auto
      path: "/tmp/base-%n.sock"
  "test@10.0.0.5:2222":
    host_ref: h-base
    identity_ref: id-test
    sudo_mode: none
    control:
      master: auto
      path: "/tmp/derived-%r@%h-%p.sock"
hosts:
  h-base:
    address: 10.0.0.5
    port: 2222
identities:
  id-root:
    user: root
    auth_type: auto
  id-test:
    user: test
    auth_type: auto
`
	if err := os.WriteFile(filepath.Join(directory, "xops_config.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	var stderr bytes.Buffer
	opts := NewSshOptions()
	opts.args = []string{"test@10.0.0.5"}
	opts.control = SSHControlFlags{CtlCmd: "check"}
	if err := opts.parseArgs(); err != nil {
		t.Fatalf("parseArgs failed: %v", err)
	}

	path, err := resolveControlSocketPath(context.Background(), opts, &stderr)
	if err != nil {
		t.Fatalf("resolveControlSocketPath failed: %v (stderr: %q)", err, stderr.String())
	}
	if path != "/tmp/derived-test@10.0.0.5-2222.sock" {
		t.Fatalf("expected /tmp/derived-test@10.0.0.5-2222.sock, got %q", path)
	}
}
