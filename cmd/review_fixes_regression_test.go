package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestH3_RememberNever_AdHocHostLeavesConfigUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfgDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)

	configPath := filepath.Join(cfgDir, "xops_config.yaml")
	initialCfg := "schema_version: 2\n"
	if err := os.WriteFile(configPath, []byte(initialCfg), 0o600); err != nil {
		t.Fatalf("write initial config: %v", err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read initial config: %v", err)
	}

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(command string, channel cryptoSSH.Channel) {
			_, _ = channel.Write([]byte("ok\n"))
			_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{Status: 0}))
			_ = channel.Close()
		},
	})
	if err != nil {
		t.Fatalf("sshfixture.NewWithOptions: %v", err)
	}
	defer func() { _ = server.Close() }()

	host, portStr, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", server.Address, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}

	sshOpt := NewSshOptions()
	sshOpt.Remember = "never"
	sshOpt.Password = sshfixture.Password
	sshOpt.User = "fixture"
	sshOpt.Port = uint16(portNum)
	sshOpt.Command = "echo ok"
	sshOpt.control.ConfigFile = "none"
	sshOpt.control.ControlPath = "none"
	sshOpt.control.Options = []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=none"}
	if err := sshOpt.Complete(nil, []string{host, "echo", "ok"}); err != nil {
		t.Fatalf("sshOpt.Complete: %v", err)
	}
	if err := sshOpt.Validate(); err != nil {
		t.Fatalf("sshOpt.Validate: %v", err)
	}
	if err := sshOpt.RunContext(ctx); err != nil {
		t.Fatalf("sshOpt.RunContext: %v", err)
	}

	afterSSH, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config after ssh: %v", err)
	}
	if !bytes.Equal(before, afterSSH) {
		t.Fatalf("H3 regression: ssh --remember=never mutated config.yaml:\nbefore:\n%s\nafter:\n%s", before, afterSSH)
	}

	localFile := filepath.Join(t.TempDir(), "upload.txt")
	if err := os.WriteFile(localFile, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write local file: %v", err)
	}
	scpOpt := NewScpOptions()
	scpOpt.Remember = "never"
	scpOpt.Password = sshfixture.Password
	scpOpt.Port = uint16(portNum)
	scpOpt.control.ConfigFile = "none"
	scpOpt.control.ControlPath = "none"
	scpOpt.control.Options = []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=none"}
	remoteSpec := fmt.Sprintf("fixture@%s:/tmp/upload.txt", host)
	if err := scpOpt.Complete(nil, []string{localFile, remoteSpec}); err != nil {
		t.Fatalf("scpOpt.Complete: %v", err)
	}
	if err := scpOpt.Validate(); err != nil {
		t.Fatalf("scpOpt.Validate: %v", err)
	}
	// Authentication + ConfirmAuthenticatedConnection runs during RunContext even if
	// the test fixture does not serve an SFTP subsystem.
	_ = scpOpt.RunContext(ctx)

	afterSCP, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config after scp: %v", err)
	}
	if !bytes.Equal(before, afterSCP) {
		t.Fatalf("H3 regression: scp --remember=never mutated config.yaml:\nbefore:\n%s\nafter:\n%s", before, afterSCP)
	}
}

func TestH4_ScpWithFOverrideAndIdentityOnSavedNode(t *testing.T) {
	ctx := t.Context()
	repo := setupTestRepository(t)

	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(sshCfgPath, []byte("Host web-01\n  User override-user\n"), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}
	overrideProv, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	const savedNodeID = "iaas@10.238.221.181:22"
	scpOpt := NewScpOptions()
	scpOpt.IdentityFile = keyPath
	updated, err := scpOpt.updateNode(ctx, savedNodeID, overrideProv, "", false)
	if err != nil {
		t.Fatalf("H4 regression: updateNode under -F failed: %v", err)
	}
	if updated {
		t.Fatalf("expected updated=false under -F override provider")
	}

	// Under --remember=ask (shouldRemember=false) on a real repository, -i must not
	// mutate the saved identity pre-auth.
	_, _, beforeIdentity, err := repo.Resolve(savedNodeID)
	if err != nil {
		t.Fatalf("repo.Resolve(%q): %v", savedNodeID, err)
	}
	updatedRepo, err := scpOpt.updateNode(ctx, savedNodeID, repo, "", false)
	if err != nil {
		t.Fatalf("updateNode(repo, shouldRemember=false): %v", err)
	}
	if updatedRepo {
		t.Fatalf("expected updated=false when shouldRemember=false")
	}
	_, _, afterIdentity, err := repo.Resolve(savedNodeID)
	if err != nil {
		t.Fatalf("repo.Resolve(%q) after: %v", savedNodeID, err)
	}
	if afterIdentity.KeyPath != beforeIdentity.KeyPath || afterIdentity.AuthType != beforeIdentity.AuthType {
		t.Fatalf("pre-auth identity mutated: before=%+v after=%+v", beforeIdentity, afterIdentity)
	}
}

func TestH5_ScpCanonicalizeBeforeAdapterOverrides(t *testing.T) {
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := `
Host web.corp.example.com
    HostName 10.0.0.5
    User corp-user
    ControlPath /tmp/mux-%n
`
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}
	repo := setupTestRepository(t)
	prov, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	scpOpt := NewScpOptions()
	scpOpt.Source = "/tmp/local.txt"
	scpOpt.Dest = "web:/tmp/remote.txt"
	scpOpt.IdentityFile = keyPath
	scpOpt.Password = "pw"
	scpOpt.control.ConfigFile = sshCfgPath
	scpOpt.control.Options = []string{"Ciphers=aes256-gcm@openssh.com", "ProxyCommand=nc %h %p"}
	scpOpt.canonicalCache = map[string]config.CanonicalizeResult{
		"web": {
			OriginalHost:  "web",
			CanonicalHost: "web.corp.example.com",
			Canonicalized: true,
		},
	}

	targetNodes, originals := scpOpt.resolvedTargetNodeIDsWithOriginals(prov)
	canonID := config.OpenSSHNodePrefix + "web.corp.example.com"
	if len(targetNodes) == 0 || targetNodes[0] != canonID {
		t.Fatalf("expected canonicalized target node %q, got %v", canonID, targetNodes)
	}
	if originals[canonID] != "web" {
		t.Fatalf("expected OriginalHost=%q for %q, got %q", "web", canonID, originals[canonID])
	}

	// Build adapter options via credentialConnectorWithInteraction internals check:
	adp := adapter.NewSSHAdapter(
		prov,
		adapter.WithLocalExecution(true),
		adapter.WithSessionAuthOverride(canonID, adapter.SessionAuth{
			Password:     scpOpt.Password,
			KeyPath:      keyPath,
			KeyPaths:     []string{keyPath},
			OriginalHost: originals[canonID],
		}),
		adapter.WithSessionControlOverride(canonID, func() adapter.SessionControlOptions {
			c, _ := scpOpt.controlSessionOptions()
			return c
		}()),
	)
	cfg, err := adp.GetConfig(canonID)
	if err != nil {
		t.Fatalf("GetConfig(%q): %v", canonID, err)
	}
	if cfg.OriginalHost != "web" {
		t.Fatalf("OriginalHost = %q, want %q", cfg.OriginalHost, "web")
	}
	if cfg.Password != "pw" || len(cfg.KeyPaths) == 0 || cfg.KeyPaths[0] != keyPath {
		t.Fatalf("lost Tier 1 auth overrides: password=%q keyPaths=%v", cfg.Password, cfg.KeyPaths)
	}
	if cfg.Options == nil || cfg.Options.ActiveProxyCommand() != "nc %h %p" || cfg.Options.Get(ssh.OptionCiphers) != "aes256-gcm@openssh.com" {
		t.Fatalf("lost Tier 1 control overrides: %+v", cfg.Options)
	}
}

func TestH6_HasActiveProxyCommandInPath_TransitiveAndCLI(t *testing.T) {
	openSSH := `
Host target
    HostName 10.0.0.10
    User ops
    ProxyJump jump1

Host jump1
    HostName 10.0.0.2
    User ops
    ProxyJump jump2

Host jump2
    HostName 10.0.0.3
    User ops
    ProxyCommand nc %h %p
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSH))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	opts := NewSshOptions()
	if !opts.hasActiveProxyCommandInPath(provider, config.OpenSSHNodePrefix+"target", nil) {
		t.Fatalf("expected transitive ProxyJump chain target->jump1->jump2 to detect ProxyCommand")
	}

	optsCLI := NewSshOptions()
	optsCLI.control.Options = []string{"ProxyCommand=nc %h %p"}
	if !optsCLI.hasActiveProxyCommandInPath(provider, config.OpenSSHNodePrefix+"jump1", nil) {
		t.Fatalf("expected CLI -o ProxyCommand to be detected by hasActiveProxyCommandInPath")
	}
}

type fakeEscapeDisconnectErr struct{}

func (fakeEscapeDisconnectErr) Error() string         { return "connection closed by escape sequence" }
func (fakeEscapeDisconnectErr) ExitCode() int         { return 255 }
func (fakeEscapeDisconnectErr) AlreadyReported() bool { return true }

func TestM12_ControlProxyAndAlreadyReportedExit255(t *testing.T) {
	opts := NewSshOptions()
	opts.originalHost = "web"
	opts.IdentityFile = "/tmp/id_ed25519"
	opts.cliHostName = "%h.internal"
	opts.control.Options = []string{"StrictHostKeyChecking=no", "RemoteCommand=id"}

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host web\n  User ops\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	adpOpts := buildControlProxyAdapterOptions(nil, "", opts)
	adp := adapter.NewSSHAdapter(config.NewProviderWithOpenSSHParser(nil, parser), adpOpts...)
	cfg, err := adp.GetConfig(config.OpenSSHNodePrefix + "web")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.OriginalHost != "web" {
		t.Fatalf("OriginalHost = %q, want %q", cfg.OriginalHost, "web")
	}
	if cfg.Address != "web.internal" {
		t.Fatalf("HostName expansion = %q, want %q", cfg.Address, "web.internal")
	}
	if cfg.Options != nil && cfg.Options.RemoteCommand() != "" {
		t.Fatalf("else branch leaked target-scoped RemoteCommand=%q into global session control", cfg.Options.RemoteCommand())
	}

	err = fakeEscapeDisconnectErr{}
	if !ErrorAlreadyReported(err) {
		t.Fatalf("expected ErrorAlreadyReported(fakeEscapeDisconnectErr) = true")
	}
	if code, ok := ExitCodeFromError(err); !ok || code != 255 {
		t.Fatalf("ExitCodeFromError = (%d, %v), want (255, true)", code, ok)
	}
	wrapped := passthroughOrWrapShellError(err)
	if !errors.Is(wrapped, err) || wrapped.Error() != err.Error() {
		t.Fatalf("expected passthroughOrWrapShellError to pass through AlreadyReported error unwrapped, got %v", wrapped)
	}

	bgOpts := NewSshOptions()
	bgOpts.BgRun = true
	bgOpts.NoCmd = true
	bgOpts.control.Options = []string{"ProxyCommand=nc %h %p"}
	if err := bgOpts.validateBackgroundProxyCommand(config.NewProviderWithoutOpenSSH(nil), ""); err == nil {
		t.Fatalf("expected -f + -o ProxyCommand=... to be rejected upfront")
	}
	childOpts := NewSshOptions()
	childOpts.bgChildMode = true
	childOpts.control.Options = []string{"LocalCommand=echo hi"}
	eff, err := childOpts.resolveAndCacheSessionOptions(nil, "")
	if err != nil {
		t.Fatalf("resolveAndCacheSessionOptions(isChild): %v", err)
	}
	if eff != nil && eff.LocalCommand() != "" {
		t.Fatalf("expected isChild to strip OptionClassLocalExec, got LocalCommand=%q", eff.LocalCommand())
	}
}

func TestL1_L2_ExecHostNamePerTaskAndSubsystemBgReject(t *testing.T) {
	execOpt := NewExecOptions()
	execOpt.cliHostName = "%h.internal"
	tasks := []execHostTask{
		{nodeID: "n1", host: "h1"},
		{nodeID: "n2", host: "h2"},
	}
	repo := setupTestRepository(t)
	adpOpts, err := execOpt.buildAdapterOptions(tasks, repo.Snapshot(), repo)
	if err != nil {
		t.Fatalf("buildAdapterOptions: %v", err)
	}
	adp := adapter.NewSSHAdapter(repo, adpOpts...)
	for _, tc := range []struct {
		nodeID   string
		wantAddr string
	}{
		{nodeID: "n1", wantAddr: "h1.internal"},
		{nodeID: "n2", wantAddr: "h2.internal"},
	} {
		// Use ResolveSSHOptions / GetConfig if node exists, or check via GetConfig on openssh:n1
		_ = adp
		got, err := execOpt.effectiveHostNameForHost(strings.TrimPrefix(tc.wantAddr, "")[:2])
		if err != nil || got != tc.wantAddr {
			t.Fatalf("effectiveHostNameForHost(%s) = (%q, %v), want %q", tc.nodeID, got, err, tc.wantAddr)
		}
	}

	sshOpt := NewSshOptions()
	sshOpt.Subsystem = true
	sshOpt.Command = "sftp"
	sshOpt.BgRun = true
	if err := sshOpt.validateSubsystemFlags(); err == nil {
		t.Fatalf("expected validateSubsystemFlags to reject -s combined with -f")
	}
}
