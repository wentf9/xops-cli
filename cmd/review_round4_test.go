package cmd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	xssh "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

type round4FakeCanonicalResolver struct {
	hosts map[string][]string
	cname map[string]string
}

func (f *round4FakeCanonicalResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if addrs, ok := f.hosts[host]; ok {
		return slices.Clone(addrs), nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f *round4FakeCanonicalResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := f.cname[host]; ok {
		return c, nil
	}
	return host + ".", nil
}

func TestRound4_P1_1_SftpPositionalValidateTwiceAndRejectsExtraArgs(t *testing.T) {
	t.Parallel()

	so := NewSftpOptions()
	cmd := newCmdSftpWithOptions(so)
	if err := cmd.Flags().Parse([]string{"web"}); err != nil {
		t.Fatalf("Parse positional: %v", err)
	}
	if err := so.Complete(cmd, cmd.Flags().Args()); err != nil {
		t.Fatalf("Complete(sftp web): %v", err)
	}
	if err := so.Validate(); err != nil {
		t.Fatalf("first Validate(sftp web): %v", err)
	}
	if err := so.Validate(); err != nil {
		t.Fatalf("second Validate(sftp web): %v", err)
	}
	if err := so.validateSftpInvariants(); err != nil {
		t.Fatalf("validateSftpInvariants after Validate: %v", err)
	}
	if so.Host != "web" || !so.hostFromPositional {
		t.Fatalf("unexpected sftp parsed state: Host=%q hostFromPositional=%v", so.Host, so.hostFromPositional)
	}

	// --host flag with an extra positional argument must still be rejected.
	soFlagExtra := NewSftpOptions()
	cmdFlagExtra := newCmdSftpWithOptions(soFlagExtra)
	if err := cmdFlagExtra.Flags().Parse([]string{"--host", "web", "extra-arg"}); err != nil {
		t.Fatalf("Parse --host extra: %v", err)
	}
	if err := soFlagExtra.Complete(cmdFlagExtra, cmdFlagExtra.Flags().Args()); err != nil {
		t.Fatalf("Complete(--host web extra-arg): %v", err)
	}
	if err := soFlagExtra.Validate(); err == nil || !strings.Contains(err.Error(), "unexpected positional argument") {
		t.Fatalf("Validate(--host web extra-arg) = %v, want unexpected positional argument error", err)
	}

	// Positional target with an extra positional argument must be rejected.
	soPosExtra := NewSftpOptions()
	cmdPosExtra := newCmdSftpWithOptions(soPosExtra)
	if err := cmdPosExtra.Flags().Parse([]string{"web", "extra-arg"}); err != nil {
		t.Fatalf("Parse positional extra: %v", err)
	}
	if err := soPosExtra.Complete(cmdPosExtra, cmdPosExtra.Flags().Args()); err != nil {
		t.Fatalf("Complete(web extra-arg): %v", err)
	}
	if err := soPosExtra.Validate(); err == nil || !strings.Contains(err.Error(), "unexpected positional argument") {
		t.Fatalf("Validate(web extra-arg) = %v, want unexpected positional argument error", err)
	}
}

func TestRound4_P1_2_ScpBatchCanonicalizesBeforeExcludeAndPreservesOverrides(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host short",
		"  User ops",
		"",
		"Host short.corp.example.com",
		"  HostName 10.200.0.10",
		"  Port 2222",
		"",
		"Host other",
		"  User ops",
		"",
		"Host other.corp.example.com",
		"  HostName 10.200.0.20",
		"  Port 2222",
		"",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"
	repo := buildPass6Repo(t, sshCfg)

	resolver := &round4FakeCanonicalResolver{
		hosts: map[string][]string{
			"short.corp.example.com": {"10.200.0.10"},
			"other.corp.example.com": {"10.200.0.20"},
		},
	}

	o := NewScpOptions()
	o.Host = "short,other"
	o.Exclude = []string{"ops@short"}
	o.Source = "/tmp/local.txt"
	o.Dest = "/tmp/remote.txt"
	o.canonicalResolver = resolver

	if err := o.canonicalizeEndpoints(t.Context(), repo); err != nil {
		t.Fatalf("canonicalizeEndpoints: %v", err)
	}

	o.canonicalMu.Lock()
	shortRes, shortCached := o.canonicalCache["short"]
	otherRes, otherCached := o.canonicalCache["other"]
	o.canonicalMu.Unlock()
	if !shortCached || !shortRes.Canonicalized || shortRes.CanonicalHost != "short.corp.example.com" {
		t.Fatalf("excluded host short was not canonicalized first: cached=%v res=%+v", shortCached, shortRes)
	}
	if !otherCached || !otherRes.Canonicalized || otherRes.CanonicalHost != "other.corp.example.com" {
		t.Fatalf("included host other canonicalization unexpected: cached=%v res=%+v", otherCached, otherRes)
	}

	excludes, err := o.resolveExcludes(repo)
	if err != nil {
		t.Fatalf("resolveExcludes: %v", err)
	}
	canonShort := PathInfo{Host: "short.corp.example.com", OriginalHost: "short", User: "ops", Port: 2222, IsRemote: true}
	excluded, err := o.isBatchHostExcluded(repo, excludes, "short", canonShort)
	if err != nil || !excluded {
		t.Fatalf("isBatchHostExcluded(short after Pass-2 port 2222) = (%v, %v), want (true, nil)", excluded, err)
	}

	remaining := o.collectTargetPaths(repo)
	if len(remaining) != 1 || remaining[0].Host != "other" {
		t.Fatalf("collectTargetPaths after exclude = %+v, want single target host 'other'", remaining)
	}

	var adpOpts []adapter.Option
	if err := o.appendScpSessionAuthOverrides(&adpOpts, repo, false, true); err != nil {
		t.Fatalf("appendScpSessionAuthOverrides: %v", err)
	}
	if len(o.targetNodeIDs) == 0 {
		t.Fatalf("expected non-excluded targetNodeIDs for 'other', got empty")
	}
	for _, id := range o.targetNodeIDs {
		if strings.Contains(id, "short") || strings.Contains(id, "10.200.0.10") {
			t.Fatalf("excluded host leaked into targetNodeIDs: %v", o.targetNodeIDs)
		}
	}

	// Direct runTransfer on positional path must also canonicalize before exclude check.
	oPos := NewScpOptions()
	oPos.Source = "/tmp/local.txt"
	oPos.Dest = "short:/tmp/remote.txt"
	oPos.Exclude = []string{"ops@short"}
	oPos.canonicalResolver = resolver
	posErr := oPos.runTransfer(t.Context(), repo, nil)
	if posErr == nil || !strings.Contains(posErr.Error(), "excluded") {
		t.Fatalf("runTransfer(positional excluded canonical target) = %v, want excluded error", posErr)
	}
}

func TestRound4_P1_3_ResolveAndCacheSessionOptionsPreservesDerivedAndSavedTiers(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host myalias",
		"  HostName 10.77.0.5",
		"  User alice",
		"  Port 2222",
		"  LocalForward 18080 127.0.0.1:80",
		"  ForkAfterAuthentication yes",
		"  RemoteCommand echo hello",
		"  PermitLocalCommand yes",
		"  LocalCommand true",
	}, "\n") + "\n"
	repo := buildPass6Repo(t, sshCfg)

	// 1. ProvenanceOpenSSHDerived (`xops ssh -l bob myalias`)
	prep, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector: "myalias",
			User:     "bob",
			HasUser:  true,
		},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(myalias -l bob): %v", err)
	}
	o := NewSshOptions()
	o.Host = "myalias"
	o.User = "bob"
	o.Target = config.ConnectionTarget{Selector: "myalias", User: "bob", HasUser: true}

	eff, err := o.resolveAndCacheSessionOptions(repo, prep.NodeID)
	if err != nil {
		t.Fatalf("resolveAndCacheSessionOptions(derived %q): %v", prep.NodeID, err)
	}
	if eff == nil {
		t.Fatal("expected non-nil effective options")
	}
	if len(eff.LocalForwards()) == 0 {
		t.Fatalf("ProvenanceOpenSSHDerived LocalForward stripped: %v", eff)
	}
	if fork, ok := eff.ForkAfterAuthentication(); !ok || !fork {
		t.Fatalf("ProvenanceOpenSSHDerived ForkAfterAuthentication = (%v, %v), want (true, true)", fork, ok)
	}
	if eff.Get(xssh.OptionRemoteCommand) != "echo hello" {
		t.Fatalf("ProvenanceOpenSSHDerived RemoteCommand = %q, want 'echo hello'", eff.Get(xssh.OptionRemoteCommand))
	}
	if eff.Get(xssh.OptionLocalCommand) != "true" {
		t.Fatalf("ProvenanceOpenSSHDerived LocalCommand = %q, want 'true'", eff.Get(xssh.OptionLocalCommand))
	}

	// 2. ProvenanceSavedManaged with an alias selector that differs from NodeID
	savedID := "ops@10.88.0.5:22"
	savedOpts := &xssh.Options{}
	if err := savedOpts.Set(xssh.OptionServerAliveInterval, "41"); err != nil {
		t.Fatal(err)
	}
	if err := savedOpts.Set(xssh.OptionLocalForward, "19090 127.0.0.1:90"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), savedID,
		models.Node{
			HostRef:     "h-saved",
			IdentityRef: "id-saved",
			Alias:       []string{"web-prod"},
			SSHOptions:  savedOpts,
		},
		models.Host{Address: "10.88.0.5", Port: 22},
		models.Identity{User: "ops", AuthType: "key", KeyPath: "/tmp/r4_dummy_id_ed25519"},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}

	oSaved := NewSshOptions()
	oSaved.Host = "web-prod"
	oSaved.Target = config.ConnectionTarget{Selector: "web-prod"}
	effSaved, err := oSaved.resolveAndCacheSessionOptions(repo, savedID)
	if err != nil {
		t.Fatalf("resolveAndCacheSessionOptions(saved %q): %v", savedID, err)
	}
	if effSaved == nil || effSaved.ServerAliveInterval() != 41*time.Second || len(effSaved.LocalForwards()) == 0 {
		t.Fatalf("ProvenanceSavedManaged Tier-2 options lost: %+v", effSaved)
	}
}

func TestRound4_P2_20_ApplyGeneralOptionsSnakeCaseProxyJumpAndCommand(t *testing.T) {
	t.Parallel()

	oJump := NewSshOptions()
	if err := ApplyGeneralOptions(oJump, []string{"proxy_jump=bastion-a", "proxy_command=nc %h %p"}, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions(snake_case jump first): %v", err)
	}
	if oJump.JumpHost != "bastion-a" {
		t.Fatalf("oJump.JumpHost = %q, want bastion-a", oJump.JumpHost)
	}

	oCmdFirst := NewSshOptions()
	if err := ApplyGeneralOptions(oCmdFirst, []string{"proxy_command=nc %h %p", "proxy_jump=bastion-b"}, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions(snake_case cmd first): %v", err)
	}
	if oCmdFirst.JumpHost != "" {
		t.Fatalf("oCmdFirst.JumpHost = %q, want empty when proxy_command came first", oCmdFirst.JumpHost)
	}

	oJumpNone := NewSshOptions()
	if err := ApplyGeneralOptions(oJumpNone, []string{"proxy_command=nc %h %p", "proxy_jump=none"}, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions(snake_case proxy_jump=none): %v", err)
	}
	if oJumpNone.JumpHost != "none" {
		t.Fatalf("oJumpNone.JumpHost = %q, want 'none'", oJumpNone.JumpHost)
	}
}

func TestRound4_P2_21_DaemonSpecDisabledProxyJumpPreservesTargetBranchAndProxyCommandNone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, _ := splitHostPortMust(t, fix.Address)

	sshCfg := strings.Join([]string{
		"Host mynode",
		"  HostName " + fixHost,
		"  User fixture",
		"  Port " + portStr,
		"  ProxyCommand nc %h %p",
	}, "\n") + "\n"
	repo := buildPass6Repo(t, sshCfg)
	nodeID := config.OpenSSHNodePrefix + "mynode"

	tmpDir := shortControlTempDir(t)
	sockPath := filepath.Join(tmpDir, "jump-none.sock")

	adp := adapter.NewSSHAdapter(
		repo,
		adapter.WithNonInteractive(true),
		adapter.WithSessionAuthOverride(nodeID, adapter.SessionAuth{
			Password:  sshfixture.Password,
			ProxyJump: "none",
		}),
		adapter.WithSessionControlOverride(nodeID, newPass6SessionControl(t, sockPath, "ProxyCommand", "none")),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("connector.Connect(%q): %v", nodeID, err)
	}
	defer func() { _ = client.Close() }()

	m := connector.Masters()[0]
	for _, jumpVal := range []string{"none", "none,none"} {
		o := NewSshOptions()
		o.Host = "mynode"
		o.JumpHost = jumpVal
		o.CipherSpec = "aes128-gcm@openssh.com"
		o.GatewayPorts = true
		o.control.Options = []string{"ProxyCommand=none", "ProxyJump=" + jumpVal}

		if !o.shouldPassIdentityFile(nodeID, m) {
			t.Fatalf("shouldPassIdentityFile(%q) = false, want true (target branch)", jumpVal)
		}
		spec := o.buildMuxDaemonSpecWithProvider(repo, nodeID, sockPath, m)
		if spec.JumpHost != "none" {
			t.Fatalf("spec.JumpHost for %q = %q, want 'none'", jumpVal, spec.JumpHost)
		}
		if spec.CipherSpec != "aes128-gcm@openssh.com" || !spec.GatewayPorts {
			t.Fatalf("target branch fields dropped for %q: spec=%+v", jumpVal, spec)
		}
		if !slices.Contains(spec.Options, "ProxyCommand=none") {
			t.Fatalf("ProxyCommand=none dropped from spec.Options for %q: %v", jumpVal, spec.Options)
		}
	}
}

func TestRound4_P2_22_CanonicalControlOriginAndHostExtractsHostAndStripsPort(t *testing.T) {
	t.Parallel()

	o := NewSshOptions()
	o.canonicalized = true
	o.originalHost = config.OpenSSHNodePrefix + "alice@short:2201"
	o.Target.Selector = config.OpenSSHNodePrefix + "bob@short.corp.example.com:2222"

	origHost, canonHost := canonicalControlOriginAndHost(o)
	if origHost != "short" || canonHost != "short.corp.example.com" {
		t.Fatalf("canonicalControlOriginAndHost = (%q, %q), want (\"short\", \"short.corp.example.com\")", origHost, canonHost)
	}
}

func TestRound4_P2_23_ExecScpCanonicalizedDaemonHandoffAndResolveMasterNodeID(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, _ := splitHostPortMust(t, fix.Address)
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}

	sshCfg := strings.Join([]string{
		"Host short",
		"  User fixture",
		"  Port " + portStr,
		"  ServerAliveCountMax 5",
		"",
		"Host *.corp.example.com",
		"  HostName " + fixHost,
		"  ServerAliveInterval 19",
	}, "\n") + "\n"
	repo := buildPass6Repo(t, sshCfg)

	// Prepare via real flow (wildcard Pass-2; no manual SetNodeCanonicalHost on openssh:<canon>).
	prep, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector:     "short.corp.example.com",
			OriginalHost: "short",
		},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext: %v", err)
	}

	tmpDir := shortControlTempDir(t)
	sockPath := filepath.Join(tmpDir, "exec-canon.sock")
	adp := adapter.NewSSHAdapter(
		repo,
		adapter.WithNonInteractive(true),
		adapter.WithSessionAuthOverride(prep.NodeID, adapter.SessionAuth{
			Password:      sshfixture.Password,
			OriginalHost:  "short",
			CanonicalHost: "short.corp.example.com",
		}),
		adapter.WithSessionControlOverride(prep.NodeID, newPass6SessionControl(t, sockPath)),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, prep.NodeID)
	if err != nil {
		t.Fatalf("connector.Connect(%q): %v", prep.NodeID, err)
	}
	defer func() { _ = client.Close() }()

	m := connector.Masters()[0]
	rawOwnedID := strings.TrimSpace(connector.MasterNodeID(m))
	if m.Target().CanonicalHost != "short.corp.example.com" {
		t.Fatalf("master.Target().CanonicalHost = %q, want short.corp.example.com", m.Target().CanonicalHost)
	}
	wantCanonID := config.OpenSSHNodePrefix + "short.corp.example.com"
	if got := resolveOwnedMasterNodeID(repo, connector, m); got != wantCanonID {
		t.Fatalf("resolveOwnedMasterNodeID = %q, want %q", got, wantCanonID)
	}
	if got := resolveMasterNodeID(repo, m); got != wantCanonID {
		t.Fatalf("resolveMasterNodeID = %q, want %q", got, wantCanonID)
	}

	// Simulate exec/scp handoff (batchOpts.canonicalized == false).
	batchOpts := NewSshOptions()
	spec := batchOpts.buildMuxDaemonSpecWithRawNode(repo, wantCanonID, rawOwnedID, sockPath, m)
	if !spec.Canonicalized || spec.OriginalHost != "short" || spec.TargetHost != "short.corp.example.com" || !spec.OpenSSHNamespace {
		t.Fatalf("exec/scp MuxDaemonSpec dropped canonical metadata: %+v", spec)
	}

	// Confirmed saved node still resolves user-pending fallback metadata.
	if err := repo.ConfirmNodeContext(ctx, prep.NodeID); err != nil {
		t.Fatalf("ConfirmNodeContext: %v", err)
	}
	if got := resolveMasterNodeIDViaUserPending(repo, "short", fixHost, "fixture", uint16(portNum)); got != wantCanonID {
		t.Fatalf("resolveMasterNodeIDViaUserPending after ConfirmNodeContext = %q, want %q", got, wantCanonID)
	}
}

func TestRound4_P2_24_CompleteRejectsInvalidArgsBeforeReadingStdin(t *testing.T) {
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = wPipe.Close() }()
	defer func() { _ = rPipe.Close() }()
	origStdin := os.Stdin
	os.Stdin = rPipe
	t.Cleanup(func() { os.Stdin = origStdin })

	runWithTimeout := func(t *testing.T, fn func() error, label string) error {
		t.Helper()
		done := make(chan error, 1)
		go func() {
			done <- fn()
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("%s blocked on os.Stdin instead of failing validation", label)
			return nil
		}
	}

	// sftp --password-stdin without host must fail without reading stdin.
	err = runWithTimeout(t, func() error {
		so := NewSftpOptions()
		cmd := newCmdSftpWithOptions(so)
		_ = cmd.Flags().Parse([]string{"--password-stdin"})
		return so.Complete(cmd, cmd.Flags().Args())
	}, "sftp missing host")
	if err == nil {
		t.Fatal("expected error for sftp --password-stdin without host")
	}

	// sftp with bad -o + ForkAfterAuthentication=yes must surface bad option error immediately.
	err = runWithTimeout(t, func() error {
		so := NewSftpOptions()
		cmd := newCmdSftpWithOptions(so)
		_ = cmd.Flags().Parse([]string{"--password-stdin", "-o", "ForkAfterAuthentication=yes", "-o", "BadOption=1", "web"})
		return so.Complete(cmd, cmd.Flags().Args())
	}, "sftp bad -o")
	if err == nil || !strings.Contains(err.Error(), "BadOption") {
		t.Fatalf("expected BadOption error from sftp Complete, got %v", err)
	}

	// sftp --force --no-clobber --password-stdin must fail before stdin.
	err = runWithTimeout(t, func() error {
		so := NewSftpOptions()
		cmd := newCmdSftpWithOptions(so)
		_ = cmd.Flags().Parse([]string{"--password-stdin", "--force", "--no-clobber", "web"})
		return so.Complete(cmd, cmd.Flags().Args())
	}, "sftp force+no-clobber")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error from sftp Complete, got %v", err)
	}

	// ssh --password-stdin without host must fail before reading stdin.
	err = runWithTimeout(t, func() error {
		so := NewSshOptions()
		cmd := newCmdSshWithOptions(so)
		_ = cmd.Flags().Parse([]string{"--password-stdin"})
		return so.Complete(cmd, cmd.Flags().Args())
	}, "ssh missing host")
	if err == nil {
		t.Fatal("expected error for ssh --password-stdin without host")
	}

	// ssh -o ForkAfterAuthentication=yes -o BadOption=1 --password-stdin web must reject BadOption immediately.
	err = runWithTimeout(t, func() error {
		so := NewSshOptions()
		cmd := newCmdSshWithOptions(so)
		_ = cmd.Flags().Parse([]string{"--password-stdin", "-o", "ForkAfterAuthentication=yes", "-o", "BadOption=1", "web"})
		return so.Complete(cmd, cmd.Flags().Args())
	}, "ssh bad -o")
	if err == nil || !strings.Contains(err.Error(), "BadOption") {
		t.Fatalf("expected BadOption error from ssh Complete, got %v", err)
	}

	// ssh -f --password-stdin web must reject background + stdin combination immediately.
	err = runWithTimeout(t, func() error {
		so := NewSshOptions()
		cmd := newCmdSshWithOptions(so)
		_ = cmd.Flags().Parse([]string{"--password-stdin", "-f", "web"})
		return so.Complete(cmd, cmd.Flags().Args())
	}, "ssh -f + --password-stdin")
	if err == nil || !strings.Contains(err.Error(), "background mode (-f)") {
		t.Fatalf("expected background mode (-f) error from ssh Complete, got %v", err)
	}
}

func TestRound4_P3_10_ControlRejectsCLIForkDirectlyWhileAllowingTier4Check(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfgDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)

	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host checkhost",
		"  HostName 127.0.0.1",
		"  ForkAfterAuthentication yes",
		"  ControlPath " + filepath.Join(t.TempDir(), "nonexistent.sock"),
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	store := config.NewDefaultStore(filepath.Join(cfgDir, "config.yaml"), filepath.Join(cfgDir, "config.key"))
	if err := store.Save(config.NewProviderWithoutOpenSSH(nil).Snapshot()); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	for _, tc := range []struct {
		name string
		prep func(*SshOptions)
	}{
		{
			name: "direct -O check -f",
			prep: func(o *SshOptions) { o.BgRun = true },
		},
		{
			name: "direct -O check -o ForkAfterAuthentication=yes",
			prep: func(o *SshOptions) { o.control.Options = []string{"ForkAfterAuthentication=yes"} },
		},
	} {
		o := NewSshOptions()
		o.Host = "checkhost"
		o.control.CtlCmd = "check"
		o.control.ctlCmdSet = true
		o.control.ConfigFile = sshCfgPath
		tc.prep(o)

		var errBuf bytes.Buffer
		err := executeControlCommandWithStreams(t.Context(), o, controlStreams{
			Stdin:  strings.NewReader(""),
			Stdout: &bytes.Buffer{},
			Stderr: &errBuf,
		})
		var ctlErr *ControlExitError
		if !errors.As(err, &ctlErr) || ctlErr.Code != 255 {
			t.Fatalf("%s: expected *ControlExitError(255), got %v (stderr=%s)", tc.name, err, errBuf.String())
		}
	}

	// Tier-4 ForkAfterAuthentication=yes in ssh_config must still allow -O check to proceed past CLI validation.
	oTier4 := NewSshOptions()
	oTier4.Host = "checkhost"
	oTier4.control.CtlCmd = "check"
	oTier4.control.ctlCmdSet = true
	oTier4.control.ConfigFile = sshCfgPath

	var tier4ErrBuf bytes.Buffer
	err := executeControlCommandWithStreams(t.Context(), oTier4, controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &bytes.Buffer{},
		Stderr: &tier4ErrBuf,
	})
	if err == nil || strings.Contains(err.Error(), "ForkAfterAuthentication") || strings.Contains(err.Error(), "background mode") {
		t.Fatalf("Tier-4 ForkAfterAuthentication=yes wrongly rejected -O check: %v", err)
	}

	// Verify effectiveCLIJumpHost extracts CLI -o proxy_jump as well.
	oJump := NewSshOptions()
	if err := ApplyGeneralOptions(oJump, []string{"proxy_jump=bastion-c"}, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions: %v", err)
	}
	if oJump.effectiveCLIJumpHost() != "bastion-c" {
		t.Fatalf("effectiveCLIJumpHost = %q, want bastion-c", oJump.effectiveCLIJumpHost())
	}
}
