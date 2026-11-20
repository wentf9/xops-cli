package cmd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	xssh "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound3_P1_2_ControlPathAndProxyRejectCanonicalPass1Fork(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)

	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host short",
		"  User alice",
		"  ForkAfterAuthentication yes",
		"",
		"Host *.corp.example.com",
		"  ControlPath /tmp/r3-ctrl-%n-%h",
		"  ConnectTimeout 7",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	store := config.NewDefaultStore(filepath.Join(cfgDir, "config.yaml"), filepath.Join(cfgDir, "config.key"))
	if err := store.Save(config.NewProviderWithoutOpenSSH(nil).Snapshot()); err != nil {
		t.Fatalf("save base config: %v", err)
	}

	// 1. Without -S: resolveControlContext / controlSocketPath finds Pass-2 ControlPath and Pass-1 %n="short".
	oCheck := NewSshOptions()
	oCheck.Host = "short.corp.example.com"
	oCheck.canonicalized = true
	oCheck.originalHost = "short"
	oCheck.expandHost = "short"
	oCheck.Target = config.ConnectionTarget{Selector: "short.corp.example.com", OriginalHost: "short"}
	oCheck.control.CtlCmd = "check"
	oCheck.control.ctlCmdSet = true
	oCheck.control.ConfigFile = sshCfgPath

	var errBuf bytes.Buffer
	sockPath, target, _, _, err := resolveControlContext(t.Context(), oCheck, &errBuf)
	if err != nil {
		t.Fatalf("resolveControlContext(-O check) error = %v, stderr=%s", err, errBuf.String())
	}
	if target.OriginalHost != "short" {
		t.Fatalf("target.OriginalHost = %q, want short", target.OriginalHost)
	}
	if sockPath != "/tmp/r3-ctrl-short-short.corp.example.com" {
		t.Fatalf("controlSocketPath = %q, want /tmp/r3-ctrl-short-short.corp.example.com", sockPath)
	}

	// 2. -O proxy without -N or command must observe Pass-1 ForkAfterAuthentication=yes and reject (Decision 1.A).
	oProxy := NewSshOptions()
	oProxy.Host = "short.corp.example.com"
	oProxy.canonicalized = true
	oProxy.originalHost = "short"
	oProxy.expandHost = "short"
	oProxy.Target = config.ConnectionTarget{Selector: "short.corp.example.com", OriginalHost: "short"}
	oProxy.control.CtlCmd = "proxy"
	oProxy.control.ctlCmdSet = true
	oProxy.control.ConfigFile = sshCfgPath

	var proxyErr bytes.Buffer
	err = executeControlCommandWithStreams(t.Context(), oProxy, controlStreams{
		Stdin:  strings.NewReader(""),
		Stdout: &bytes.Buffer{},
		Stderr: &proxyErr,
	})
	var ctlErr *ControlExitError
	if !errors.As(err, &ctlErr) || ctlErr.Code != 255 {
		t.Fatalf("expected *ControlExitError(255) for -O proxy with Pass-1 ForkAfterAuthentication=yes, got (%v, stderr=%s)", err, proxyErr.String())
	}
}

func TestRound3_P1_3_CanonicalizedMuxDaemonSpecAndMasterIDPreserveTwoPass(t *testing.T) {
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
		"Host short",
		"  User fixture",
		"  Port " + portStr,
		"  ServerAliveCountMax 5",
		"",
		"Host short.corp.example.com",
		"  HostName " + fixHost,
		"  ServerAliveInterval 19",
	}, "\n") + "\n"
	repo := buildPass6Repo(t, sshCfg)

	canonID := config.OpenSSHNodePrefix + "short.corp.example.com"
	repo.SetNodeOpenSSHAlias(canonID, "short")
	repo.SetNodeCanonicalHost(canonID, "short.corp.example.com")

	tmpDir := shortControlTempDir(t)
	sockPath := filepath.Join(tmpDir, "canon-handoff.sock")

	adp := adapter.NewSSHAdapter(
		repo,
		adapter.WithNonInteractive(true),
		adapter.WithSessionAuthOverride(canonID, adapter.SessionAuth{
			Password:     sshfixture.Password,
			OriginalHost: "short",
		}),
		adapter.WithSessionControlOverride(canonID, newPass6SessionControl(t, sockPath)),
	)
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, canonID)
	if err != nil {
		t.Fatalf("connector.Connect(%q): %v", canonID, err)
	}
	defer func() { _ = client.Close() }()

	masters := connector.Masters()
	if len(masters) != 1 {
		t.Fatalf("expected 1 owned master, got %d", len(masters))
	}
	m := masters[0]
	if got := resolveOwnedMasterNodeID(repo, connector, m); got != canonID {
		t.Fatalf("resolveOwnedMasterNodeID = %q, want %q", got, canonID)
	}
	if got := resolveMasterNodeID(repo, m); got != canonID {
		t.Fatalf("resolveMasterNodeID = %q, want %q", got, canonID)
	}

	opts := NewSshOptions()
	opts.Host = "short.corp.example.com"
	opts.canonicalized = true
	opts.originalHost = "short"
	opts.targetNodeIDs = []string{canonID}

	spec := opts.buildMuxDaemonSpecWithProvider(repo, canonID, sockPath, m)
	if !spec.Canonicalized || spec.OriginalHost != "short" || spec.TargetHost != "short.corp.example.com" || !spec.OpenSSHNamespace {
		t.Fatalf("unexpected canonical MuxDaemonSpec: %+v", spec)
	}

	// Verify scp/exec style invocation (o.canonicalized==false, master==nil) also preserves Canonicalized & OriginalHost via provider.
	batchOpts := NewSshOptions()
	batchSpec := batchOpts.buildMuxDaemonSpecWithProvider(repo, canonID, sockPath, nil)
	if !batchSpec.Canonicalized || batchSpec.OriginalHost != "short" {
		t.Fatalf("batch buildMuxDaemonSpecWithProvider = %+v, want Canonicalized=true OriginalHost=short", batchSpec)
	}

	childRepo := buildPass6Repo(t, sshCfg)
	childNodeID, childCfg, effOpts := parsePass6MuxDaemonChild(t, ctx, childRepo, spec)
	if childNodeID != canonID {
		t.Fatalf("child nodeID = %q, want %q", childNodeID, canonID)
	}
	if childCfg.OriginalHost != "short" {
		t.Fatalf("childCfg.OriginalHost = %q, want short", childCfg.OriginalHost)
	}
	if effOpts == nil || effOpts.ServerAliveCountMax() != 5 || effOpts.ServerAliveInterval() != 19*time.Second {
		t.Fatalf("child daemon options = %v, want Pass-1 ServerAliveCountMax=5 & Pass-2 ServerAliveInterval=19s", effOpts)
	}
}

func TestRound3_P1_4_CLITargetExcludeInfoCarriesCanonicalHost(t *testing.T) {
	eo := NewExecOptions()
	task := execHostTask{
		nodeID:        config.OpenSSHNodePrefix + "short.corp.example.com",
		matchedNodeID: config.OpenSSHNodePrefix + "short.corp.example.com",
		baseNodeID:    config.OpenSSHNodePrefix + "short.corp.example.com",
		openSSHAlias:  "short",
		canonicalHost: "short.corp.example.com",
		rawHost:       "short",
		host:          "short.corp.example.com",
		originalHost:  "short",
		user:          "ops",
		port:          22,
	}
	info := eo.execTaskExcludeInfo(task)
	if info.CanonicalHost != "short.corp.example.com" || info.OpenSSHAlias != "short" {
		t.Fatalf("execTaskExcludeInfo = %+v, want CanonicalHost=short.corp.example.com", info)
	}

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host short\n  User ops\nHost *.corp.example.com\n  HostName 10.20.0.5\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser error = %v", err)
	}
	so := NewScpOptions()
	scpInfo, err := so.excludeTargetInfoForPath(repo, "short", PathInfo{
		Host:         "short.corp.example.com",
		OriginalHost: "short",
		IsRemote:     true,
	})
	if err != nil {
		t.Fatalf("excludeTargetInfoForPath error = %v", err)
	}
	if scpInfo.CanonicalHost != "short.corp.example.com" || scpInfo.OpenSSHAlias != "short" {
		t.Fatalf("scp excludeTargetInfoForPath = %+v, want CanonicalHost=short.corp.example.com OpenSSHAlias=short", scpInfo)
	}
}

func TestRound3_P2_11_CLIOptionAndJumpPrecedence(t *testing.T) {
	t.Parallel()

	// 1. -J none + -o ProxyJump=bastion + -o ProxyCommand=... preserves ProxyCommand.
	o := NewSshOptions()
	cmd := newCmdSshWithOptions(o)
	if err := cmd.Flags().Parse([]string{
		"-J", "none",
		"-o", "ProxyJump=bastion",
		"-o", "ProxyCommand=nc %h %p",
		"web",
	}); err != nil {
		t.Fatalf("Parse flags: %v", err)
	}
	if err := o.Complete(cmd, cmd.Flags().Args()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	sessOpts, err := o.controlSessionOptions()
	if err != nil {
		t.Fatalf("controlSessionOptions: %v", err)
	}
	if sessOpts.Options == nil || sessOpts.Options.Get(xssh.OptionProxyCommand) != "nc %h %p" {
		t.Fatalf("expected ProxyCommand preserved alongside -J none -o ProxyJump=bastion, got %+v", sessOpts.Options)
	}

	// 2. -o ProxyCommand=none -o ProxyJump=none allows ProxyJump=none to apply.
	o2 := NewSshOptions()
	o2.control.Options = []string{"ProxyCommand=none", "ProxyJump=none"}
	if err := ApplyGeneralOptions(o2, o2.control.Options, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions: %v", err)
	}
	if !strings.EqualFold(o2.JumpHost, "none") {
		t.Fatalf("o2.JumpHost = %q after -o ProxyCommand=none -o ProxyJump=none, want \"none\"", o2.JumpHost)
	}
}

func TestRound3_P2_14_And_P3_9_NonProxyControlBgRejectionAndCaseInsensitiveNone(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"check_with_-f", []string{"-O", "check", "-f", "web"}},
		{"stop_with_-f", []string{"-O", "stop", "-f", "web"}},
		{"check_with_-o_Fork", []string{"-O", "check", "-o", "ForkAfterAuthentication=yes", "web"}},
		{"check_with_-S_NONE", []string{"-O", "check", "-S", "NONE", "web"}},
		{"check_with_-S_None", []string{"-O", "check", "-S", "None", "web"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := NewSshOptions()
			cmd := newCmdSshWithOptions(o)
			if err := cmd.Flags().Parse(tc.args); err != nil {
				t.Fatalf("Parse(%v): %v", tc.args, err)
			}
			if err := o.Complete(cmd, cmd.Flags().Args()); err != nil {
				t.Fatalf("Complete(%v): %v", tc.args, err)
			}
			err := o.Validate()
			var ctlErr *ControlExitError
			if !errors.As(err, &ctlErr) || ctlErr.Code != 255 {
				t.Fatalf("Validate(%v) = %v, want *ControlExitError(255)", tc.args, err)
			}
		})
	}

	// Case-insensitive -S NONE normalizes to "none" in SessionControlOptions.
	flags := SSHControlFlags{ControlPath: "NONE"}
	sOpts, err := flags.ToSessionControlOptions()
	if err != nil {
		t.Fatalf("ToSessionControlOptions(-S NONE): %v", err)
	}
	if sOpts.Path == nil || *sOpts.Path != "none" {
		t.Fatalf("SessionControlOptions.Path = %v, want \"none\"", sOpts.Path)
	}
	if ctrl := mergeSessionControl(sOpts); ctrl.AllowReuse || ctrl.Path != "none" {
		t.Fatalf("mergeSessionControl(-S NONE) = %+v, want Path=\"none\" AllowReuse=false", ctrl)
	}
	if (&SSHControlFlags{CtlCmd: "stop", ControlPath: "NONE"}).ControlCommandWithoutTarget() {
		t.Fatal("ControlCommandWithoutTarget(-S NONE) must be false")
	}

	// Whitespace-only CtlCmd still wraps errors in ControlExitError{Code: 255}.
	wsErr := (&SSHControlFlags{CtlCmd: "   "}).controlUsageError(errors.New("bad opt"))
	var wsCtlErr *ControlExitError
	if !errors.As(wsErr, &wsCtlErr) || wsCtlErr.Code != 255 {
		t.Fatalf("whitespace CtlCmd error = %v, want *ControlExitError(255)", wsErr)
	}

	// Tier-4 ForkAfterAuthentication=yes in ssh_config does NOT block `xops ssh -O check <host>` Validate().
	oT4 := NewSshOptions()
	cmdT4 := newCmdSshWithOptions(oT4)
	if err := cmdT4.Flags().Parse([]string{"-O", "check", "web"}); err != nil {
		t.Fatalf("Parse(-O check web): %v", err)
	}
	if err := oT4.Complete(cmdT4, cmdT4.Flags().Args()); err != nil {
		t.Fatalf("Complete(-O check web): %v", err)
	}
	if err := oT4.Validate(); err != nil {
		t.Fatalf("Validate(-O check web) unexpected error: %v", err)
	}
}

func TestRound3_P2_15_SavedNodeNotPersistedWhenBackgroundInvariantFails(t *testing.T) {
	cfgDir := t.TempDir()
	t.Setenv("XOPS_CONFIG_DIR", cfgDir)
	t.Setenv("HOME", t.TempDir())

	cfgPath := filepath.Join(cfgDir, "config.yaml")
	keyPath := filepath.Join(cfgDir, "config.key")
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "127.0.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	nodeID := "ops@127.0.0.1:22"
	cfg.Nodes.Set(nodeID, models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		Alias:       []string{"saved-node"},
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(sshCfgPath, []byte("Host *\n  ForkAfterAuthentication yes\n"), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	o := NewSshOptions()
	cmd := newCmdSshWithOptions(o)
	if err := cmd.Flags().Parse([]string{
		"-F", sshCfgPath,
		"--tag", "mutated-before-validation",
		"--remember", "always",
		"saved-node",
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := o.Complete(cmd, cmd.Flags().Args()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	runErr := o.RunContext(t.Context())
	if runErr == nil {
		t.Fatal("expected RunContext to fail on Tier-4 ForkAfterAuthentication=yes without -N or command")
	}

	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	gotNode, ok := reloaded.Nodes.Get(nodeID)
	if !ok {
		t.Fatalf("missing node %q after failed RunContext", nodeID)
	}
	origNode, _ := cfg.Nodes.Get(nodeID)
	if !reflect.DeepEqual(gotNode, origNode) {
		t.Fatalf("failed invocation modified saved node on disk: got %+v, want %+v", gotNode, origNode)
	}
}

func TestRound3_P3_8_SftpErrorOrderNoFFlagAndMutualExclusion(t *testing.T) {
	// Guard against blocking on os.Stdin: use an open pipe with zero bytes written.
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = wPipe.Close() }()
	defer func() { _ = rPipe.Close() }()
	origStdin := os.Stdin
	os.Stdin = rPipe
	t.Cleanup(func() { os.Stdin = origStdin })

	runCompleteWithTimeout := func(t *testing.T, args []string, opts []string, setPwStdin bool) error {
		t.Helper()
		so := NewSftpOptions()
		cmd := NewCmdSftp()
		cmd.SetArgs(args)
		if setPwStdin {
			so.PasswordStdin = true
		}
		so.control.Options = append([]string(nil), opts...)
		done := make(chan error, 1)
		go func() {
			soCopy := so
			_ = cmd.Flags().Parse(args)
			done <- soCopy.Complete(cmd, cmd.Flags().Args())
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(500 * time.Millisecond):
			t.Fatal("SftpOptions.Complete attempted to read stdin before validation checks")
			return nil
		}
	}

	if err := runCompleteWithTimeout(t, []string{"host", "extra-arg"}, nil, true); err == nil || !strings.Contains(err.Error(), "unexpected positional argument") {
		t.Fatalf("expected extra positional argument error before reading stdin, got %v", err)
	}
	if err := runCompleteWithTimeout(t, []string{"host"}, []string{"ForkAfterAuthentication=yes"}, true); err == nil ||
		!strings.Contains(err.Error(), "ForkAfterAuthentication") ||
		strings.Contains(err.Error(), "(-f") {
		t.Fatalf("expected ForkAfterAuthentication error without -f before reading stdin, got %v", err)
	}

	// Validate & RunContext enforce force + noOverwrite mutual exclusion programmatically too.
	soMutex := NewSftpOptions()
	soMutex.Host = "web"
	soMutex.force = true
	soMutex.noOverwrite = true
	if err := soMutex.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("SftpOptions.Validate(force+noOverwrite) = %v, want mutually exclusive error", err)
	}
	if err := soMutex.RunContext(t.Context()); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("SftpOptions.RunContext(force+noOverwrite) = %v, want mutually exclusive error", err)
	}
}

func splitHostPortMust(t *testing.T, addr string) (string, string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	return h, p, 0
}
