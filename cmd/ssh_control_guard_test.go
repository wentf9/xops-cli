package cmd

import (
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

	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func shortControlTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "xops-ctl-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestControlFlagsValidateRejectsInvalidOption verifies that -o is validated
// before a command resolves or prepares a node, and also when -S makes path
// resolution return early. Otherwise a typo is silently ignored.
func TestControlFlagsValidateRejectsInvalidOption(t *testing.T) {
	for _, name := range []string{"ssh", "explicit -S"} {
		flags := SSHControlFlags{CtlCmd: "check", Options: []string{"ControlMaste=yes"}}
		if name == "explicit -S" {
			flags.ControlPath = "/tmp/explicit.sock"
		}
		if err := flags.Validate(); err == nil {
			t.Fatalf("%s: expected an unsupported -o option error", name)
		}
	}

	// A valid option set must keep working.
	valid := SSHControlFlags{CtlCmd: "check", Options: []string{"ControlPersist=10m", "Port=2222", "User=ops"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid -o options were rejected: %v", err)
	}

	// SshOptions.Validate runs the control validation before touching a node.
	options := NewSshOptions()
	options.Host = "192.0.2.10"
	options.control = SSHControlFlags{Options: []string{"Bogus=1"}}
	err := options.Validate()
	if err == nil || !strings.Contains(err.Error(), "unsupported -o option") {
		t.Fatalf("expected an unsupported -o option error from Validate, got %v", err)
	}
}

// TestParentDaemonDisablesNodeControlSharing verifies that a -f parent cannot
// claim the control socket the detached child must own, even when the session
// supplies -M/-S/-o for that node. A global disable would be outranked by the
// node-scoped session override.
func TestParentDaemonDisablesNodeControlSharing(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/global.sock", Persist: "1h"}),
	}
	cfg.Hosts.Set("host-1", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("id-1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		SSHOptions:  ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/node.sock", Persist: "10m"}),
	})
	provider := config.NewProviderWithoutOpenSSH(cfg)

	options := NewSshOptions()
	options.Remember = "never"
	options.control.MasterCount = 1 // -M

	adpOpts, err := options.buildAdapterOptions("web-01", cfg, nil)
	if err != nil {
		t.Fatalf("buildAdapterOptions failed: %v", err)
	}

	// Baseline: the session -M wins and keeps the node's control path, so the
	// parent would bind the socket without the dedicated disable.
	sessionOnly, err := adapter.NewSSHAdapter(provider, adpOpts...).GetControlConfig("web-01")
	if err != nil {
		t.Fatalf("ResolveControl failed: %v", err)
	}
	if sessionOnly == nil || sessionOnly.Master != ssh.ControlMasterYes || sessionOnly.Path != "/tmp/node.sock" {
		t.Fatalf("expected the session -M master on the node path, got %+v", sessionOnly)
	}

	adpOpts = append(adpOpts, disableSessionControlForParent("web-01"))
	disabled, err := adapter.NewSSHAdapter(provider, adpOpts...).GetControlConfig("web-01")
	if err != nil {
		t.Fatalf("ResolveControl with the parent disable failed: %v", err)
	}
	if disabled == nil || disabled.Path != "none" || disabled.Master != ssh.ControlMasterNo || disabled.Persist != "" {
		t.Fatalf("expected the -f parent to disable connection sharing, got %+v", disabled)
	}

	// ProxyJump hops must also have connection sharing disabled in the -f parent.
	cfg.Nodes.Set("jump-01", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		SSHOptions:  ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/jump.sock", Persist: "10m"}),
	})
	jumpDisabled, err := adapter.NewSSHAdapter(provider, adpOpts...).GetControlConfig("jump-01")
	if err != nil {
		t.Fatalf("ResolveControl for jump hop with parent disable failed: %v", err)
	}
	if jumpDisabled == nil || jumpDisabled.Path != "none" || jumpDisabled.Master != ssh.ControlMasterNo || jumpDisabled.Persist != "" {
		t.Fatalf("expected the -f parent to disable jump hop connection sharing, got %+v", jumpDisabled)
	}
}

// TestSftpExecScpValidateControlAndExtraArgs verifies that SftpOptions rejects
// unexpected positional arguments and that ExecOptions/ScpOptions validate -o
// control flags even when Validate is called directly.
func TestSftpExecScpValidateControlAndExtraArgs(t *testing.T) {
	sftpOpts := NewSftpOptions()
	sftpOpts.args = []string{"web-01", "unexpected-arg"}
	if err := sftpOpts.Validate(); err == nil || !strings.Contains(err.Error(), "unexpected positional argument") {
		t.Fatalf("expected SftpOptions.Validate to reject extra positional args, got %v", err)
	}

	execOpts := NewExecOptions()
	execOpts.Host = "web-01"
	execOpts.Command = "uptime"
	execOpts.control = SSHControlFlags{Options: []string{"BogusOption=1"}}
	if err := execOpts.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported -o option") {
		t.Fatalf("expected ExecOptions.Validate to reject invalid -o option, got %v", err)
	}

	scpOpts := NewScpOptions()
	scpOpts.Source = "local.txt"
	scpOpts.Dest = "web-01:/tmp/remote.txt"
	scpOpts.control = SSHControlFlags{Options: []string{"BogusOption=1"}}
	if err := scpOpts.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported -o option") {
		t.Fatalf("expected ScpOptions.Validate to reject invalid -o option, got %v", err)
	}
}

// TestMuxDaemonArgsBuildsSSHCommandForNonSSHInvocations verifies that when a
// persistent master is started by scp/sftp/exec, muxDaemonArgs constructs an
// `ssh -N` command line rather than re-running the transfer/batch subcommand.
func TestMuxDaemonArgsBuildsSSHCommandForNonSSHInvocations(t *testing.T) {
	opts := NewSshOptions()
	opts.Port = 2222
	opts.User = "deploy"
	opts.IdentityFile = "/tmp/id_ed25519"
	opts.JumpHost = "bastion"
	opts.Remember = "never"
	opts.control.Options = []string{"ControlPersist=10m"}

	args := opts.muxDaemonArgs("web-01", "/tmp/cm.sock", nil)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"ssh -N --host web-01 -S /tmp/cm.sock",
		"-p 2222",
		"-l deploy",
		"-i /tmp/id_ed25519",
		"-J bastion",
		"--remember never",
		"-o ControlPersist=10m",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("muxDaemonArgs = %q, missing %q", joined, want)
		}
	}
}

type staticHostKeyTrust struct{}

func (staticHostKeyTrust) Verify(context.Context, ssh.HostKeyRequest, cryptoSSH.PublicKey) error {
	return nil
}

// TestDrainOwnedMastersWaitsForSecondarySession verifies that when a foreground
// session finishes while another client session is attached to the connector's
// master, drainOwnedMasters waits for the secondary session to finish before
// allowing handoff or CloseAll to shut the master down.
func TestDrainOwnedMastersWaitsForSecondarySession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fixture.Close() }()

	host, portStr, err := net.SplitHostPort(fixture.Address)
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi failed: %v", err)
	}

	sockPath := filepath.Join(shortControlTempDir(t), "drain.sock")
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    sockPath,
			Persist: "10m",
		}),
	})
	provider := config.NewProviderWithoutOpenSSH(cfg)
	connector := adapter.NewConnector(provider, ssh.WithHostKeyVerifier(staticHostKeyTrust{}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	if _, err := connector.Connect(ctx, "web-01"); err != nil {
		t.Fatalf("connector.Connect failed: %v", err)
	}

	master := ssh.GetActiveMuxServer(sockPath)
	if master == nil {
		t.Fatal("expected active MuxServer on sockPath")
	}

	// Attach a secondary proxy client
	proxyCli, proxyConn, err := ssh.DialControlProxy(ctx, sockPath, master.Target())
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = proxyCli.Close()
		_ = proxyConn.Close()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for master.ActiveSessions() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if master.ActiveSessions() != 2 {
		t.Fatalf("expected ActiveSessions == 2, got %d", master.ActiveSessions())
	}

	done := make(chan error, 1)
	go func() {
		done <- drainOwnedMasters(ctx, connector)
	}()

	select {
	case err := <-done:
		t.Fatalf("drainOwnedMasters returned while secondary proxy client was still active: %v", err)
	case <-time.After(80 * time.Millisecond):
	}

	// Close the secondary proxy client; drainOwnedMasters must now unblock and
	// releaseMastersForHandoff must succeed cleanly.
	_ = proxyCli.Close()
	_ = proxyConn.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drainOwnedMasters failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("drainOwnedMasters did not return after secondary proxy client disconnected")
	}

	ready, err := releaseMastersForHandoff(connector, master, sockPath)
	if err != nil || !ready {
		t.Fatalf("expected releaseMastersForHandoff to succeed after drain, got ready=%v, err=%v", ready, err)
	}
}

// TestReleaseMastersForHandoffRestoresSessionOnFailure verifies that if
// PrepareHandoff refuses handoff (for example because a forward is still
// active), releaseMastersForHandoff restores the connector's foreground session
// reference so the master's idle timer cannot fire while waiting for drain.
func TestReleaseMastersForHandoffRestoresSessionOnFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fixture.Close() }()

	host, portStr, err := net.SplitHostPort(fixture.Address)
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi failed: %v", err)
	}

	sockPath := filepath.Join(shortControlTempDir(t), "restore.sock")
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    sockPath,
			Persist: "1s",
		}),
	})
	provider := config.NewProviderWithoutOpenSSH(cfg)
	connector := adapter.NewConnector(provider, ssh.WithHostKeyVerifier(staticHostKeyTrust{}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	if _, err := connector.Connect(ctx, "web-01"); err != nil {
		t.Fatalf("connector.Connect failed: %v", err)
	}
	master := ssh.GetActiveMuxServer(sockPath)
	if master == nil {
		t.Fatal("expected active MuxServer on sockPath")
	}

	muxCli, err := ssh.DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	fwd := ssh.ForwardRequest{Type: ssh.ForwardLocal, ListenHost: "127.0.0.1", ConnectHost: "127.0.0.1", ConnectPort: 22}
	if _, err := muxCli.OpenForward(ctx, fwd); err != nil {
		t.Fatalf("OpenForward failed: %v", err)
	}

	ready, err := releaseMastersForHandoff(connector, master, sockPath)
	if err != nil || ready {
		t.Fatalf("expected releaseMastersForHandoff to refuse while forward is active, got ready=%v, err=%v", ready, err)
	}
	if !connector.HasMasterSession(master) || master.ActiveSessions() != 1 {
		t.Fatalf("expected foreground session to be restored (has=%v, active=%d)", connector.HasMasterSession(master), master.ActiveSessions())
	}

	// Wait 1.2s (> Persist 1s); master must stay alive because the foreground
	// session reference was restored.
	time.Sleep(1200 * time.Millisecond)
	select {
	case <-master.Wait():
		t.Fatal("master shut down on idle timeout after handoff rollback")
	default:
	}

	if err := muxCli.CloseForward(ctx, fwd); err != nil {
		t.Fatalf("CloseForward failed: %v", err)
	}
	ready, err = releaseMastersForHandoff(connector, master, sockPath)
	if err != nil || !ready {
		t.Fatalf("expected releaseMastersForHandoff to succeed after forward closed, got ready=%v, err=%v", ready, err)
	}
}

// TestScpResolvedTargetNodeIDsIncludesDerivedUserOverride verifies that when
// scp targets an existing host with a different user@ prefix, resolvedTargetNodeIDs
// includes the derived user@host:port node ID that PrepareNodeContext creates.
func TestScpResolvedTargetNodeIDsIncludesDerivedUserOverride(t *testing.T) {
	repo := setupNonDefaultPortWithProxyJumpRepo(t)
	scpOpts := NewScpOptions()
	scpOpts.Source = "local.txt"
	scpOpts.Dest = "test@10.0.0.5:/tmp/remote.txt"

	ids := scpOpts.resolvedTargetNodeIDs(repo)
	found := false
	for _, id := range ids {
		if id == "test@10.0.0.5:2222" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("resolvedTargetNodeIDs = %v, missing derived node ID test@10.0.0.5:2222", ids)
	}
}

// TestCompleteDoesNotEnableStdinScriptForControlCommand verifies that piped or
// /dev/null stdin during `xops ssh -O ...` does not set o.stdinScript = true
// (which would fail Validate when combined with -N or other flags).
func TestCompleteDoesNotEnableStdinScriptForControlCommand(t *testing.T) {
	opts := NewSshOptions()
	opts.NoCmd = true
	opts.control = SSHControlFlags{
		CtlCmd:      "proxy",
		ControlPath: "/tmp/test.sock",
	}
	cmd := newCmdSshWithOptions(opts)
	if err := opts.Complete(cmd, []string{"web-01"}); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if opts.stdinScript {
		t.Fatal("expected stdinScript to remain false when -O control command is set")
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate failed for -N -O proxy with non-TTY test stdin: %v", err)
	}
}

// TestHandoffPersistentMasterNotSkippedAfterTunnelClose verifies that closing
// sshTunnelGroup (which cancels runCtx) does not prevent handoffPersistentMaster
// from running when the outer command context ctx is still active.
func TestHandoffPersistentMasterNotSkippedAfterTunnelClose(t *testing.T) {
	outerCtx, cancelOuter := context.WithCancel(context.Background())
	defer cancelOuter()

	runCtx, cancelRun := context.WithCancel(outerCtx)
	tunnels, _ := newSSHTunnelGroup(outerCtx, cancelRun)
	if err := tunnels.Close(); err != nil {
		t.Fatalf("tunnels.Close failed: %v", err)
	}
	if runCtx.Err() == nil {
		t.Fatal("expected tunnels.Close to cancel runCtx")
	}
	if outerCtx.Err() != nil {
		t.Fatal("expected outerCtx to remain active after normal tunnel close")
	}
}

// TestSshDoubleDashHostCommand verifies that `xops ssh -- <host> <cmd>` assigns
// the first positional argument after `--` to Host and the remainder to Command
// when --host was not specified via flag.
func TestSshDoubleDashHostCommand(t *testing.T) {
	opts := NewSshOptions()
	cmd := newCmdSshWithOptions(opts)
	if err := cmd.Flags().Parse([]string{"--", "web-01", "uname", "-a"}); err != nil {
		t.Fatalf("Flags().Parse failed: %v", err)
	}
	if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	opts.stdinScript = false
	if err := opts.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if opts.Host != "web-01" {
		t.Fatalf("expected Host=%q, got %q", "web-01", opts.Host)
	}
	if opts.Command != "uname -a" {
		t.Fatalf("expected Command=%q, got %q", "uname -a", opts.Command)
	}
}

// TestMultiHostHandoff_PreservesAllTargetMasters verifies that releasing one
// target master for handoff only releases that master and its ProxyJump chain,
// leaving unrelated target masters in the same connector intact for subsequent
// handoff iterations (e.g. remote-to-remote `xops scp hostA:file hostB:file`).
func TestMultiHostHandoff_PreservesAllTargetMasters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixA, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New(A) failed: %v", err)
	}
	defer func() { _ = fixA.Close() }()
	fixB, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New(B) failed: %v", err)
	}
	defer func() { _ = fixB.Close() }()

	hostA, portAStr, _ := net.SplitHostPort(fixA.Address)
	portA, _ := strconv.Atoi(portAStr)
	hostB, portBStr, _ := net.SplitHostPort(fixB.Address)
	portB, _ := strconv.Atoi(portBStr)

	tmpDir := shortControlTempDir(t)
	sockA := filepath.Join(tmpDir, "hostA.sock")
	sockB := filepath.Join(tmpDir, "hostB.sock")

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Identities.Set("id1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Hosts.Set("hA", models.Host{Address: hostA, Port: uint16(portA)})
	cfg.Hosts.Set("hB", models.Host{Address: hostB, Port: uint16(portB)})
	cfg.Nodes.Set("nodeA", models.Node{
		HostRef:     "hA",
		IdentityRef: "id1",
		SSHOptions:  ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: sockA, Persist: "10m"}),
	})
	cfg.Nodes.Set("nodeB", models.Node{
		HostRef:     "hB",
		IdentityRef: "id1",
		SSHOptions:  ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: sockB, Persist: "10m"}),
	})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	connector := adapter.NewConnector(provider, ssh.WithHostKeyVerifier(staticHostKeyTrust{}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	if _, err := connector.Connect(ctx, "nodeA"); err != nil {
		t.Fatalf("Connect(nodeA) failed: %v", err)
	}
	if _, err := connector.Connect(ctx, "nodeB"); err != nil {
		t.Fatalf("Connect(nodeB) failed: %v", err)
	}

	masterA := ssh.GetActiveMuxServer(sockA)
	masterB := ssh.GetActiveMuxServer(sockB)
	if masterA == nil || masterB == nil {
		t.Fatalf("expected both masterA (%v) and masterB (%v) to exist", masterA, masterB)
	}

	// Releasing masterA for handoff must NOT shut down masterB or remove it from connector!
	readyA, err := releaseMastersForHandoff(connector, masterA, sockA)
	if err != nil || !readyA {
		t.Fatalf("releaseMastersForHandoff(masterA) failed: ready=%v err=%v", readyA, err)
	}

	if gotB := ssh.GetActiveMuxServer(sockB); gotB != masterB || !connector.HasMasterSession(masterB) {
		t.Fatalf("releasing masterA destroyed unrelated target masterB (got %v, hasSession=%v)", gotB, connector.HasMasterSession(masterB))
	}

	readyB, err := releaseMastersForHandoff(connector, masterB, sockB)
	if err != nil || !readyB {
		t.Fatalf("releaseMastersForHandoff(masterB) failed: ready=%v err=%v", readyB, err)
	}
}

// TestHandoffSkipsImplicitTier4Control verifies Decision 1.A: when multiplexing
// configuration comes solely from Tier 4 (~/.ssh/config) without explicit CLI
// flags or xops config, ResolveControl marks ImplicitTier4=true and
// handoffMasterInstance does NOT spawn a background daemon on command exit
// (releasing the in-process master cleanly instead).
func TestHandoffSkipsImplicitTier4Control(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fix.Close() }()

	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)
	sockPath := filepath.Join(shortControlTempDir(t), "tier4.sock")

	openSSHContent := "Host web-tier4\n" +
		"    ControlMaster auto\n" +
		"    ControlPath " + sockPath + "\n" +
		"    ControlPersist 10m\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHContent))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("web-tier4", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
	})

	provider := config.NewProviderWithOpenSSHParser(cfg, parser)
	adp := adapter.NewSSHAdapter(provider)

	ctrl, err := adp.GetControlConfig("web-tier4")
	if err != nil {
		t.Fatalf("GetControlConfig failed: %v", err)
	}
	if ctrl == nil || !ctrl.ImplicitTier4 {
		t.Fatalf("expected ImplicitTier4=true for pure Tier 4 config, got %+v", ctrl)
	}

	connector := ssh.NewConnector(adp, ssh.WithHostKeyVerifier(staticHostKeyTrust{}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	if _, err := connector.Connect(ctx, "web-tier4"); err != nil {
		t.Fatalf("Connect(web-tier4) failed: %v", err)
	}
	master := ssh.GetActiveMuxServer(sockPath)
	if master == nil {
		t.Fatal("expected in-process master to start during session")
	}

	opts := NewSshOptions()
	if err := opts.handoffMasterInstance(ctx, connector, master, "web-tier4"); err != nil {
		t.Fatalf("handoffMasterInstance returned unexpected error: %v", err)
	}

	// Because ImplicitTier4 is true, handoffMasterInstance must NOT have detached
	// a background daemon; closing the connector now shuts down the in-process
	// master and removes the socket.
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("connector.CloseAll failed: %v", err)
	}
	if _, dialErr := ssh.DialMuxClient(ctx, sockPath); dialErr == nil {
		t.Fatal("expected no detached background master to remain on sockPath for ImplicitTier4 config")
	}

	// R2-5: Even if Tier 1 overrides -S (ControlPath), inheriting ControlPersist
	// solely from Tier 4 must keep ImplicitTier4=true.
	overridePath := filepath.Join(shortControlTempDir(t), "override.sock")
	adpWithPathOverride := adapter.NewSSHAdapter(
		provider,
		adapter.WithSessionControlOverride("web-tier4", adapter.SessionControlOptions{Path: &overridePath}),
	)
	ctrlOverride, err := adpWithPathOverride.GetControlConfig("web-tier4")
	if err != nil {
		t.Fatalf("GetControlConfig with path override failed: %v", err)
	}
	if ctrlOverride == nil || !ctrlOverride.ImplicitTier4 {
		t.Fatalf("expected ImplicitTier4=true when Persist comes solely from Tier 4, got %+v", ctrlOverride)
	}
}

// TestMuxDaemonArgsAndTargetResolutionForVirtualAndPendingNodes verifies R2-1:
// muxDaemonArgs strips "openssh:" and falls back to master.Target() for port/user,
// and PrepareNodeContext resolves "openssh:<ip>" and unconfirmed "user@ip:port"
// selectors without wrapping them as IPv6 literals.
func TestMuxDaemonArgsAndTargetResolutionForVirtualAndPendingNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fix.Close() }()

	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)
	sockPath := filepath.Join(shortControlTempDir(t), "r2-1.sock")

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial failed: %v", err)
	}
	defer func() { _ = rawClient.Close() }()

	master, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: sockPath,
		Target: ssh.TargetContext{
			Host:         host,
			Port:         port,
			User:         "fixture",
			OriginalHost: "openssh:" + host,
			Control: &ssh.ControlConfig{
				Master:  ssh.ControlMasterAuto,
				Path:    sockPath,
				Persist: "10m",
			},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer failed: %v", err)
	}
	defer func() { _ = master.Shutdown() }()

	// Simulate scp/exec where o.Port == 0 and o.User == "" on SshOptions.
	opts := NewSshOptions()
	args := opts.muxDaemonArgs("openssh:"+host, sockPath, master)
	joined := strings.Join(args, " ")
	wantPrefix := "ssh -N --host " + host + " -S " + sockPath
	if !strings.Contains(joined, wantPrefix) {
		t.Fatalf("muxDaemonArgs = %q, expected %q (with openssh: stripped)", joined, wantPrefix)
	}
	if !strings.Contains(joined, "-p "+strconv.Itoa(port)) || !strings.Contains(joined, "-l fixture") {
		t.Fatalf("muxDaemonArgs = %q, expected fallback -p %d and -l fixture from master.Target()", joined, port)
	}

	// Verify PrepareNodeContext resolves unconfirmed "user@host:port" and "openssh:host"
	// selectors to clean host addresses rather than bracketed IPv6 literals.
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}

	for _, sel := range []string{"openssh:" + host, "fixture@" + host + ":" + strconv.Itoa(port)} {
		res, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
			Target: config.ConnectionTarget{
				Selector: sel,
				User:     "fixture",
				HasUser:  true,
				Port:     uint16(port),
				HasPort:  true,
			},
		})
		if err != nil {
			t.Fatalf("PrepareNodeContext(%q) failed: %v", sel, err)
		}
		_, hostCfg, _, err := repo.Resolve(res.NodeID)
		if err != nil {
			t.Fatalf("Resolve(%q) failed: %v", res.NodeID, err)
		}
		if hostCfg.Address != host {
			t.Fatalf("Selector %q resolved to Address %q, want %q", sel, hostCfg.Address, host)
		}
	}
}

// TestMuxDaemonArgsIsolationAndRememberSuppression verifies R3-1:
//   - muxDaemonArgs always appends "--remember never".
//   - When master != nil, muxDaemonArgs prefers master.Target().Port, User, and
//     JumpHost over SshOptions fields and drops target-specific -o options
//     (Port, User, ProxyJump) so jump-master or multi-host handoffs never inherit
//     the foreground target's flags.
//   - When isMuxDaemonChild() is true (XOPS_CLI_SSH_MUX_DAEMON=true), resolveNode
//     does not persist or mutate nodes even if Remember was set to "always".
func TestMuxDaemonArgsIsolationAndRememberSuppression(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fix.Close() }()

	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)
	sockPath := filepath.Join(shortControlTempDir(t), "r3-1.sock")

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial failed: %v", err)
	}
	defer func() { _ = rawClient.Close() }()

	jumpMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: sockPath,
		Target: ssh.TargetContext{
			Host:         host,
			Port:         port,
			User:         "jumpuser",
			OriginalHost: "bastion",
			JumpHost:     "",
			Control: &ssh.ControlConfig{
				Master:  ssh.ControlMasterAuto,
				Path:    sockPath,
				Persist: "5m",
			},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer failed: %v", err)
	}
	defer func() { _ = jumpMaster.Shutdown() }()

	opts := NewSshOptions()
	opts.Host = "target-host"
	opts.Port = 2222
	opts.User = "targetuser"
	opts.IdentityFile = "/tmp/target-only-id"
	opts.JumpHost = "bastion"
	opts.control.Options = []string{
		"ProxyJump=bastion",
		"Port=2222",
		"User=targetuser",
		"IdentityFile=/tmp/target-only-id",
		"ControlMaster=auto",
		"StrictHostKeyChecking=no",
		"PubkeyAuthentication=no",
		"UserKnownHostsFile=/tmp/target_kh",
	}

	args := opts.muxDaemonArgs("bastion", sockPath, jumpMaster)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--remember never") {
		t.Fatalf("expected --remember never in muxDaemonArgs, got %q", joined)
	}
	if !strings.Contains(joined, "-p "+strconv.Itoa(port)) || !strings.Contains(joined, "-l jumpuser") {
		t.Fatalf("expected jumpMaster's port %d and user jumpuser, got %q", port, joined)
	}
	for _, forbidden := range []string{
		"-J ",
		"ProxyJump=",
		"2222",
		"targetuser",
		"target-only-id",
		"-i ",
		"StrictHostKeyChecking=no",
		"PubkeyAuthentication=no",
		"UserKnownHostsFile=",
		"ControlMaster=auto",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("expected target-scoped option %q to be stripped for jumpMaster, got %q", forbidden, joined)
		}
	}
	if !strings.Contains(joined, "-o ControlPersist=5m") || !strings.Contains(joined, "-o ControlMaster=yes") {
		t.Fatalf("expected jumpMaster's own ControlPersist=5m and ControlMaster=yes, got %q", joined)
	}

	// Verify resolveNode in mux daemon child mode never persists an unconfirmed target.
	t.Setenv(sshMuxDaemonEnv, "true")
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	daemonOpts := NewSshOptions()
	daemonOpts.Host = host
	daemonOpts.Port = uint16(port)
	daemonOpts.User = "fixture"
	daemonOpts.Remember = "always"
	daemonOpts.IdentityFile = "/tmp/test-key"
	daemonOpts.Target = config.ConnectionTarget{
		Selector: host,
		User:     "fixture",
		HasUser:  true,
		Port:     uint16(port),
		HasPort:  true,
	}

	nodeID, _, err := daemonOpts.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("resolveNode in daemon mode failed: %v", err)
	}
	adpOpts, err := daemonOpts.buildAdapterOptions(nodeID, repo.Snapshot(), repo)
	if err != nil {
		t.Fatalf("buildAdapterOptions in daemon mode failed: %v", err)
	}
	adp := adapter.NewSSHAdapter(repo, adpOpts...)
	if _, err := adp.UpdateAuth(ctx, nodeID, "tok", "secret", "", ""); err != nil {
		t.Fatalf("UpdateAuth in daemon mode failed: %v", err)
	}
	if cfg.Nodes.Count() != 0 {
		t.Fatalf("expected 0 persisted nodes in mux daemon child mode, got %d", cfg.Nodes.Count())
	}
}

// TestOpenSSHVirtualNodeOverridesDoNotFailOrPersist verifies R3-2:
// OpenSSH virtual nodes ("openssh:<alias>") work with CLI overrides (-i, -J) in
// ssh, scp, and exec without failing with ErrNodeNotFound or writing bogus
// TestOpenSSHVirtualNodeOverridesDoNotFailOrPersist verifies R3-2 and R4-1:
// When connecting to an OpenSSH virtual node with CLI overrides (-i, -J, etc.),
// ssh/scp/exec must not attempt to persist or mutate the read-only
// "openssh:<alias>" entries into Repository, MUST apply -J (ProxyJump) via
// SessionAuth override, and MUST fail fast if -J cannot be resolved.
func TestOpenSSHVirtualNodeOverridesDoNotFailOrPersist(t *testing.T) {
	ctx := context.Background()
	content := "Host demo-alias\n  HostName 127.0.0.1\n  User demo\n  Port 2200\nHost bastion\n  HostName 127.0.0.1\n  User jump\n  Port 2201\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(content))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser failed: %v", err)
	}

	// 1. ssh resolveNode + buildAdapterOptions with -i and -J on an OpenSSH virtual node.
	verifyOpenSSHVirtualNodeSSHOverride(t, ctx, repo, cfg)

	// 2. scp getOrCreateNodeForPath + credentialConnectorWithInteraction with -i and -J.
	scpOpts := NewScpOptions()
	scpOpts.Source = "demo-alias:/tmp/file.txt"
	scpOpts.Dest = "/tmp/local.txt"
	scpOpts.IdentityFile = "/tmp/override_id_ed25519"
	scpOpts.JumpHost = "bastion"
	scpNodeID, _, err := scpOpts.getOrCreateNodeForPath(ctx, repo, PathInfo{Host: "demo-alias", Path: "/tmp/file.txt", IsRemote: true}, "")
	if err != nil {
		t.Fatalf("ScpOptions.getOrCreateNodeForPath for OpenSSH alias failed: %v", err)
	}
	if scpNodeID != "openssh:demo-alias" {
		t.Fatalf("expected scpNodeID %q, got %q", "openssh:demo-alias", scpNodeID)
	}
	if cfg.Nodes.Count() != 0 {
		t.Fatalf("expected 0 persisted nodes after ScpOptions.getOrCreateNodeForPath, got %d", cfg.Nodes.Count())
	}
	conn, err := scpOpts.credentialConnectorWithInteraction(repo, cfg, newCLIInteractionHandler())
	if err != nil || conn == nil {
		t.Fatalf("expected non-nil connector from ScpOptions.credentialConnectorWithInteraction, err=%v", err)
	}

	// 3. exec getOrCreateNode + buildAdapterOptions on an OpenSSH virtual node.
	verifyOpenSSHVirtualNodeExecOverride(t, ctx, repo, cfg)
}

func verifyOpenSSHVirtualNodeSSHOverride(t *testing.T, ctx context.Context, repo *config.Repository, cfg *config.Configuration) {
	t.Helper()
	sshOpts := NewSshOptions()
	sshOpts.Host = "demo-alias"
	sshOpts.IdentityFile = "/tmp/override_id_ed25519"
	sshOpts.JumpHost = "bastion"
	sshOpts.Target = config.ConnectionTarget{
		Selector:     "demo-alias",
		ProxyJump:    "bastion",
		HasProxyJump: true,
	}
	nodeID, _, err := sshOpts.resolveNode(ctx, repo)
	if err != nil {
		t.Fatalf("SshOptions.resolveNode for OpenSSH alias with overrides failed: %v", err)
	}
	if nodeID != "openssh:demo-alias" {
		t.Fatalf("expected nodeID %q, got %q", "openssh:demo-alias", nodeID)
	}
	if cfg.Nodes.Count() != 0 {
		t.Fatalf("expected 0 persisted nodes after SshOptions.resolveNode, got %d", cfg.Nodes.Count())
	}
	sshAdpOpts, err := sshOpts.buildAdapterOptions(nodeID, cfg, repo)
	if err != nil {
		t.Fatalf("SshOptions.buildAdapterOptions failed: %v", err)
	}
	sshAdp := adapter.NewSSHAdapter(repo, sshAdpOpts...)
	sshClientCfg, err := sshAdp.GetConfig(nodeID)
	if err != nil {
		t.Fatalf("sshAdp.GetConfig(%q) failed: %v", nodeID, err)
	}
	if sshClientCfg.ProxyJump != "openssh:bastion" {
		t.Fatalf("expected sshClientCfg.ProxyJump == %q, got %q", "openssh:bastion", sshClientCfg.ProxyJump)
	}

	// Invalid -J on OpenSSH virtual node must fail validation in update.
	sshBadJump := NewSshOptions()
	sshBadJump.Host = "demo-alias"
	sshBadJump.JumpHost = "nonexistent-jump-alias"
	sshBadJump.Target = config.ConnectionTarget{Selector: "demo-alias", ProxyJump: "nonexistent-jump-alias", HasProxyJump: true}
	if _, _, err := sshBadJump.resolveNode(ctx, repo); err == nil {
		t.Fatal("expected SshOptions.resolveNode to fail on nonexistent ProxyJump override")
	}
}

func verifyOpenSSHVirtualNodeExecOverride(t *testing.T, ctx context.Context, repo *config.Repository, cfg *config.Configuration) {
	t.Helper()
	execOpts := NewExecOptions()
	execOpts.IdentityFile = "/tmp/override_id_ed25519"
	execOpts.JumpHost = "bastion"
	execNodeID, _, err := execOpts.getOrCreateNode(ctx, repo, config.ConnectionTarget{
		Selector:     "demo-alias",
		ProxyJump:    "bastion",
		HasProxyJump: true,
	}, cmdutils.HostInfo{
		Host:    "demo-alias",
		KeyPath: "/tmp/override_id_ed25519",
	})
	if err != nil {
		t.Fatalf("ExecOptions.getOrCreateNode for OpenSSH alias failed: %v", err)
	}
	if execNodeID != "openssh:demo-alias" {
		t.Fatalf("expected execNodeID %q, got %q", "openssh:demo-alias", execNodeID)
	}
	if cfg.Nodes.Count() != 0 {
		t.Fatalf("expected 0 persisted nodes after ExecOptions.getOrCreateNode, got %d", cfg.Nodes.Count())
	}
	execAdpOpts, err := execOpts.buildAdapterOptions([]execHostTask{{
		nodeID:  execNodeID,
		host:    "demo-alias",
		keyPath: "/tmp/override_id_ed25519",
	}}, cfg, repo)
	if err != nil {
		t.Fatalf("ExecOptions.buildAdapterOptions failed: %v", err)
	}
	execAdp := adapter.NewSSHAdapter(repo, execAdpOpts...)
	execClientCfg, err := execAdp.GetConfig(execNodeID)
	if err != nil {
		t.Fatalf("execAdp.GetConfig(%q) failed: %v", execNodeID, err)
	}
	if execClientCfg.ProxyJump != "openssh:bastion" {
		t.Fatalf("expected execClientCfg.ProxyJump == %q, got %q", "openssh:bastion", execClientCfg.ProxyJump)
	}
}

// TestHandoffConnectorMastersDoesNotSkipPersistentJumpForNonPersistentTarget verifies R3-3:
// When a target node's master does NOT have ControlPersist enabled (e.g.
// ControlMaster=auto, ControlPersist=no), handoffConnectorMasters does not add
// its JumpHost to the suppressed jumps map, allowing a persistent jump master
// (with ImplicitTier4=true so we can test the loop without spawning an OS process)
// to be visited by handoffMasterInstance.
func TestHandoffConnectorMastersDoesNotSkipPersistentJumpForNonPersistentTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fix.Close() }()

	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)
	jumpSock := filepath.Join(shortControlTempDir(t), "jump.sock")
	targetSock := filepath.Join(shortControlTempDir(t), "target.sock")

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h-jump", models.Host{Address: host, Port: uint16(port)})
	cfg.Hosts.Set("h-target", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("bastion", models.Node{
		HostRef:     "h-jump",
		IdentityRef: "id1",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    jumpSock,
			Persist: "5m",
		}),
	})
	cfg.Nodes.Set("app", models.Node{
		HostRef:     "h-target",
		IdentityRef: "id1",
		ProxyJump:   "bastion",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    targetSock,
			Persist: "no",
		}),
	})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	adp := adapter.NewSSHAdapter(provider)
	connector := ssh.NewConnector(adp, ssh.WithHostKeyVerifier(staticHostKeyTrust{}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	if _, err := connector.Connect(ctx, "app"); err != nil {
		t.Fatalf("Connect(app) via bastion failed: %v", err)
	}

	jumpMaster := ssh.GetActiveMuxServer(jumpSock)
	targetMaster := ssh.GetActiveMuxServer(targetSock)
	if jumpMaster == nil || targetMaster == nil {
		t.Fatalf("expected both jumpMaster (%v) and targetMaster (%v) to be active", jumpMaster, targetMaster)
	}
	if !jumpMaster.PersistEnabled() {
		t.Fatal("expected jumpMaster.PersistEnabled() == true")
	}
	if targetMaster.PersistEnabled() {
		t.Fatal("expected targetMaster.PersistEnabled() == false")
	}

	// Verify persistentJumpHops used by handoffConnectorMasters: non-persistent
	// targetMaster must NOT mark "bastion" as a suppressed jump hop.
	jumps := persistentJumpHops(connector.Masters())
	if jumps["bastion"] {
		t.Fatal("expected bastion NOT to be suppressed in jumps when targetMaster is non-persistent")
	}
}

// TestMuxDaemonKeepsJumpMasterReferenceUntilTargetExits verifies R4-2:
//  1. prepareMuxDaemonSession releases only the terminal targetMaster while
//     keeping the foreground session reference on upstream jumpMaster so a
//     shorter jump ControlPersist cannot tear down targetMaster's tunnel.
//  2. waitForDaemonJumpMasters releases and waits for jumpMaster after
//     targetMaster exits.
//  3. canHandoffMaster returns false for ImplicitTier4 or ControlMasterAsk, so
//     persistentJumpHops does not suppress a persistent jump hop when the target
//     master cannot be handed off.
func TestMuxDaemonKeepsJumpMasterReferenceUntilTargetExits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fix.Close() }()

	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)
	jumpSock := filepath.Join(shortControlTempDir(t), "jump-daemon.sock")
	targetSock := filepath.Join(shortControlTempDir(t), "target-daemon.sock")

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h-jump", models.Host{Address: host, Port: uint16(port)})
	cfg.Hosts.Set("h-target", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("bastion", models.Node{
		HostRef:     "h-jump",
		IdentityRef: "id1",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterAuto,
			Path:    jumpSock,
			Persist: "1s",
		}),
	})
	cfg.Nodes.Set("app", models.Node{
		HostRef:     "h-target",
		IdentityRef: "id1",
		ProxyJump:   "bastion",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterAutoAsk,
			Path:    targetSock,
			Persist: "5m",
		}),
	})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	adp := adapter.NewSSHAdapter(provider)
	connector := ssh.NewConnector(adp, ssh.WithHostKeyVerifier(staticHostKeyTrust{}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, "app")
	if err != nil {
		t.Fatalf("Connect(app) via bastion failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	jumpMaster := ssh.GetActiveMuxServer(jumpSock)
	targetMaster := ssh.GetActiveMuxServer(targetSock)
	if jumpMaster == nil || targetMaster == nil {
		t.Fatalf("expected both jumpMaster (%v) and targetMaster (%v) to be active", jumpMaster, targetMaster)
	}

	// Because targetMaster has ControlMasterAutoAsk, canHandoffMaster(targetMaster)
	// must be false and persistentJumpHops must not suppress "bastion".
	if canHandoffMaster(targetMaster) {
		t.Fatal("expected canHandoffMaster(targetMaster) == false for ControlMasterAutoAsk")
	}
	if !canHandoffMaster(jumpMaster) {
		t.Fatal("expected canHandoffMaster(jumpMaster) == true")
	}
	if jumps := persistentJumpHops(connector.Masters()); jumps["bastion"] {
		t.Fatal("expected bastion NOT to be suppressed when targetMaster has ControlMasterAutoAsk")
	}

	if err := prepareMuxDaemonSession(connector, targetMaster, "app"); err != nil {
		t.Fatalf("prepareMuxDaemonSession failed: %v", err)
	}
	if targetMaster.ActiveSessions() != 0 {
		t.Fatalf("expected targetMaster.ActiveSessions() == 0 after prepareMuxDaemonSession, got %d", targetMaster.ActiveSessions())
	}
	if jumpMaster.ActiveSessions() != 1 {
		t.Fatalf("expected jumpMaster.ActiveSessions() == 1 while targetMaster is alive, got %d", jumpMaster.ActiveSessions())
	}

	// Once targetMaster exits and waitForDaemonJumpMasters runs, jumpMaster
	// releases its foreground reference (ActiveSessions drops to 0) and exits
	// after its 1s persist timer.
	_ = targetMaster.Shutdown()
	_ = client.Close()
	waitForDaemonJumpMasters(ctx, connector, targetMaster)
	if jumpMaster.ActiveSessions() != 0 {
		t.Fatalf("expected jumpMaster.ActiveSessions() == 0 after waitForDaemonJumpMasters, got %d", jumpMaster.ActiveSessions())
	}
	select {
	case <-jumpMaster.Wait():
	default:
		t.Fatal("expected jumpMaster to have exited after waitForDaemonJumpMasters")
	}
}

// TestPrepareNodeContextDisambiguatesSelectorAndOpenSSHVirtualNode verifies R4-3:
//  1. When two configured nodes share the same (user, address, port), explicitly
//     specifying -p / -l alongside a node ID or alias selector narrows matches
//     to the named node instead of returning AmbiguousNodeError.
//  2. When an OpenSSH virtual node matches the explicit user and port,
//     PrepareNodeContext returns "openssh:<alias>" in-memory without persisting.
func TestPrepareNodeContextDisambiguatesSelectorAndOpenSSHVirtualNode(t *testing.T) {
	ctx := context.Background()
	content := "Host demo-alias\n  HostName 10.0.0.50\n  User demo\n  Port 2222\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(content))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.10", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "root", AuthType: "password"})
	cfg.Nodes.Set("node-a", models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{"alias-a"}})
	cfg.Nodes.Set("node-b", models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{"alias-b"}})

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser failed: %v", err)
	}

	// 1a. Selector is exact node ID "node-a" with explicit -p 22 -l root.
	res, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector: "node-a",
			User:     "root",
			HasUser:  true,
			Port:     22,
			HasPort:  true,
		},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(node-a, root, 22) failed: %v", err)
	}
	if res.NodeID != "node-a" || res.Created {
		t.Fatalf("expected existing node-a, got NodeID=%q Created=%v", res.NodeID, res.Created)
	}

	// 1b. Selector is exact alias "alias-b" with explicit -p 22.
	resAlias, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector: "alias-b",
			Port:     22,
			HasPort:  true,
		},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(alias-b, 22) failed: %v", err)
	}
	if resAlias.NodeID != "node-b" || resAlias.Created {
		t.Fatalf("expected existing node-b, got NodeID=%q Created=%v", resAlias.NodeID, resAlias.Created)
	}

	// 2. OpenSSH virtual node with matching explicit user and port resolves to
	// "openssh:demo-alias" without creating a pending/persisted node.
	resOpenSSH, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector: "demo-alias",
			User:     "demo",
			HasUser:  true,
			Port:     2222,
			HasPort:  true,
		},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(demo-alias, demo, 2222) failed: %v", err)
	}
	if resOpenSSH.NodeID != "openssh:demo-alias" || resOpenSSH.Created {
		t.Fatalf("expected existing openssh:demo-alias, got NodeID=%q Created=%v", resOpenSSH.NodeID, resOpenSSH.Created)
	}
}

// TestControlTargetNormalizesProxyJump verifies R5-1:
// controlTarget must normalize explicit -J / ProxyJump overrides via
// provider.ResolveProxyJumpChain so ControlPath token expansion (%j, %C) and
// -O proxy target matching agree with Connector.buildTargetContext.
func TestControlTargetNormalizesProxyJump(t *testing.T) {
	content := "Host demo-target\n  HostName 10.0.0.20\n  User demo\n  Port 2200\nHost bastion\n  HostName 10.0.0.1\n  User jump\n  Port 2201\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(content))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	opts := NewSshOptions()
	opts.Host = "demo-target"
	opts.JumpHost = "bastion"
	opts.Target = config.ConnectionTarget{
		Selector:     "demo-target",
		ProxyJump:    "bastion",
		HasProxyJump: true,
	}

	target := controlTarget(opts, provider, "openssh:demo-target")
	if target.JumpHost != "openssh:bastion" {
		t.Fatalf("expected normalized JumpHost %q, got %q", "openssh:bastion", target.JumpHost)
	}
	masterTarget := ssh.TargetContext{
		Host:         "10.0.0.20",
		Port:         2200,
		User:         "demo",
		OriginalHost: "openssh:demo-target",
		JumpHost:     "openssh:bastion",
	}
	if !target.MatchesMasterTarget(masterTarget.CanonicalTargetIdentity()) {
		t.Fatalf("expected controlTarget to match master target with normalized JumpHost")
	}
}

// TestScpResolvedTargetNodeIDsIncludesTagAndHostFile verifies R5-2:
// ScpOptions.resolvedTargetNodeIDs must resolve nodes from --tag (o.Tag) and
// -I (o.HostFile) so batch SCP does not fall back to global session auth/control.
func TestScpResolvedTargetNodeIDsIncludesTagAndHostFile(t *testing.T) {
	content := "Host file-alias\n  HostName 10.0.0.30\n  User fileuser\n  Port 2202\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(content))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.40", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "password"})
	cfg.Nodes.Set("tagged-node", models.Node{HostRef: "h1", IdentityRef: "id1", Tags: []string{"prod"}})

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser failed: %v", err)
	}

	// 1. --tag mode
	tagOpts := NewScpOptions()
	tagOpts.Tag = "prod"
	tagOpts.Source = "/tmp/local.txt"
	tagOpts.Dest = "/tmp/remote.txt"
	tagIDs := tagOpts.resolvedTargetNodeIDs(repo)
	if !slices.Contains(tagIDs, "tagged-node") {
		t.Fatalf("expected resolvedTargetNodeIDs for --tag prod to contain %q, got %v", "tagged-node", tagIDs)
	}

	// 2. -I (HostFile) mode
	hostFile := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(hostFile, []byte("file-alias\n"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	fileOpts := NewScpOptions()
	fileOpts.HostFile = hostFile
	fileOpts.Source = "/tmp/local.txt"
	fileOpts.Dest = "/tmp/remote.txt"
	fileIDs := fileOpts.resolvedTargetNodeIDs(repo)
	if !slices.Contains(fileIDs, "openssh:file-alias") {
		t.Fatalf("expected resolvedTargetNodeIDs for -I hosts.txt to contain %q, got %v", "openssh:file-alias", fileIDs)
	}
}

// TestResolveExplicitOverrideNodeFindsCustomNamedNode verifies R5-3:
// When a control command specifies -l / -p against a selector that resolves to
// a base node, resolveExplicitOverrideNode matches a custom-named node sharing
// the overridden (user, address, port) tuple.
func TestResolveExplicitOverrideNodeFindsCustomNamedNode(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h-default", models.Host{Address: "10.0.0.5", Port: 22})
	cfg.Hosts.Set("h-ops", models.Host{Address: "10.0.0.5", Port: 2222})
	cfg.Identities.Set("id-root", models.Identity{User: "root", AuthType: "password"})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "password"})
	cfg.Nodes.Set("base-node", models.Node{HostRef: "h-default", IdentityRef: "id-root", Alias: []string{"web"}})
	cfg.Nodes.Set("custom-ops-node", models.Node{HostRef: "h-ops", IdentityRef: "id-ops"})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	nodeID, err := resolveControlNodeID(provider, config.ConnectionTarget{
		Selector: "web",
		User:     "ops",
		HasUser:  true,
		Port:     2222,
		HasPort:  true,
	})
	if err != nil {
		t.Fatalf("resolveControlNodeID failed: %v", err)
	}
	if nodeID != "custom-ops-node" {
		t.Fatalf("expected custom-ops-node, got %q", nodeID)
	}
}

// TestDerivedNodeFromOpenSSHAliasInheritsTier4Control verifies R6-3:
// When a user overrides -l or -p on a concrete OpenSSH Host alias (e.g. demo-alias),
// the derived node (ops@10.0.0.20:2200) still inherits Tier 4 ControlConfig from
// Host demo-alias and expands the exact same ControlPath as `xops ssh -O check -l ops demo-alias`.
func TestDerivedNodeFromOpenSSHAliasInheritsTier4Control(t *testing.T) {
	content := "Host demo-alias\n  HostName 10.0.0.20\n  User demo\n  Port 2200\n  ControlMaster auto\n  ControlPath /tmp/cm-%n-%r@%h:%p\n  ControlPersist 60s\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(content))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser failed: %v", err)
	}

	target := config.ConnectionTarget{
		Selector: "demo-alias",
		User:     "ops",
		HasUser:  true,
	}
	res, err := repo.PrepareNodeContext(context.Background(), config.EnsureNodeOptions{Target: target})
	if err != nil {
		t.Fatalf("PrepareNodeContext failed: %v", err)
	}
	if res.NodeID != "ops@10.0.0.20:2200" {
		t.Fatalf("expected derived node ops@10.0.0.20:2200, got %q", res.NodeID)
	}

	adp := adapter.NewSSHAdapter(repo)
	ctrl, err := adp.ResolveControl(res.NodeID, adapter.SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveControl(%q) failed: %v", res.NodeID, err)
	}
	if ctrl == nil || ctrl.Master != ssh.ControlMasterAuto || ctrl.Path != "/tmp/cm-%n-%r@%h:%p" || ctrl.Persist != "60s" {
		t.Fatalf("expected Tier 4 ControlConfig from demo-alias, got %+v", ctrl)
	}

	sshOpts := NewSshOptions()
	sshOpts.Host = "demo-alias"
	sshOpts.User = "ops"
	sshOpts.Target = target
	connectSock, err := controlSocketPath(sshOpts, repo, res.NodeID)
	if err != nil {
		t.Fatalf("controlSocketPath(connect) failed: %v", err)
	}

	// Simulate read-only -O check before derived node is persisted to disk.
	readOnlyProvider := config.NewProviderWithOpenSSHParser(cfg, parser)
	ctlNodeID, err := resolveControlNodeID(readOnlyProvider, target)
	if err != nil {
		t.Fatalf("resolveControlNodeID failed: %v", err)
	}
	ctlSock, err := controlSocketPath(sshOpts, readOnlyProvider, ctlNodeID)
	if err != nil {
		t.Fatalf("controlSocketPath(-O) failed: %v", err)
	}
	if connectSock != ctlSock {
		t.Fatalf("expected connect socket %q to equal -O socket %q", connectSock, ctlSock)
	}
}

// TestControlCandidateFallbackAndPortOverrideJumpAlignment verifies R7-2 and R7-3:
//  1. Multi-candidate nodes with inconsistent ports return AmbiguousNodeError on -O -l,
//     while multi-candidate nodes with consistent (Address, Port) inherit port and ProxyJump.
//  2. Explicit port override on a local node clears ProxyJump when no node on the new port shares it.
//  3. FindConcreteHostsByAddress does not match a concrete Host block with a different port,
//     and derived nodes track their originating OpenSSHAlias when multiple aliases share HostName/Port.
func TestControlCandidateFallbackAndPortOverrideJumpAlignment(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h-22", models.Host{Address: "10.0.0.5", Port: 22})
	cfg.Hosts.Set("h-2222", models.Host{Address: "10.0.0.5", Port: 2222})
	cfg.Identities.Set("id-root", models.Identity{User: "root", AuthType: "password"})
	cfg.Identities.Set("id-admin", models.Identity{User: "admin", AuthType: "password"})

	// Case 1a: Same IP, different ports -> -l test without -p must return AmbiguousNodeError.
	cfg.Nodes.Set("root@10.0.0.5:22", models.Node{HostRef: "h-22", IdentityRef: "id-root"})
	cfg.Nodes.Set("root@10.0.0.5:2222", models.Node{HostRef: "h-2222", IdentityRef: "id-root"})
	providerInconsistent := config.NewProviderWithoutOpenSSH(cfg)
	if _, err := resolveControlNodeID(providerInconsistent, config.ConnectionTarget{
		Selector: "10.0.0.5",
		User:     "test",
		HasUser:  true,
	}); err == nil {
		t.Fatal("expected AmbiguousNodeError when candidates have different ports and -p is not specified")
	}

	// Case 1b: Same IP, same port (2222), different users -> -l test inherits port 2222 and ProxyJump.
	cfg.Nodes.Remove("root@10.0.0.5:22")
	cfg.Nodes.Set("root@10.0.0.5:2222", models.Node{HostRef: "h-2222", IdentityRef: "id-root", ProxyJump: "upstream"})
	cfg.Nodes.Set("admin@10.0.0.5:2222", models.Node{HostRef: "h-2222", IdentityRef: "id-admin", ProxyJump: "upstream"})
	providerConsistent := config.NewProviderWithoutOpenSSH(cfg)
	targetSamePort := config.ConnectionTarget{
		Selector: "10.0.0.5",
		User:     "test",
		HasUser:  true,
	}
	nodeID, err := resolveControlNodeID(providerConsistent, targetSamePort)
	if err != nil {
		t.Fatalf("resolveControlNodeID for consistent port candidates failed: %v", err)
	}
	optsSamePort := NewSshOptions()
	optsSamePort.Host = "10.0.0.5"
	optsSamePort.User = "test"
	optsSamePort.Target = targetSamePort
	ctxSamePort := controlTarget(optsSamePort, providerConsistent, nodeID)
	if ctxSamePort.Port != 2222 || ctxSamePort.JumpHost != "upstream" || ctxSamePort.OriginalHost != "test@10.0.0.5:2222" {
		t.Fatalf("unexpected controlTarget for consistent candidates: %+v", ctxSamePort)
	}

	// Case 2: Local node with explicit port override (-p 2223) does not inherit port 2222's ProxyJump.
	targetDiffPort := config.ConnectionTarget{
		Selector: "10.0.0.5",
		User:     "test",
		HasUser:  true,
		Port:     2223,
		HasPort:  true,
	}
	nodeIDDiffPort, err := resolveControlNodeID(providerConsistent, targetDiffPort)
	if err != nil {
		t.Fatalf("resolveControlNodeID for explicit port override failed: %v", err)
	}
	optsDiffPort := NewSshOptions()
	optsDiffPort.Host = "10.0.0.5"
	optsDiffPort.User = "test"
	optsDiffPort.Port = 2223
	optsDiffPort.Target = targetDiffPort
	ctxDiffPort := controlTarget(optsDiffPort, providerConsistent, nodeIDDiffPort)
	if ctxDiffPort.JumpHost != "" {
		t.Fatalf("expected empty JumpHost when local node port is overridden to 2223, got %q", ctxDiffPort.JumpHost)
	}

	// Case 3 (R7-3): Two concrete aliases sharing HostName/Port and another alias on a different port.
	sshCfgText := strings.Join([]string{
		"Host alias-a",
		"  HostName 10.0.0.30",
		"  Port 2200",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-a-%C",
		"  ControlPersist 10s",
		"Host alias-b",
		"  HostName 10.0.0.30",
		"  Port 2200",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-b-%C",
		"  ControlPersist 20s",
		"Host alias-2222",
		"  HostName 10.0.0.40",
		"  Port 2222",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-2222-%C",
		"Host *",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-star-%C",
	}, "\n")
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	cfgR73 := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfgR73.Hosts.Set("h-40-22", models.Host{Address: "10.0.0.40", Port: 22})
	cfgR73.Identities.Set("id-root", models.Identity{User: "root", AuthType: "password"})
	cfgR73.Nodes.Set("root@10.0.0.40:22", models.Node{HostRef: "h-40-22", IdentityRef: "id-root"})

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfgR73, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser failed: %v", err)
	}
	adp := adapter.NewSSHAdapter(repo)

	// Node on 10.0.0.40:22 must fall back to Host *, not Host alias-2222 (Port 2222).
	ctrl40, err := adp.ResolveControl("root@10.0.0.40:22", adapter.SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveControl(root@10.0.0.40:22) failed: %v", err)
	}
	if ctrl40 == nil || ctrl40.Path != "/tmp/cm-star-%C" {
		t.Fatalf("expected Host * ControlPath /tmp/cm-star-%%C for port 22 node, got %+v", ctrl40)
	}

	// Derived node from alias-b must resolve alias-b's ControlPath (/tmp/cm-b-%C), not alias-a's.
	resB, err := repo.PrepareNodeContext(context.Background(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "alias-b", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(alias-b) failed: %v", err)
	}
	ctrlB, err := adp.ResolveControl(resB.NodeID, adapter.SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveControl(%q) failed: %v", resB.NodeID, err)
	}
	if ctrlB == nil || ctrlB.Path != "/tmp/cm-b-%C" || ctrlB.Persist != "20s" {
		t.Fatalf("expected alias-b ControlConfig (/tmp/cm-b-%%C, 20s), got %+v", ctrlB)
	}
}

// TestAdHocOverrideWithWildcardOpenSSHAndSameIPJumpIdentityIsolation verifies R8-1 and R8-2:
//  1. When ~/.ssh/config has a wildcard `Host *` (e.g. Port 2200) and the user connects to
//     an ad-hoc IP (not a concrete Host block) with `-l ops`, both PrepareNodeContext,
//     resolveControlNodeID + controlTarget, and ScpOptions.resolvedTargetNodeIDs agree on
//     `ops@<ip>:22` instead of pulling `Port 2200` from `GetVirtualNode("openssh:<ip>")`.
//  2. When a jump master and target master share the same IP on different ports (e.g.
//     127.0.0.1:2201 and 127.0.0.1:2200), shouldPassIdentityFile strictly matches node IDs
//     and port/user so the target keeps `-i` while the jump master strips it.
func TestAdHocOverrideWithWildcardOpenSSHAndSameIPJumpIdentityIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sshCfgText := strings.Join([]string{
		"Host *",
		"  Port 2200",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-adhoc-%n-%C",
	}, "\n")
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	readOnlyProvider := config.NewProviderWithOpenSSHParser(cfg, parser)

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser failed: %v", err)
	}

	target := config.ConnectionTarget{
		Selector: "10.0.0.88",
		User:     "ops",
		HasUser:  true,
	}
	res, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{Target: target})
	if err != nil {
		t.Fatalf("PrepareNodeContext failed: %v", err)
	}
	if res.NodeID != "ops@10.0.0.88:22" {
		t.Fatalf("expected PrepareNodeContext nodeID ops@10.0.0.88:22, got %q", res.NodeID)
	}

	sshOpts := NewSshOptions()
	sshOpts.Host = "10.0.0.88"
	sshOpts.User = "ops"
	sshOpts.Target = target
	connectSock, err := controlSocketPath(sshOpts, repo, res.NodeID)
	if err != nil {
		t.Fatalf("controlSocketPath(connect) failed: %v", err)
	}

	ctlNodeID, err := resolveControlNodeID(readOnlyProvider, target)
	if err != nil {
		t.Fatalf("resolveControlNodeID failed: %v", err)
	}
	ctlSock, err := controlSocketPath(sshOpts, readOnlyProvider, ctlNodeID)
	if err != nil {
		t.Fatalf("controlSocketPath(-O) failed: %v", err)
	}
	if connectSock != ctlSock {
		t.Fatalf("expected connect socket %q to equal -O socket %q", connectSock, ctlSock)
	}

	scpOpts := NewScpOptions()
	scpOpts.User = "ops"
	scpOpts.Source = "10.0.0.88:/tmp/a"
	scpOpts.Dest = "/tmp/b"
	scpIDs := scpOpts.resolvedTargetNodeIDs(repo)
	if !slices.Contains(scpIDs, "ops@10.0.0.88:22") {
		t.Fatalf("expected scp resolvedTargetNodeIDs to contain ops@10.0.0.88:22, got %v", scpIDs)
	}

	// Verify R8-2: same IP (127.0.0.1), different ports for jump (2201) and target (2200).
	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fix.Close() }()
	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial failed: %v", err)
	}
	defer func() { _ = rawClient.Close() }()

	tmpDir := shortControlTempDir(t)
	jumpMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: filepath.Join(tmpDir, "jump.sock"),
		Target: ssh.TargetContext{
			Host:         host,
			Port:         port + 1,
			User:         "jump",
			OriginalHost: "jump@" + host + ":" + strconv.Itoa(port+1),
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: filepath.Join(tmpDir, "jump.sock"), Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(jump) failed: %v", err)
	}
	defer func() { _ = jumpMaster.Shutdown() }()

	targetMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: filepath.Join(tmpDir, "target.sock"),
		Target: ssh.TargetContext{
			Host:         host,
			Port:         port,
			User:         "root",
			OriginalHost: "root@" + host + ":" + strconv.Itoa(port),
			JumpHost:     "jump@" + host + ":" + strconv.Itoa(port+1),
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: filepath.Join(tmpDir, "target.sock"), Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(target) failed: %v", err)
	}
	defer func() { _ = targetMaster.Shutdown() }()

	sameIPOpts := NewSshOptions()
	sameIPOpts.Host = host
	sameIPOpts.Port = uint16(port)
	sameIPOpts.User = "root"
	sameIPOpts.IdentityFile = "/tmp/target-key"
	sameIPOpts.targetNodeIDs = []string{"root@" + host + ":" + strconv.Itoa(port)}

	jumpArgs := strings.Join(sameIPOpts.muxDaemonArgs(jumpMaster.Target().OriginalHost, jumpMaster.ControlPath(), jumpMaster), " ")
	if strings.Contains(jumpArgs, "-i ") || strings.Contains(jumpArgs, "target-key") {
		t.Fatalf("expected jumpMaster on same IP different port to strip -i, got %q", jumpArgs)
	}
	targetArgs := strings.Join(sameIPOpts.muxDaemonArgs(targetMaster.Target().OriginalHost, targetMaster.ControlPath(), targetMaster), " ")
	if !strings.Contains(targetArgs, "-i /tmp/target-key") {
		t.Fatalf("expected targetMaster on same IP to keep -i /tmp/target-key, got %q", targetArgs)
	}
}

// TestMuxDaemonKeyPathAndScpIsolationAndHostFlagAndLookupOpenSSHAlias verifies R9-1 through R9-4:
//   - R9-1: muxDaemonArgs forwards master.Target().KeyPath when o.IdentityFile is empty or when
//     a jump master has its own configured KeyPath distinct from the target's CLI -i.
//   - R9-2: ScpOptions.resolvedTargetNodeIDs excludes the un-overridden base node when user/port
//     is overridden (preventing ProxyJump self-loops) and ignores colons in o.Source/o.Dest when
//     o.Host, o.Tag, or o.HostFile is used.
//   - R9-3: SshOptions.parseTarget parses --host user@host:port and --host [::1], and
//     controlTarget / resolveControlNodeID handles bracketed IPv6 and custom-ID nodes.
//   - R9-4: PrepareNodeContext preserves OpenSSHAlias when resolving via lookup[selector], and
//     controlTarget inherits ProxyJump from a node at (host, port) even when base is openssh:.
func TestMuxDaemonKeyPathAndScpIsolationAndHostFlagAndLookupOpenSSHAlias(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Verify R9-1: master.Target().KeyPath is passed to muxDaemonArgs.
	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fix.Close() }()
	host, portStr, _ := net.SplitHostPort(fix.Address)
	port, _ := strconv.Atoi(portStr)

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial failed: %v", err)
	}
	defer func() { _ = rawClient.Close() }()

	tmpDir := shortControlTempDir(t)
	derivedMaster, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: filepath.Join(tmpDir, "derived.sock"),
		Target: ssh.TargetContext{
			Host:         host,
			Port:         port,
			User:         "ops",
			KeyPath:      "/tmp/ssh-config-derived-key",
			OriginalHost: "ops@" + host + ":" + strconv.Itoa(port),
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: filepath.Join(tmpDir, "derived.sock"), Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(derived) failed: %v", err)
	}
	defer func() { _ = derivedMaster.Shutdown() }()

	// Even when o.IdentityFile is empty, muxDaemonArgs passes -i master.Target().KeyPath.
	noFlagOpts := NewSshOptions()
	derivedArgs := strings.Join(noFlagOpts.muxDaemonArgs(derivedMaster.Target().OriginalHost, derivedMaster.ControlPath(), derivedMaster), " ")
	if !strings.Contains(derivedArgs, "-i /tmp/ssh-config-derived-key") {
		t.Fatalf("expected muxDaemonArgs to include -i /tmp/ssh-config-derived-key from master.Target().KeyPath, got %q", derivedArgs)
	}

	// Jump master with its own KeyPath keeps its own KeyPath instead of inheriting target's CLI -i.
	jumpWithKey, err := ssh.StartMuxServer(ctx, rawClient, ssh.MuxMasterOptions{
		Path: filepath.Join(tmpDir, "jump-key.sock"),
		Target: ssh.TargetContext{
			Host:         host,
			Port:         port + 1,
			User:         "jump",
			KeyPath:      "/tmp/jump-own-key",
			OriginalHost: "jump@" + host + ":" + strconv.Itoa(port+1),
			Control:      &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: filepath.Join(tmpDir, "jump-key.sock"), Persist: "5m"},
		},
	})
	if err != nil {
		t.Fatalf("StartMuxServer(jumpWithKey) failed: %v", err)
	}
	defer func() { _ = jumpWithKey.Shutdown() }()

	withTargetFlagOpts := NewSshOptions()
	withTargetFlagOpts.IdentityFile = "/tmp/target-cli-key"
	withTargetFlagOpts.targetNodeIDs = []string{"ops@" + host + ":" + strconv.Itoa(port)}
	jumpWithKeyArgs := strings.Join(withTargetFlagOpts.muxDaemonArgs(jumpWithKey.Target().OriginalHost, jumpWithKey.ControlPath(), jumpWithKey), " ")
	if !strings.Contains(jumpWithKeyArgs, "-i /tmp/jump-own-key") || strings.Contains(jumpWithKeyArgs, "target-cli-key") {
		t.Fatalf("expected jumpWithKey muxDaemonArgs to use -i /tmp/jump-own-key and strip target-cli-key, got %q", jumpWithKeyArgs)
	}

	// R10-4: when jump master's own configured KeyPath equals target's CLI -i, jump master keeps -i.
	withSharedKeyOpts := NewSshOptions()
	withSharedKeyOpts.IdentityFile = "/tmp/jump-own-key"
	withSharedKeyOpts.targetNodeIDs = []string{"ops@" + host + ":" + strconv.Itoa(port)}
	if gotKey := withSharedKeyOpts.resolveMuxDaemonIdentityFile(jumpWithKey.Target().OriginalHost, jumpWithKey); gotKey != "/tmp/jump-own-key" {
		t.Fatalf("expected jump master to keep its configured KeyPath when equal to target -i, got %q", gotKey)
	}

	// 2. Verify R9-2, R9-3, and R9-4.
	verifyScpIsolationAndHostFlagAndLookupAlias(t, ctx)
}

func verifyScpIsolationAndHostFlagAndLookupAlias(t *testing.T, ctx context.Context) {
	t.Helper()
	sshCfgText := strings.Join([]string{
		"Host gw",
		"  HostName 10.0.0.10",
		"  User root",
		"  Port 22",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-gw-%C",
		"  ControlPersist 30s",
	}, "\n")
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h-gw-22", models.Host{Address: "10.0.0.10", Port: 22})
	cfg.Hosts.Set("h-gw-2222", models.Host{Address: "10.0.0.10", Port: 2222})
	cfg.Identities.Set("id-root", models.Identity{User: "root", AuthType: "password"})
	// Persisted node derived earlier from Host gw has OpenSSHAlias: "gw".
	cfg.Nodes.Set("root@10.0.0.10:22", models.Node{
		HostRef:      "h-gw-22",
		IdentityRef:  "id-root",
		OpenSSHAlias: "gw",
	})
	// Container node on 10.0.0.10:2222 jumps through gw.
	cfg.Nodes.Set("container-node", models.Node{
		HostRef:     "h-gw-2222",
		IdentityRef: "id-root",
		ProxyJump:   "openssh:gw",
	})

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser failed: %v", err)
	}

	// R9-2: SCP to gw:/tmp/file with -P 2222 -J gw must only include root@10.0.0.10:2222,
	// never base node openssh:gw or root@10.0.0.10:22, and -H mode ignores colons in local Source.
	verifyScpIsolationAndHostFlag(t, repo)

	// R9-4a: PrepareNodeContext via lookup["10.0.0.10"] with -l ops -p 22 preserves OpenSSHAlias "gw".
	resLookup, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "10.0.0.10", User: "ops", HasUser: true, Port: 22, HasPort: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(10.0.0.10, -l ops -p 22) failed: %v", err)
	}
	nodeLookup, _, _, err := repo.Resolve(resLookup.NodeID)
	if err != nil {
		t.Fatalf("Resolve(%q) failed: %v", resLookup.NodeID, err)
	}
	if nodeLookup.OpenSSHAlias != "gw" {
		t.Fatalf("expected derived node from 10.0.0.10 lookup to preserve OpenSSHAlias %q, got %q", "gw", nodeLookup.OpenSSHAlias)
	}

	// R9-4b: controlTarget for `gw -p 2222` (where base node is openssh:gw) inherits
	// ProxyJump "openssh:gw" from container-node at (10.0.0.10, 2222).
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)
	targetPortOverride := config.ConnectionTarget{Selector: "gw", Port: 2222, HasPort: true}
	ctlNodeID, err := resolveControlNodeID(provider, targetPortOverride)
	if err != nil {
		t.Fatalf("resolveControlNodeID(gw -p 2222) failed: %v", err)
	}
	if ctlNodeID != "container-node" {
		t.Fatalf("expected resolveControlNodeID(gw -p 2222) to resolve custom-ID container-node, got %q", ctlNodeID)
	}
	ctlOpts := NewSshOptions()
	ctlOpts.Host = "gw"
	ctlOpts.Port = 2222
	ctlOpts.Target = targetPortOverride
	ctlCtx := controlTarget(ctlOpts, provider, "openssh:gw")
	if ctlCtx.JumpHost != "openssh:gw" {
		t.Fatalf("expected controlTarget(openssh:gw, -p 2222) to inherit JumpHost %q from 10.0.0.10:2222, got %q", "openssh:gw", ctlCtx.JumpHost)
	}
}

func verifyScpIsolationAndHostFlag(t *testing.T, repo *config.Repository) {
	t.Helper()
	scpOpts := NewScpOptions()
	scpOpts.Port = 2222
	scpOpts.JumpHost = "gw"
	scpOpts.Source = "gw:/tmp/file"
	scpOpts.Dest = "/tmp/out"
	scpIDs := scpOpts.resolvedTargetNodeIDs(repo)
	if !slices.Contains(scpIDs, "root@10.0.0.10:2222") {
		t.Fatalf("expected resolvedTargetNodeIDs to contain root@10.0.0.10:2222, got %v", scpIDs)
	}
	if slices.Contains(scpIDs, "openssh:gw") || slices.Contains(scpIDs, "root@10.0.0.10:22") {
		t.Fatalf("expected resolvedTargetNodeIDs to exclude un-overridden base node, got %v", scpIDs)
	}
	scpHostMode := NewScpOptions()
	scpHostMode.Host = "gw"
	scpHostMode.Port = 2222
	scpHostMode.User = "ops"
	scpHostMode.Source = "./archive:2026.tar.gz"
	scpHostMode.Dest = "/tmp/remote.tar.gz"
	hostModeIDs := scpHostMode.resolvedTargetNodeIDs(repo)
	if !slices.Contains(hostModeIDs, "ops@10.0.0.10:2222") {
		t.Fatalf("expected -H mode to ignore colon in local Source and include ops@10.0.0.10:2222, got %v", hostModeIDs)
	}
	if slices.Contains(hostModeIDs, "openssh:gw") || slices.Contains(hostModeIDs, "root@10.0.0.10:22") {
		t.Fatalf("expected -H mode to exclude base port-22 nodes, got %v", hostModeIDs)
	}

	// R9-3: SshOptions.parseTarget parses --host user@host:port and --host [::1].
	flagOpts := NewSshOptions()
	flagOpts.Host = "ops@10.0.0.10:2222"
	if err := flagOpts.parseTarget(false); err != nil {
		t.Fatalf("parseTarget(--host ops@10.0.0.10:2222) failed: %v", err)
	}
	if flagOpts.Host != "10.0.0.10" || flagOpts.User != "ops" || flagOpts.Port != 2222 {
		t.Fatalf("unexpected parseTarget result: Host=%q User=%q Port=%d", flagOpts.Host, flagOpts.User, flagOpts.Port)
	}
	ipv6Opts := NewSshOptions()
	ipv6Opts.Host = "[::1]"
	if err := ipv6Opts.parseTarget(false); err != nil {
		t.Fatalf("parseTarget(--host [::1]) failed: %v", err)
	}
	if ipv6Opts.Host != "::1" {
		t.Fatalf("expected parseTarget(--host [::1]) to strip brackets to ::1, got %q", ipv6Opts.Host)
	}
}

func TestRound10TargetDisambiguationAndControlResolution(t *testing.T) {
	verifyRound10RawSelectorAndOpenSSHStep4(t)
	verifyRound10Tier2AndTier4ControlResolution(t)
	verifyRound10ControlAmbiguityAndSharedJumpKey(t)
}

func newEmptyTestConfig() *config.Configuration {
	return config.NewProviderWithoutOpenSSH(nil).Snapshot()
}

func verifyRound10RawSelectorAndOpenSSHStep4(t *testing.T) {
	t.Helper()
	sshCfgText := `
Host demo-alias
    HostName 10.0.0.10
    User demo
    Port 2200

Host 10.0.0.10
    HostName 10.0.0.10
    User wronguser
    Port 2200
    IdentityFile /tmp/wrong_ip_key
    ProxyJump wrongjump
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("parse ssh_config: %v", err)
	}
	cfg := newEmptyTestConfig()
	cfg.Hosts.Set("10.0.0.10:22", models.Host{Address: "10.0.0.10", Port: 22})
	cfg.Identities.Set("root@10.0.0.10", models.Identity{User: "root", AuthType: "auto"})
	cfg.Nodes.Set("root@10.0.0.10:22", models.Node{HostRef: "10.0.0.10:22", IdentityRef: "root@10.0.0.10"})
	cfg.Nodes.Set("web-prod", models.Node{HostRef: "10.0.0.10:22", IdentityRef: "root@10.0.0.10", Alias: []string{"web-alias"}})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}

	// R10-1: exact canonical node ID root@10.0.0.10:22 disambiguates against web-prod.
	opts := NewSshOptions()
	opts.Host = "root@10.0.0.10:22"
	if err := opts.parseTarget(false); err != nil {
		t.Fatalf("parseTarget: %v", err)
	}
	res, err := repo.PrepareNodeContext(context.Background(), config.EnsureNodeOptions{Target: opts.Target})
	if err != nil || res.NodeID != "root@10.0.0.10:22" {
		t.Fatalf("expected PrepareNodeContext(root@10.0.0.10:22) to resolve root@10.0.0.10:22, got %q (err=%v)", res.NodeID, err)
	}
	ctlID, err := resolveControlNodeID(repo, opts.Target)
	if err != nil || ctlID != "root@10.0.0.10:22" {
		t.Fatalf("expected resolveControlNodeID(root@10.0.0.10:22) to resolve root@10.0.0.10:22, got %q (err=%v)", ctlID, err)
	}

	// R10-1 Step 4: composite user@host:port selector does not match Host 10.0.0.10 block.
	daemonRes, err := repo.PrepareNodeContext(context.Background(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector:    "ops@10.0.0.10:2200",
			RawSelector: "ops@10.0.0.10:2200",
			User:        "ops",
			HasUser:     true,
			Port:        2200,
			HasPort:     true,
		},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(ops@10.0.0.10:2200): %v", err)
	}
	snap, err := repo.ResolveConnection(daemonRes.NodeID)
	if err != nil {
		t.Fatalf("ResolveConnection(%q): %v", daemonRes.NodeID, err)
	}
	if snap.Node.ProxyJump != "" || snap.Identity.KeyPath != "" {
		t.Fatalf("expected composite selector ops@10.0.0.10:2200 not to inherit Host 10.0.0.10 ProxyJump/KeyPath, got jump=%q key=%q", snap.Node.ProxyJump, snap.Identity.KeyPath)
	}
}

func verifyRound10Tier2AndTier4ControlResolution(t *testing.T) {
	t.Helper()
	sshCfgText := `
Host app
    HostName 10.0.0.20
    User ubuntu
    Port 2200
    ControlMaster auto
    ControlPath /tmp/app-%r@%h:%p-%n
    ControlPersist 60s
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("parse ssh_config: %v", err)
	}
	cfg := newEmptyTestConfig()
	cfg.SSHOptions = ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/global-%n", Persist: "30s"})
	cfg.Hosts.Set("10.0.0.10:22", models.Host{Address: "10.0.0.10", Port: 22})
	cfg.Identities.Set("ubuntu@10.0.0.10", models.Identity{User: "ubuntu", AuthType: "auto"})
	cfg.Nodes.Set("prod", models.Node{
		HostRef:     "10.0.0.10:22",
		IdentityRef: "ubuntu@10.0.0.10",
		SSHOptions:  ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/prod-tier2-%n", Persist: "30s"}),
	})
	// Saved node from a previous `xops ssh -p 2222 app` where OpenSSHAlias was not serialized to YAML.
	cfg.Hosts.Set("10.0.0.20:2222", models.Host{Address: "10.0.0.20", Port: 2222})
	cfg.Identities.Set("ubuntu@10.0.0.20", models.Identity{User: "ubuntu", AuthType: "auto"})
	cfg.Nodes.Set("ubuntu@10.0.0.20:2222", models.Node{
		HostRef:     "10.0.0.20:2222",
		IdentityRef: "ubuntu@10.0.0.20",
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}

	// R10-2 (Part 1): unremembered override `-l root prod` uses Tier 3 global, not prod's Tier 2.
	overrideOpts := NewSshOptions()
	overrideOpts.Host = "prod"
	overrideOpts.User = "root"
	overrideOpts.Target = config.ConnectionTarget{Selector: "prod", User: "root", HasUser: true}
	ctlNodeID, err := resolveControlNodeID(repo, overrideOpts.Target)
	if err != nil {
		t.Fatalf("resolveControlNodeID(-l root prod): %v", err)
	}
	sockPath, err := controlSocketPath(overrideOpts, repo, ctlNodeID)
	if err != nil {
		t.Fatalf("controlSocketPath(-l root prod): %v", err)
	}
	if sockPath != "/tmp/global-root@10.0.0.10:22" {
		t.Fatalf("expected unremembered override on prod to use global Tier 3 path, got %q", sockPath)
	}

	// R10-2 (Part 2): saved node ubuntu@10.0.0.20:2222 retains OpenSSHAlias="app" when resolved via selector "app".
	cfgNoGlobal := repo.Snapshot()
	cfgNoGlobal.SSHOptions = nil
	store2 := config.NewDefaultStore(filepath.Join(t.TempDir(), "config2.yaml"), filepath.Join(t.TempDir(), "key2"))
	repoTier4, err := config.NewRepositoryWithOpenSSHParser(cfgNoGlobal, store2, parser)
	if err != nil {
		t.Fatalf("create repoTier4: %v", err)
	}
	appOpts := NewSshOptions()
	appOpts.Host = "app"
	appOpts.Port = 2222
	appOpts.Target = config.ConnectionTarget{Selector: "app", Port: 2222, HasPort: true}
	res, err := repoTier4.PrepareNodeContext(context.Background(), config.EnsureNodeOptions{Target: appOpts.Target})
	if err != nil || res.NodeID != "ubuntu@10.0.0.20:2222" {
		t.Fatalf("PrepareNodeContext(-p 2222 app) = %q, err=%v", res.NodeID, err)
	}
	appSock, err := controlSocketPath(appOpts, repoTier4, res.NodeID)
	if err != nil || appSock != "/tmp/app-ubuntu@10.0.0.20:2222-ubuntu@10.0.0.20:2222" {
		t.Fatalf("expected Tier 4 OpenSSH ControlPath for saved override node, got %q (err=%v)", appSock, err)
	}
}

func verifyRound10ControlAmbiguityAndSharedJumpKey(t *testing.T) {
	t.Helper()
	cfg := newEmptyTestConfig()
	cfg.Hosts.Set("db.internal:22", models.Host{Address: "db.internal", Port: 22})
	cfg.Identities.Set("postgres@db", models.Identity{User: "postgres", AuthType: "auto"})
	cfg.Nodes.Set("node-1", models.Node{HostRef: "db.internal:22", IdentityRef: "postgres@db", Alias: []string{"db.internal"}})
	cfg.Nodes.Set("node-2", models.Node{HostRef: "db.internal:22", IdentityRef: "postgres@db"})
	provider := config.NewProviderWithoutOpenSSH(cfg)

	// R10-3: filterAmbiguousControlCandidates narrows by unique alias.
	nodeID, err := resolveControlNodeID(provider, config.ConnectionTarget{
		Selector: "db.internal",
		User:     "postgres",
		HasUser:  true,
	})
	if err != nil || nodeID != "node-1" {
		t.Fatalf("expected resolveControlNodeID(db.internal) to narrow to alias owner node-1, got %q (err=%v)", nodeID, err)
	}
}

func TestRound11UnifiedTargetAndControlResolution(t *testing.T) {
	verifyRound11OpenSSHAliasRePrepareAndConfirm(t)
	verifyRound11ThreeWayAliasTombstone(t)
	verifyRound11Tier4OpenSSHSpecificityAndLocalShadow(t)
	verifyRound11OpenSSHPortOverrideAndSavedNode(t)
	verifyRound11UnifiedInvariantMatrix(t)
}

func verifyRound11OpenSSHAliasRePrepareAndConfirm(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	sshCfgText := `
Host app
    HostName 10.0.0.10
    User ubuntu
    Port 2200
    ControlMaster auto
    ControlPath /tmp/cm-app-%r@%h:%p
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("parse ssh_config: %v", err)
	}
	cfg := newEmptyTestConfig()
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}

	// 1. Prepare via raw IP first (OpenSSHAlias == ""), then re-prepare via OpenSSH alias "app"
	// (OpenSSHAlias == "app"). Must not fail with ErrConfigConflict and must preserve "app".
	rawTarget := config.ConnectionTarget{Selector: "10.0.0.10", User: "root", HasUser: true, Port: 2200, HasPort: true}
	res1, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{Target: rawTarget})
	if err != nil || res1.NodeID != "root@10.0.0.10:2200" {
		t.Fatalf("PrepareNodeContext(10.0.0.10): got %q, err=%v", res1.NodeID, err)
	}
	aliasTarget := config.ConnectionTarget{Selector: "app", User: "root", HasUser: true}
	res2, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{Target: aliasTarget})
	if err != nil || res2.NodeID != "root@10.0.0.10:2200" {
		t.Fatalf("PrepareNodeContext(app) after raw IP failed with conflict: got %q, err=%v", res2.NodeID, err)
	}
	snap, err := repo.ResolveConnection(res2.NodeID)
	if err != nil || snap.Node.OpenSSHAlias != "app" {
		t.Fatalf("expected pending connection to retain OpenSSHAlias='app', got %q (err=%v)", snap.Node.OpenSSHAlias, err)
	}

	// 2. ConfirmNodeContext must succeed even if another writer already saved root@10.0.0.10:2200
	// without OpenSSHAlias, and must keep OpenSSHAlias in session memory + Frozen().
	if err := repo.ConfirmNodeContext(ctx, res2.NodeID); err != nil {
		t.Fatalf("ConfirmNodeContext(%q) failed: %v", res2.NodeID, err)
	}
	snapAfter, err := repo.ResolveConnection(res2.NodeID)
	if err != nil || snapAfter.Node.OpenSSHAlias != "app" {
		t.Fatalf("expected confirmed node to retain session OpenSSHAlias='app', got %q (err=%v)", snapAfter.Node.OpenSSHAlias, err)
	}
	frozen := repo.Frozen()
	frozenSnap, err := frozen.ResolveConnection(res2.NodeID)
	if err != nil || frozenSnap.Node.OpenSSHAlias != "app" {
		t.Fatalf("expected Frozen() provider to retain OpenSSHAlias='app', got %q (err=%v)", frozenSnap.Node.OpenSSHAlias, err)
	}
}

func verifyRound11ThreeWayAliasTombstone(t *testing.T) {
	t.Helper()
	cfg := newEmptyTestConfig()
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "root", AuthType: "auto"})
	cfg.Nodes.Set("node-1", models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{"dup"}})
	cfg.Nodes.Set("node-2", models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{"dup"}})
	cfg.Nodes.Set("node-3", models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{"dup"}})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	if got := provider.FindAlias("dup"); got != "" {
		t.Fatalf("expected FindAlias('dup') to be empty when 3 nodes share alias, got %q", got)
	}
	var ambig *config.AmbiguousNodeError
	if _, err := config.ResolveTarget(provider, config.ConnectionTarget{Selector: "dup"}); !errors.As(err, &ambig) {
		t.Fatalf("expected ResolveTarget('dup') to return AmbiguousNodeError when 3 nodes share alias, got %v", err)
	}
	if _, err := config.ResolveTarget(provider, config.ConnectionTarget{Selector: "dup", User: "root", HasUser: true}); !errors.As(err, &ambig) {
		t.Fatalf("expected ResolveTarget('dup', -l root) to return AmbiguousNodeError when 3 nodes share alias, got %v", err)
	}
}

func verifyRound11Tier4OpenSSHSpecificityAndLocalShadow(t *testing.T) {
	t.Helper()
	sshCfgText := `
Host prod
    HostName 192.168.99.99
    ControlMaster auto
    ControlPath /tmp/wrong-openssh-prod-%C

Host web-alias
    HostName 10.0.0.10
    Port 2200
    ControlMaster auto
    ControlPath /tmp/specific-web-alias-%C

Host 10.0.0.10
    HostName 10.0.0.10
    ControlMaster auto
    ControlPath /tmp/generic-ip-%C

Host single-addr-host
    HostName 10.0.0.55
    Port 2200
    ControlMaster auto
    ControlPath /tmp/single-addr-host-%C
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("parse ssh_config: %v", err)
	}
	cfg := newEmptyTestConfig()
	cfg.Hosts.Set("h-prod", models.Host{Address: "10.0.0.10", Port: 2200})
	cfg.Hosts.Set("h-55", models.Host{Address: "10.0.0.55", Port: 2222})
	cfg.Identities.Set("id-root", models.Identity{User: "root", AuthType: "auto"})
	// Saved local node "prod" has Alias "web-alias" and points to 10.0.0.10:2200, NOT 192.168.99.99.
	cfg.Nodes.Set("prod", models.Node{
		HostRef:     "h-prod",
		IdentityRef: "id-root",
		Alias:       []string{"web-alias"},
	})
	// Saved node on 10.0.0.55:2222 (port overridden from single-addr-host on 10.0.0.55:2200).
	cfg.Nodes.Set("root@10.0.0.55:2222", models.Node{
		HostRef:     "h-55",
		IdentityRef: "id-root",
	})
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	// 1. Local node "prod" with Alias "web-alias" must use Host web-alias (not Host prod or Host 10.0.0.10).
	optsProd := NewSshOptions()
	optsProd.Host = "prod"
	optsProd.Target = config.ConnectionTarget{Selector: "prod"}
	sockProd, err := controlSocketPath(optsProd, provider, "prod")
	if err != nil {
		t.Fatalf("controlSocketPath(prod): %v", err)
	}
	if !strings.HasPrefix(sockProd, "/tmp/specific-web-alias-") {
		t.Fatalf("expected Tier 4 lookup for local node 'prod' (Alias: web-alias) to pick /tmp/specific-web-alias-*, got %q", sockProd)
	}

	// 2. Saved node root@10.0.0.55:2222 accessed via OpenSSH alias "single-addr-host" with -p 2222
	// records OpenSSHAlias="single-addr-host" and resolves its ControlPath (/tmp/single-addr-host-%C).
	opts55 := NewSshOptions()
	opts55.Host = "single-addr-host"
	opts55.Port = 2222
	opts55.Target = config.ConnectionTarget{Selector: "single-addr-host", Port: 2222, HasPort: true}
	sock55, err := controlSocketPath(opts55, provider, "root@10.0.0.55:2222")
	if err != nil {
		t.Fatalf("controlSocketPath(single-addr-host -p 2222): %v", err)
	}
	if !strings.HasPrefix(sock55, "/tmp/single-addr-host-") {
		t.Fatalf("expected OpenSSH alias with -p 2222 on saved node to use /tmp/single-addr-host-*, got %q", sock55)
	}
}

func verifyRound11OpenSSHPortOverrideAndSavedNode(t *testing.T) {
	t.Helper()
	sshCfgText := `
Host demo
    HostName 10.0.0.70
    User ubuntu
    Port 2200
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("parse ssh_config: %v", err)
	}
	cfg := newEmptyTestConfig()
	cfg.Hosts.Set("10.0.0.70:2200", models.Host{Address: "10.0.0.70", Port: 2200})
	cfg.Identities.Set("ubuntu@10.0.0.70", models.Identity{User: "ubuntu", AuthType: "auto"})
	cfg.Nodes.Set("saved-demo", models.Node{
		HostRef:     "10.0.0.70:2200",
		IdentityRef: "ubuntu@10.0.0.70",
		ProxyJump:   "saved-jump",
	})
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	// 1. OpenSSH alias "demo" with explicit matching -p 2200 resolves to saved node "saved-demo"
	// (inheriting saved-jump) just like PrepareNodeContext.
	resMatch, err := config.ResolveTarget(provider, config.ConnectionTarget{
		Selector: "demo",
		Port:     2200,
		HasPort:  true,
	})
	if err != nil {
		t.Fatalf("ResolveTarget(demo -p 2200): %v", err)
	}
	if resMatch.NodeID != "saved-demo" || resMatch.MatchedNodeID != "saved-demo" || resMatch.ProxyJump != "saved-jump" {
		t.Fatalf("expected ResolveTarget(demo -p 2200) to match saved-demo with ProxyJump saved-jump, got %+v", resMatch)
	}

	// 2. OpenSSH alias "demo" with overridden -p 2222 (not in saved nodes) has MatchedNodeID == ""
	// and NodeID == "ubuntu@10.0.0.70:2222".
	resOverride, err := config.ResolveTarget(provider, config.ConnectionTarget{
		Selector: "demo",
		Port:     2222,
		HasPort:  true,
	})
	if err != nil {
		t.Fatalf("ResolveTarget(demo -p 2222): %v", err)
	}
	if resOverride.MatchedNodeID != "" || resOverride.NodeID != "ubuntu@10.0.0.70:2222" {
		t.Fatalf("expected unremembered override on OpenSSH alias to have MatchedNodeID='', NodeID='ubuntu@10.0.0.70:2222', got %+v", resOverride)
	}
}

func verifyRound11UnifiedInvariantMatrix(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	sshCfgText := `
Host app-alias
    HostName 10.0.0.20
    User dev
    Port 2200
    IdentityFile /tmp/app_key
    ProxyJump jump-alias
    ControlMaster auto
    ControlPath /tmp/cm-inv-%n-%r@%h:%p-%j
    ControlPersist 30s

Host jump-alias
    HostName 10.0.0.1
    User jump
    Port 22
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("parse ssh_config: %v", err)
	}
	baseCfg := newEmptyTestConfig()
	baseCfg.SSHOptions = ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/cm-global-%n-%r@%h:%p-%j", Persist: "30s"})
	baseCfg.Hosts.Set("10.0.0.10:22", models.Host{Address: "10.0.0.10", Port: 22, Alias: []string{"host-alias"}})
	baseCfg.Identities.Set("root@10.0.0.10", models.Identity{User: "root", AuthType: "auto", KeyPath: "/tmp/root_key"})
	baseCfg.Nodes.Set("web-node", models.Node{
		HostRef:     "10.0.0.10:22",
		IdentityRef: "root@10.0.0.10",
		Alias:       []string{"web"},
		ProxyJump:   "openssh:jump-alias",
		SSHOptions:  ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/cm-node-%n-%r@%h:%p-%j", Persist: "30s"}),
	})

	targets := []config.ConnectionTarget{
		{Selector: "web-node"},
		{Selector: "web"},
		{Selector: "host-alias"},
		{Selector: "10.0.0.10"},
		{Selector: "web", User: "root", HasUser: true, Port: 22, HasPort: true},
		{Selector: "web", User: "ops", HasUser: true},
		{Selector: "web", Port: 2222, HasPort: true},
		{Selector: "app-alias"},
		{Selector: "app-alias", User: "dev", HasUser: true, Port: 2200, HasPort: true},
		{Selector: "app-alias", User: "ops", HasUser: true},
		{Selector: "app-alias", Port: 2222, HasPort: true},
		{Selector: "10.0.0.99", User: "admin", HasUser: true, Port: 2222, HasPort: true},
		{Selector: "ops@web"},
		{Selector: "ops@web:2222"},
		{Selector: "[::1]"},
		{Selector: "openssh:app-alias"},
		{Selector: "openssh:app-alias", User: "dev", HasUser: true, Port: 2200, HasPort: true},
		{Selector: "openssh:app-alias", User: "ops", HasUser: true},
		{Selector: "openssh:jumpuser@10.0.0.10:2201"},
		{Selector: "web-node", ProxyJump: "none", HasProxyJump: true},
		{Selector: "app-alias", ProxyJump: "none", HasProxyJump: true},
	}

	for _, target := range targets {
		store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
		repo, err := config.NewRepositoryWithOpenSSHParser(baseCfg.Snapshot(), store, parser)
		if err != nil {
			t.Fatalf("create repo for %+v: %v", target, err)
		}
		ensureStore := config.NewDefaultStore(filepath.Join(t.TempDir(), "ensure.yaml"), filepath.Join(t.TempDir(), "ensure.key"))
		if err := ensureStore.Save(baseCfg.Snapshot()); err != nil {
			t.Fatalf("save ensureStore for %+v: %v", target, err)
		}
		ensureRepo, err := config.NewRepositoryWithOpenSSHParser(baseCfg.Snapshot(), ensureStore, parser)
		if err != nil {
			t.Fatalf("create ensureRepo for %+v: %v", target, err)
		}
		readOnlyProvider := config.NewProviderWithOpenSSHParser(baseCfg.Snapshot(), parser)

		prepRes, prepErr := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{Target: target})
		ensureRes, ensureErr := ensureRepo.EnsureNodeContext(ctx, config.EnsureNodeOptions{Target: target})
		resTarget, resErr := config.ResolveTarget(readOnlyProvider, target)
		if (prepErr != nil) != (resErr != nil) || (prepErr != nil) != (ensureErr != nil) {
			t.Fatalf("target %+v: Prepare err=%v vs Ensure err=%v vs ResolveTarget err=%v", target, prepErr, ensureErr, resErr)
		}
		if prepErr != nil {
			continue
		}
		if prepRes.NodeID != resTarget.NodeID || prepRes.Created != resTarget.Created ||
			ensureRes.NodeID != resTarget.NodeID || ensureRes.Created != resTarget.Created {
			t.Fatalf("target %+v: Prepare=(%q,%v) Ensure=(%q,%v) ResolveTarget=(%q,%v)",
				target, prepRes.NodeID, prepRes.Created, ensureRes.NodeID, ensureRes.Created, resTarget.NodeID, resTarget.Created)
		}

		opts := NewSshOptions()
		opts.Host = target.Selector
		opts.User = target.User
		opts.Port = target.Port
		opts.JumpHost = target.ProxyJump
		opts.Target = target

		connectCtx := controlTarget(opts, repo, prepRes.NodeID)
		ctlNodeID, err := resolveControlNodeID(readOnlyProvider, target)
		if err != nil {
			t.Fatalf("target %+v: resolveControlNodeID failed: %v", target, err)
		}
		ctlCtx := controlTarget(opts, readOnlyProvider, ctlNodeID)
		if connectCtx.CanonicalTargetIdentity() != ctlCtx.CanonicalTargetIdentity() {
			t.Fatalf("target %+v: connect TargetContext %+v != control TargetContext %+v", target, connectCtx, ctlCtx)
		}

		connectSock, err1 := controlSocketPath(opts, repo, prepRes.NodeID)
		ctlSock, err2 := controlSocketPath(opts, readOnlyProvider, ctlNodeID)
		if err1 != nil || err2 != nil || connectSock != ctlSock {
			t.Fatalf("target %+v: connect socket (%q, %v) != control socket (%q, %v)", target, connectSock, err1, ctlSock, err2)
		}
	}

	verifyRound12NormalizedTargetAndEffectiveControlNodeID(t)
	verifyRound13OpenSSHVirtualNodeAndProxyJumpNoneAndNilProvider(t)
}

func verifyRound12NormalizedTargetAndEffectiveControlNodeID(t *testing.T) {
	t.Helper()
	sshCfgText := `
Host gw
    HostName 10.0.0.10
    User root
    Port 22
    ControlMaster auto
    ControlPath /tmp/tier4-gw-%n
    ControlPersist 30s
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("parse ssh_config: %v", err)
	}
	cfg := newEmptyTestConfig()
	cfg.Hosts.Set("10.0.0.10:2222", models.Host{Address: "10.0.0.10", Port: 2222})
	cfg.Identities.Set("root@10.0.0.10", models.Identity{User: "root", AuthType: "auto"})
	cfg.Nodes.Set("gw-2222", models.Node{
		HostRef:     "10.0.0.10:2222",
		IdentityRef: "root@10.0.0.10",
		SSHOptions:  ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/tier2-gw2222-%n", Persist: "30s"}),
	})
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	// R12-2 & R12-3: calling controlSocketPath with nodeID="openssh:gw" and Port=2222
	// resolves OriginalHost="gw-2222" and uses gw-2222's Tier 2 Node.Control.
	opts := NewSshOptions()
	opts.Host = "gw"
	opts.Port = 2222
	sock, err := controlSocketPath(opts, provider, "openssh:gw")
	if err != nil {
		t.Fatalf("controlSocketPath(openssh:gw, -p 2222): %v", err)
	}
	if sock != "/tmp/tier2-gw2222-gw-2222" {
		t.Fatalf("expected Tier 2 socket path /tmp/tier2-gw2222-gw-2222, got %q", sock)
	}
}

func verifyRound13OpenSSHVirtualNodeAndProxyJumpNoneAndNilProvider(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	sshCfgText := `
Host app-alias
    HostName 10.0.0.20
    User dev
    Port 2200
    ProxyJump jump-alias
    ControlMaster auto
    ControlPath /tmp/tier4-app-%n-%j

Host jump-alias
    HostName 10.0.0.1
    User jump
    Port 22
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfgText))
	if err != nil {
		t.Fatalf("parse ssh_config: %v", err)
	}
	cfg := newEmptyTestConfig()
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("create repo: %v", err)
	}

	// R13-1a: controlSocketPath and controlTarget with empty opts.Host and nodeID="openssh:app-alias"
	// must keep OriginalHost="openssh:app-alias" (not strip "openssh:" into "dev@10.0.0.20:2200").
	emptyHostOpts := NewSshOptions()
	tCtx := controlTarget(emptyHostOpts, repo, "openssh:app-alias")
	if tCtx.OriginalHost != "openssh:app-alias" {
		t.Fatalf("expected OriginalHost='openssh:app-alias' when opts.Host is empty, got %q", tCtx.OriginalHost)
	}
	sock, err := controlSocketPath(emptyHostOpts, repo, "openssh:app-alias")
	if err != nil || sock != "/tmp/tier4-app-openssh:app-alias-openssh:jump-alias" {
		t.Fatalf("unexpected socket path for openssh:app-alias with empty opts.Host: %q (err=%v)", sock, err)
	}

	// R13-1b: pending node with custom IdentityFile preserves KeyPath in ResolveTarget when queried by nodeID.
	customKeyPath := filepath.Join(t.TempDir(), "pending-custom-key")
	prep, err := repo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target:       config.ConnectionTarget{Selector: "10.0.0.88", User: "ops", HasUser: true, Port: 2222, HasPort: true},
		IdentityFile: customKeyPath,
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(10.0.0.88): %v", err)
	}
	pendingCtx := controlTarget(NewSshOptions(), repo, prep.NodeID)
	if pendingCtx.KeyPath != customKeyPath {
		t.Fatalf("expected controlTarget on pending node %q to retain KeyPath %q, got %q", prep.NodeID, customKeyPath, pendingCtx.KeyPath)
	}

	// R13-2: controlTarget with provider == nil matches provider != nil for composite and explicit targets.
	compOpts := NewSshOptions()
	compOpts.Host = "ops@10.0.0.10:2222"
	nilCtx1 := controlTarget(compOpts, nil, "")
	if nilCtx1.Host != "10.0.0.10" || nilCtx1.User != "ops" || nilCtx1.Port != 2222 || nilCtx1.OriginalHost != "ops@10.0.0.10:2222" {
		t.Fatalf("unexpected nil-provider controlTarget for composite Host: %+v", nilCtx1)
	}
	expOpts := NewSshOptions()
	expOpts.Host = "10.0.0.10"
	expOpts.User = "ops"
	expOpts.Port = 2222
	expOpts.JumpHost = "none"
	nilCtx2 := controlTarget(expOpts, nil, "")
	if nilCtx2.OriginalHost != "ops@10.0.0.10:2222" || nilCtx2.JumpHost != "" {
		t.Fatalf("unexpected nil-provider controlTarget for explicit flags: %+v", nilCtx2)
	}

	// R13-3: -J none / ProxyJump=none disables ProxyJump across ResolveProxyJumpChain, controlSocketPath, and SSHAdapter.
	noneOpts := NewSshOptions()
	noneOpts.Host = "app-alias"
	noneOpts.JumpHost = "none"
	noneSock, err := controlSocketPath(noneOpts, repo, "openssh:app-alias")
	if err != nil || noneSock != "/tmp/tier4-app-openssh:app-alias-" {
		t.Fatalf("expected -J none to clear %s in ControlPath, got %q (err=%v)", "%j", noneSock, err)
	}
	adp := adapter.NewSSHAdapter(repo, adapter.WithSessionAuthOverride("openssh:app-alias", adapter.SessionAuth{ProxyJump: "none"}))
	clientCfg, err := adp.GetConfig("openssh:app-alias")
	if err != nil || clientCfg.ProxyJump != "" {
		t.Fatalf("expected SessionAuth{ProxyJump: 'none'} to clear clientCfg.ProxyJump, got %q (err=%v)", clientCfg.ProxyJump, err)
	}

	verifyRound15ControlProxySudoAndScpTagParity(t)
	verifyRound16ControlEdgeCases(t)
}

func verifyRound15ControlProxySudoAndScpTagParity(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	// 1. Verify buildControlProxyClientConfig wires session password and read-only SecretResolver
	// both when nodeID is known and when nodeID is empty (ad-hoc -S socket).
	cfg := newEmptyTestConfig()
	cfg.PasswordPromptPattern = `(?i)custom-pass:`
	cfg.Hosts.Set("10.0.0.50:22", models.Host{Address: "10.0.0.50", Port: 22})
	cfg.Identities.Set("ops@10.0.0.50", models.Identity{User: "ops", AuthType: "password"})
	cfg.Nodes.Set("web-50", models.Node{
		HostRef:     "10.0.0.50:22",
		IdentityRef: "ops@10.0.0.50",
		SudoMode:    models.SudoModeSudo,
	})
	provider := config.NewProviderWithoutOpenSSH(cfg)

	sshOpts := NewSshOptions()
	sshOpts.Password = "session-sudo-secret"
	target := ssh.TargetContext{Host: "10.0.0.50", User: "ops", Port: 22, OriginalHost: "web-50"}

	knownCfg, knownMuxOpts := buildControlProxyClientConfig(target, provider, "web-50", sshOpts)
	if knownCfg == nil || knownCfg.NodeID != "web-50" {
		t.Fatalf("expected known node ClientConfig for web-50, got %+v", knownCfg)
	}
	if len(knownMuxOpts) == 0 {
		t.Fatalf("expected MuxClientOptions to be populated for known node")
	}

	adhocCfg, _ := buildControlProxyClientConfig(target, provider, "", sshOpts)
	if adhocCfg == nil || adhocCfg.Password != "session-sudo-secret" || adhocCfg.PasswordPromptPattern != `(?i)custom-pass:` {
		t.Fatalf("expected ad-hoc ClientConfig to retain session password and global prompt pattern, got %+v", adhocCfg)
	}

	// 2. Verify scp --tag target resolution parity between collectTargetPaths and runBatch
	// when a tagged node has empty identity.User or port 0.
	tagCfg := newEmptyTestConfig()
	tagCfg.Hosts.Set("10.0.0.60:0", models.Host{Address: "10.0.0.60", Port: 0})
	tagCfg.Identities.Set("default-id", models.Identity{User: "", AuthType: "auto"})
	tagCfg.Nodes.Set("tagged-node", models.Node{
		HostRef:     "10.0.0.60:0",
		IdentityRef: "default-id",
		Tags:        []string{"batch-tag"},
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	tagRepo, err := config.NewRepositoryWithoutOpenSSH(tagCfg, store)
	if err != nil {
		t.Fatalf("create tagRepo: %v", err)
	}

	scpOpts := NewScpOptions()
	scpOpts.Tag = "batch-tag"
	scpOpts.Source = "local.txt"
	scpOpts.Dest = ":/tmp/remote.txt"

	paths := scpOpts.collectTargetPaths(tagRepo)
	if len(paths) != 1 {
		t.Fatalf("expected 1 target path from collectTargetPaths, got %d", len(paths))
	}
	batchAddr := PathInfo{Host: "tagged-node", IsRemote: true}
	if paths[0] != batchAddr {
		t.Fatalf("expected collectTargetPaths path %+v to match runBatch path %+v", paths[0], batchAddr)
	}
	collectTarget, err := scpOpts.resolveTargetForPath(paths[0])
	if err != nil {
		t.Fatalf("resolveTargetForPath(collectTargetPaths) failed: %v", err)
	}
	prepCollect, err := tagRepo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: collectTarget,
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(collectTargetPaths) failed: %v", err)
	}
	batchTarget, err := scpOpts.resolveTargetForPath(batchAddr)
	if err != nil {
		t.Fatalf("resolveTargetForPath(runBatch) failed: %v", err)
	}
	prepBatch, err := tagRepo.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target: batchTarget,
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(runBatch) failed: %v", err)
	}
	if prepCollect.NodeID != "tagged-node" || prepBatch.NodeID != "tagged-node" || prepCollect.Created || prepBatch.Created {
		t.Fatalf("expected both collectTargetPaths and runBatch to match existing 'tagged-node' without creating a new node, got collect=%+v batch=%+v", prepCollect, prepBatch)
	}
}

func verifyRound16ControlEdgeCases(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	target := ssh.TargetContext{Host: "10.0.0.50", User: "ops", Port: 22, OriginalHost: "web-50"}

	// 1. Round 16: resolveEffectiveControlNodeID strips user@ and :port from openssh: composite nodeID.
	aliasCfg := newEmptyTestConfig()
	aliasProvider := config.NewProviderWithoutOpenSSH(aliasCfg)
	effNodeID := resolveEffectiveControlNodeID(aliasProvider, "openssh:ops@my-jump-alias:2222", "ops@10.0.0.77:2222")
	if effNodeID != "ops@10.0.0.77:2222" {
		t.Fatalf("expected effective node ID 'ops@10.0.0.77:2222', got %q", effNodeID)
	}
	if gotAlias := aliasProvider.NodeOpenSSHAlias("ops@10.0.0.77:2222"); gotAlias != "my-jump-alias" {
		t.Fatalf("expected clean OpenSSH alias 'my-jump-alias', got %q", gotAlias)
	}

	// 2. Round 16: Validate skips prepareCommandPlan for non-proxy -O commands, and ExecuteControlCommand validates control options.
	checkOpts := NewSshOptions()
	checkOpts.Host = "10.0.0.50"
	checkOpts.control.CtlCmd = "check"
	if err := checkOpts.Validate(); err != nil {
		t.Fatalf("expected Validate() on -O check to succeed, got %v", err)
	}
	if checkOpts.commandPlan != nil {
		t.Fatalf("expected -O check Validate() not to populate commandPlan")
	}

	invalidCtlOpts := NewSshOptions()
	invalidCtlOpts.Host = "10.0.0.50"
	invalidCtlOpts.control.CtlCmd = "invalid-subcommand"
	if err := ExecuteControlCommand(ctx, invalidCtlOpts); err == nil {
		t.Fatalf("expected direct ExecuteControlCommand with invalid CtlCmd to fail validation")
	}

	// 3. Round 16: buildControlProxyClientConfig does not inject non-TTY prompter when StdinRedirect is set.
	redirectOpts := NewSshOptions()
	redirectOpts.StdinRedirect = true
	_, redirectMuxOpts := buildControlProxyClientConfig(target, nil, "", redirectOpts)
	if len(redirectMuxOpts) != 0 {
		t.Fatalf("expected no default CLI prompter mux option when StdinRedirect is true and interaction is nil, got %d options", len(redirectMuxOpts))
	}
}
