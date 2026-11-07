package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestMasterCountFlag(t *testing.T) {
	tests := []struct {
		name       string
		count      int
		wantMaster ssh.ControlMasterMode
		wantNil    bool
	}{
		{name: "count 0", count: 0, wantNil: true},
		{name: "count 1 (-M)", count: 1, wantMaster: ssh.ControlMasterYes},
		{name: "count 2 (-MM or -M -M)", count: 2, wantMaster: ssh.ControlMasterAsk},
		{name: "count 3", count: 3, wantMaster: ssh.ControlMasterAsk},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flags := SSHControlFlags{MasterCount: tc.count}
			sessionOpts, err := flags.ToSessionControlOptions()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantNil {
				if sessionOpts.Master != nil {
					t.Fatalf("expected nil Master, got %v", *sessionOpts.Master)
				}
			} else {
				if sessionOpts.Master == nil || *sessionOpts.Master != tc.wantMaster {
					t.Fatalf("expected Master %v, got %v", tc.wantMaster, sessionOpts.Master)
				}
			}
		})
	}
}

func TestControlPathFlag(t *testing.T) {
	flags := SSHControlFlags{ControlPath: "/tmp/test.sock"}
	sessionOpts, err := flags.ToSessionControlOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionOpts.Path == nil || *sessionOpts.Path != "/tmp/test.sock" {
		t.Fatalf("expected Path /tmp/test.sock, got %v", sessionOpts.Path)
	}

	flagsNone := SSHControlFlags{ControlPath: "none"}
	sessionOptsNone, err := flagsNone.ToSessionControlOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionOptsNone.Path == nil || *sessionOptsNone.Path != "none" {
		t.Fatalf("expected Path 'none', got %v", sessionOptsNone.Path)
	}
}

func TestOptionFlagParsing(t *testing.T) {
	flags := SSHControlFlags{
		Options: []string{
			"ControlMaster=auto",
			"ControlPath=/tmp/opt.sock",
			"ControlPersist=10m",
			"ConnectTimeout=15",
			"StrictHostKeyChecking=no",
			"ServerAliveInterval=20s",
			"TCPKeepAlive=no",
		},
	}
	sessionOpts, err := flags.ToSessionControlOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionOpts.Master == nil || *sessionOpts.Master != ssh.ControlMasterAuto {
		t.Fatalf("expected Master auto, got %v", sessionOpts.Master)
	}
	if sessionOpts.Path == nil || *sessionOpts.Path != "/tmp/opt.sock" {
		t.Fatalf("expected Path /tmp/opt.sock, got %v", sessionOpts.Path)
	}
	if sessionOpts.Persist == nil || *sessionOpts.Persist != "10m" {
		t.Fatalf("expected Persist 10m, got %v", sessionOpts.Persist)
	}
	eff := sessionOpts.ToSSHOptions()
	tcpKA, tcpKASet := eff.TCPKeepAlive()
	if eff.ConnectTimeout() != 15*time.Second || eff.StrictHostKeyChecking() != ssh.StrictHostKeyCheckingNo || eff.ServerAliveInterval() != 20*time.Second || !tcpKASet || tcpKA {
		t.Fatalf("unexpected effective options from -o flags: %+v", eff)
	}

	// Invalid format
	flagsBadFormat := SSHControlFlags{Options: []string{"NoEqualsSign"}}
	if _, err := flagsBadFormat.ToSessionControlOptions(); err == nil {
		t.Fatal("expected error on missing '=' in -o option")
	}

	// Invalid ControlMaster
	flagsBadMaster := SSHControlFlags{Options: []string{"ControlMaster=invalid"}}
	if _, err := flagsBadMaster.ToSessionControlOptions(); err == nil {
		t.Fatal("expected error on invalid ControlMaster mode")
	}
}

func TestFlagPrecedenceOverOptions(t *testing.T) {
	// -M overrides -o ControlMaster=auto
	flags := SSHControlFlags{
		MasterCount: 1,
		Options:     []string{"ControlMaster=auto"},
	}
	sessionOpts, err := flags.ToSessionControlOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionOpts.Master == nil || *sessionOpts.Master != ssh.ControlMasterYes {
		t.Fatalf("expected -M (yes) to override -o (auto), got %v", sessionOpts.Master)
	}

	// -S overrides -o ControlPath=/other.sock
	flagsPath := SSHControlFlags{
		ControlPath: "/explicit.sock",
		Options:     []string{"ControlPath=/other.sock"},
	}
	sessionOptsPath, err := flagsPath.ToSessionControlOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionOptsPath.Path == nil || *sessionOptsPath.Path != "/explicit.sock" {
		t.Fatalf("expected -S (/explicit.sock) to override -o, got %v", sessionOptsPath.Path)
	}
}

func TestControlCommandValidation(t *testing.T) {
	validCmds := []string{"check", "exit", "stop", "forward", "cancel", "proxy", "conninfo", "channels", "CHECK", "  exit  "}
	for _, cmd := range validCmds {
		f := SSHControlFlags{CtlCmd: cmd}
		if err := f.Validate(); err != nil {
			t.Fatalf("expected valid command %q, got error: %v", cmd, err)
		}
	}

	// Invalid command
	fInvalid := SSHControlFlags{CtlCmd: "restart"}
	if err := fInvalid.Validate(); err == nil || !strings.Contains(err.Error(), "unknown control command") {
		t.Fatalf("expected unknown control command error, got: %v", err)
	}

	// Conflict with -M
	fConflictM := SSHControlFlags{CtlCmd: "check", MasterCount: 1}
	if err := fConflictM.Validate(); err == nil || !strings.Contains(err.Error(), "cannot be combined with master mode") {
		t.Fatalf("expected conflict with -M error, got: %v", err)
	}

	// Conflict with -S none
	fConflictNone := SSHControlFlags{CtlCmd: "check", ControlPath: "none"}
	if err := fConflictNone.Validate(); err == nil || !strings.Contains(err.Error(), "cannot be specified with -S none") {
		t.Fatalf("expected conflict with -S none error, got: %v", err)
	}
}

func TestApplyGeneralOptions(t *testing.T) {
	opts := &SshOptions{}
	cmd := &cobra.Command{}
	cmd.Flags().Uint16P("port", "p", 22, "")
	cmd.Flags().StringVarP(&opts.User, "login", "l", "", "")
	cmd.Flags().StringVarP(&opts.IdentityFile, "identity", "i", "", "")
	cmd.Flags().StringVarP(&opts.JumpHost, "jump", "J", "", "")

	options := []string{
		"Port=2222",
		"User=alice",
		"IdentityFile=/path/to/key",
		"ProxyJump=jump.example.com",
	}

	if err := ApplyGeneralOptions(opts, options, cmd.Flags()); err != nil {
		t.Fatalf("ApplyGeneralOptions failed: %v", err)
	}

	if opts.Port != 2222 {
		t.Fatalf("expected Port 2222, got %d", opts.Port)
	}
	if opts.User != "alice" {
		t.Fatalf("expected User alice, got %q", opts.User)
	}
	if opts.IdentityFile != "/path/to/key" {
		t.Fatalf("expected IdentityFile /path/to/key, got %q", opts.IdentityFile)
	}
	if opts.JumpHost != "jump.example.com" {
		t.Fatalf("expected JumpHost jump.example.com, got %q", opts.JumpHost)
	}
}

func TestControlFlagsRegistration(t *testing.T) {
	// 1. ssh command must have -M, -S, -o, -O
	sshCmd := NewCmdSsh()
	for _, flagName := range []string{"master", "control-path", "option", "control-command"} {
		if sshCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("ssh command missing expected flag %q", flagName)
		}
	}

	// 2. scp command must have -S, -o, but NOT master or control-command
	scpCmd := NewCmdScp()
	for _, flagName := range []string{"control-path", "option"} {
		if scpCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("scp command missing expected flag %q", flagName)
		}
	}
	for _, flagName := range []string{"master", "control-command"} {
		if scpCmd.Flags().Lookup(flagName) != nil {
			t.Errorf("scp command has unexpected flag %q", flagName)
		}
	}

	// 3. sftp command must have -S, -o, but NOT master or control-command
	sftpCmd := NewCmdSftp()
	for _, flagName := range []string{"control-path", "option"} {
		if sftpCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("sftp command missing expected flag %q", flagName)
		}
	}
	for _, flagName := range []string{"master", "control-command"} {
		if sftpCmd.Flags().Lookup(flagName) != nil {
			t.Errorf("sftp command has unexpected flag %q", flagName)
		}
	}

	// 4. exec command must have -S, -o, but NOT master or control-command
	execCmd := NewCmdExec()
	for _, flagName := range []string{"control-path", "option"} {
		if execCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("exec command missing expected flag %q", flagName)
		}
	}
	for _, flagName := range []string{"master", "control-command"} {
		if execCmd.Flags().Lookup(flagName) != nil {
			t.Errorf("exec command has unexpected flag %q", flagName)
		}
	}
}

// TestApplyGeneralOptionsRespectsExplicitFlags verifies that -o values only fill
// gaps. An explicit -p/-l/-i/-J must always win over the same key in -o.
func TestApplyGeneralOptionsRespectsExplicitFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "ssh"}
	options := NewSshOptions()
	options.control.RegisterSSHFlags(cmd)
	cmd.Flags().Uint16VarP(&options.Port, "port", "p", 0, "")
	cmd.Flags().StringVarP(&options.User, "login", "l", "", "")
	cmd.Flags().StringVarP(&options.IdentityFile, "identity", "i", "", "")
	cmd.Flags().StringVarP(&options.JumpHost, "jump", "J", "", "")

	if err := cmd.ParseFlags([]string{
		"-p", "2200", "-l", "explicit",
		"-o", "Port=9999", "-o", "User=from-option", "-o", "IdentityFile=/tmp/k", "-o", "ProxyJump=bastion",
	}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if err := ApplyGeneralOptions(options, options.control.Options, cmd.Flags()); err != nil {
		t.Fatalf("ApplyGeneralOptions failed: %v", err)
	}
	if options.Port != 2200 {
		t.Fatalf("explicit -p must win over -o Port, got %d", options.Port)
	}
	if options.User != "explicit" {
		t.Fatalf("explicit -l must win over -o User, got %q", options.User)
	}
	if options.IdentityFile != "/tmp/k" {
		t.Fatalf("expected -o IdentityFile to apply, got %q", options.IdentityFile)
	}
	if options.JumpHost != "bastion" {
		t.Fatalf("expected -o ProxyJump to apply, got %q", options.JumpHost)
	}
}

// TestControlFlagsRejectUnknownOptionKey verifies the CLI surfaces a mistyped -o
// key instead of silently ignoring it.
func TestControlFlagsRejectUnknownOptionKey(t *testing.T) {
	flags := SSHControlFlags{Options: []string{"ControlMaste=yes"}}
	if _, err := flags.ToSessionControlOptions(); err == nil {
		t.Fatal("expected an unsupported -o option error")
	}
}

// TestMuxDaemonChildNormalizesSession verifies that the detached ControlPersist
// daemon ignores stdin credentials and the original command. With stdio on
// /dev/null a --password-stdin read would fail the child and silently break
// connection persistence.
func TestMuxDaemonChildNormalizesSession(t *testing.T) {
	t.Setenv(sshMuxDaemonEnv, "true")

	options := NewSshOptions()
	cmd := &cobra.Command{Use: "ssh"}
	options.control.RegisterSSHFlags(cmd)
	cmd.Flags().BoolVar(&options.PasswordStdin, "password-stdin", false, "")
	cmd.Flags().BoolVar(&options.OTPStdin, "otp-stdin", false, "")

	if err := cmd.ParseFlags([]string{"-M", "--password-stdin", "web-01", "uptime"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if err := options.Complete(cmd, []string{"web-01", "uptime"}); err != nil {
		t.Fatalf("Complete failed for the multiplexing daemon child: %v", err)
	}
	if !options.NoCmd {
		t.Fatal("expected the daemon child to run in -N mode")
	}
	if options.Command != "" {
		t.Fatalf("expected the daemon child to drop the original command, got %q", options.Command)
	}
	if options.PasswordStdin || options.OTPStdin {
		t.Fatal("expected the daemon child to skip stdin credential reads")
	}
	if !options.StdinRedirect {
		t.Fatal("expected the daemon child to redirect stdin")
	}
}

// TestMuxDaemonChildSkipsMasterHandoff verifies that the daemon child neither
// spawns another daemon nor claims a foreground session, so its idle timer can
// still expire and terminate the process.
func TestMuxDaemonChildSkipsMasterHandoff(t *testing.T) {
	t.Setenv(sshMuxDaemonEnv, "true")

	options := NewSshOptions()
	options.Host = "web-01"
	options.NoCmd = true
	if err := options.handoffPersistentMaster(context.Background(), nil, nil, "web-01"); err != nil {
		t.Fatalf("handoffPersistentMaster must be a no-op for the daemon child: %v", err)
	}

	// A -N foreground master never hands the socket over either.
	t.Setenv(sshMuxDaemonEnv, "")
	noCmd := NewSshOptions()
	noCmd.Host = "web-01"
	noCmd.NoCmd = true
	if err := noCmd.handoffPersistentMaster(context.Background(), nil, nil, "web-01"); err != nil {
		t.Fatalf("handoffPersistentMaster must be a no-op for -N: %v", err)
	}

	// A cancelled session must not resurrect the master the user just stopped.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	stopped := NewSshOptions()
	stopped.Host = "web-01"
	if err := stopped.handoffPersistentMaster(cancelled, nil, nil, "web-01"); err != nil {
		t.Fatalf("handoffPersistentMaster must be a no-op after cancellation: %v", err)
	}
}

// TestMuxDaemonChildIgnoresPositionalCommand verifies that Validate does not
// rebuild a command from the preserved positional arguments after the daemon
// normalization. Otherwise the daemon would plan and possibly run it.
func TestMuxDaemonChildIgnoresPositionalCommand(t *testing.T) {
	t.Setenv(sshMuxDaemonEnv, "true")

	options := NewSshOptions()
	cmd := &cobra.Command{Use: "ssh"}
	options.control.RegisterSSHFlags(cmd)
	cmd.Flags().Uint16VarP(&options.Port, "port", "p", 0, "")
	cmd.Flags().StringVarP(&options.User, "login", "l", "", "")
	cmd.Flags().StringVarP(&options.IdentityFile, "identity", "i", "", "")
	cmd.Flags().StringVarP(&options.JumpHost, "jump", "J", "", "")
	cmd.Flags().StringVar(&options.Remember, "remember", "", "")

	args := []string{"web-01", "uptime", "&&", "whoami"}
	if err := cmd.ParseFlags([]string{"-M"}); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if err := options.Complete(cmd, args); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if err := options.Validate(); err != nil {
		t.Fatalf("Validate failed for the multiplexing daemon child: %v", err)
	}
	if !options.NoCmd {
		t.Fatal("expected the daemon child to stay in -N mode")
	}
	if options.Command != "" {
		t.Fatalf("daemon child rebuilt a command: %q", options.Command)
	}
	if options.commandPlan != nil {
		t.Fatal("daemon child prepared a command plan")
	}
	if options.Host != "web-01" {
		t.Fatalf("expected the target host to survive normalization, got %q", options.Host)
	}
}

// TestHandoffSkipsOneTimePassword verifies that a consumed --otp is never
// replayed by the detached daemon. Replaying it cannot succeed and can trip
// server-side MFA lockouts.
func TestHandoffSkipsOneTimePassword(t *testing.T) {
	options := NewSshOptions()
	options.Host = "web-01"
	options.OTP = "123456"
	if err := options.handoffPersistentMaster(context.Background(), nil, nil, "web-01"); err != nil {
		t.Fatalf("handoffPersistentMaster must skip a one-time-password session: %v", err)
	}
}

// TestWaitForControlSocketStopsWhenDaemonExits verifies that a daemon which dies
// immediately does not stall the completed command for the full readiness
// timeout, and that the reported error stays well formed when no probe has run
// yet (no "%!w(<nil>)" artifact).
func TestWaitForControlSocketStopsWhenDaemonExits(t *testing.T) {
	exited := make(chan struct{})
	close(exited)

	socketPath := filepath.Join(shortControlTempDir(t), "never.sock")
	start := time.Now()
	err := waitForControlSocket(context.Background(), socketPath, 10*time.Second, exited)
	if err == nil {
		t.Fatal("expected an error when the daemon exits before the socket is ready")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("waited %s for an already-exited daemon", elapsed)
	}
	message := err.Error()
	if !strings.Contains(message, "master daemon exited before it answered") {
		t.Fatalf("unexpected error message %q", message)
	}
	if strings.Contains(message, "nil") || strings.Contains(message, "%!w") {
		t.Fatalf("error message carries a nil wrapping artifact: %q", message)
	}
}

// TestWaitForControlSocketWakesOnDaemonExit verifies that an exit arriving during
// the poll interval interrupts the wait immediately instead of being observed
// only on the next probe.
func TestWaitForControlSocketWakesOnDaemonExit(t *testing.T) {
	exited := make(chan struct{})
	socketPath := filepath.Join(shortControlTempDir(t), "late.sock")

	go func() {
		time.Sleep(controlSocketPollInterval / 2)
		close(exited)
	}()

	start := time.Now()
	err := waitForControlSocket(context.Background(), socketPath, 30*time.Second, exited)
	if err == nil {
		t.Fatal("expected an error when the daemon exits during the wait")
	}
	if elapsed := time.Since(start); elapsed > controlSocketPollInterval+500*time.Millisecond {
		t.Fatalf("waited %s; the exit should wake the wait during the poll interval", elapsed)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected the last probe error to be preserved, got %v", err)
	}
}

// TestWaitForControlSocketHonorsCancellation verifies that a canceled caller stops
// the wait promptly and reports cancellation rather than a probe error.
func TestWaitForControlSocketHonorsCancellation(t *testing.T) {
	socketPath := filepath.Join(shortControlTempDir(t), "canceled.sock")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(controlSocketPollInterval / 2)
		cancel()
	}()

	start := time.Now()
	err := waitForControlSocket(ctx, socketPath, 30*time.Second, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > controlSocketPollInterval+500*time.Millisecond {
		t.Fatalf("waited %s for a canceled caller", elapsed)
	}
}

// TestControlUsageFailuresExit255 verifies that rejected control commands and
// flags report the OpenSSH exit status. Exiting 1 made `-O` scriptable failures
// (bad subcommand, invalid combination) indistinguishable from a crash, and the
// message must still be printable by the top-level handler.
func TestControlUsageFailuresExit255(t *testing.T) {
	cases := []struct {
		name  string
		flags SSHControlFlags
	}{
		{name: "unknown command", flags: SSHControlFlags{CtlCmd: "restart"}},
		{name: "with master mode", flags: SSHControlFlags{CtlCmd: "check", MasterCount: 1}},
		{name: "with -S none", flags: SSHControlFlags{CtlCmd: "check", ControlPath: "none"}},
		{name: "invalid -o", flags: SSHControlFlags{CtlCmd: "check", Options: []string{"ControlMaste=yes"}}},
		{name: "invalid -o Port", flags: SSHControlFlags{CtlCmd: "check", Options: []string{"Port=invalid"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.flags.Validate()
			if err == nil {
				t.Fatal("expected a usage error")
			}
			code, ok := ExitCodeFromError(err)
			if !ok || code != 255 {
				t.Fatalf("expected exit code 255, got code=%d (ok=%v)", code, ok)
			}
			if ErrorAlreadyReported(err) {
				t.Fatal("a usage error has not been printed yet and must be reported by the caller")
			}
		})
	}

	// Without -O the same flag errors stay ordinary errors with exit status 1.
	plain := SSHControlFlags{Options: []string{"ControlMaste=yes"}}
	if err := plain.Validate(); err == nil {
		t.Fatal("expected an unsupported -o option error")
	} else if code, ok := ExitCodeFromError(err); ok {
		t.Fatalf("a non-control invocation must not use an OpenSSH exit code, got %d", code)
	}
}

// TestControlCommandAllowsExplicitSocketWithoutTarget verifies that -O against an
// explicit -S socket works without a destination argument. resolveControlSocketPath
// already supported it, but Validate rejected the invocation as "no host" first.
func TestControlCommandAllowsExplicitSocketWithoutTarget(t *testing.T) {
	options := NewSshOptions()
	options.control = SSHControlFlags{CtlCmd: "check", ControlPath: "/tmp/explicit.sock"}
	if err := options.Validate(); err != nil {
		t.Fatalf("Validate rejected -O with an explicit control socket and no target: %v", err)
	}

	// Without -S the socket has to come from a resolved target, so the argument
	// is still required and its absence must stay an error with exit code 255.
	missingTarget := NewSshOptions()
	missingTarget.control = SSHControlFlags{CtlCmd: "check"}
	if err := missingTarget.Validate(); err == nil {
		t.Fatal("expected -O without -S and without a target to be rejected")
	} else if code, ok := ExitCodeFromError(err); !ok || code != 255 {
		t.Fatalf("expected exit code 255 for -O missing target, got code=%d (ok=%v)", code, ok)
	}
}

// TestReleaseMastersForHandoffClosesTargetSocket verifies that
// releaseMastersForHandoff reserves and shuts down a persistent target master.
func TestReleaseMastersForHandoffClosesTargetSocket(t *testing.T) {
	targetSock := filepath.Join(shortControlTempDir(t), "target.sock")
	targetMaster, err := ssh.StartMuxServer(context.Background(), nilDummySSHClient(t), ssh.MuxMasterOptions{
		Path:                  targetSock,
		Target:                ssh.TargetContext{Control: &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: targetSock, Persist: "10m"}},
		InitialActiveSessions: 1,
	})
	if err != nil {
		t.Fatalf("StartMuxServer failed: %v", err)
	}
	defer func() { _ = targetMaster.Shutdown() }()

	targetMaster.RemoveForegroundSession()
	ready, err := releaseMastersForHandoff(nil, targetMaster, targetSock)
	if err != nil {
		t.Fatalf("releaseMastersForHandoff failed: %v", err)
	}
	if !ready {
		t.Fatal("expected releaseMastersForHandoff to succeed")
	}
	select {
	case <-targetMaster.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("target master did not shut down during handoff release")
	}
}

func nilDummySSHClient(_ *testing.T) *cryptoSSH.Client {
	return &cryptoSSH.Client{}
}
