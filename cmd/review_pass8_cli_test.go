package cmd

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

func TestPass8_H4_ApplyGeneralOptionsFirstWinsAndNilFlagsIdentity(t *testing.T) {
	opts := NewSshOptions()
	if err := ApplyGeneralOptions(opts, []string{
		"User=first-user",
		"User=second-user",
		"Port=2201",
		"Port=2202",
		"HostName=first.example.com",
		"HostName=second.example.com",
		"ProxyJump=jump-first",
		"ProxyJump=jump-second",
		"IdentityFile=/tmp/id_first",
		"IdentityFile=/tmp/id_second",
	}, nil); err != nil {
		t.Fatalf("ApplyGeneralOptions failed: %v", err)
	}
	if opts.User != "first-user" {
		t.Errorf("User = %q, want first-user", opts.User)
	}
	if opts.Port != 2201 {
		t.Errorf("Port = %d, want 2201", opts.Port)
	}
	if opts.cliHostName != "first.example.com" {
		t.Errorf("cliHostName = %q, want first.example.com", opts.cliHostName)
	}
	if opts.JumpHost != "jump-first" {
		t.Errorf("JumpHost = %q, want jump-first", opts.JumpHost)
	}
	if len(opts.IdentityFiles) != 2 || opts.IdentityFiles[0] != "/tmp/id_first" || opts.IdentityFiles[1] != "/tmp/id_second" {
		t.Errorf("IdentityFiles with nil flags = %v, want [/tmp/id_first /tmp/id_second]", opts.IdentityFiles)
	}

	// Explicit ProxyCommand or ProxyCommand=none blocks later -o ProxyJump.
	for _, cmdVal := range []string{"nc %h %p", "none"} {
		o := NewSshOptions()
		if err := ApplyGeneralOptions(o, []string{
			"ProxyCommand=" + cmdVal,
			"ProxyJump=later-jump",
		}, nil); err != nil {
			t.Fatalf("ApplyGeneralOptions(ProxyCommand=%s): %v", cmdVal, err)
		}
		if o.JumpHost != "" {
			t.Errorf("ProxyCommand=%s must block later -o ProxyJump, got JumpHost=%q", cmdVal, o.JumpHost)
		}
	}

	// Explicit -l/-p via FlagSet still win over -o while invalid subsequent -o still errors.
	cmd := &cobra.Command{Use: "ssh"}
	flagOpts := NewSshOptions()
	cmd.Flags().Uint16VarP(&flagOpts.Port, "port", "p", 0, "")
	cmd.Flags().StringVarP(&flagOpts.User, "login", "l", "", "")
	if err := cmd.ParseFlags([]string{"-l", "flag-user", "-p", "2299"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := ApplyGeneralOptions(flagOpts, []string{"User=opt-user", "Port=2201"}, cmd.Flags()); err != nil {
		t.Fatalf("ApplyGeneralOptions(flags): %v", err)
	}
	if flagOpts.User != "flag-user" || flagOpts.Port != 2299 {
		t.Errorf("explicit flags overridden: user=%q port=%d", flagOpts.User, flagOpts.Port)
	}

	badOpts := NewSshOptions()
	if err := ApplyGeneralOptions(badOpts, []string{"Port=2201", "Port=notaport"}, nil); err == nil {
		t.Fatal("expected invalid second -o Port to return validation error")
	}
}

func TestPass8_M4_OpenSSHSelectorAcrossCLICommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Run("parse_addr", verifyPass8M4ParseAddr)
	t.Run("ssh_and_sftp", verifyPass8M4SshAndSftp)
	t.Run("exec", verifyPass8M4Exec)
	t.Run("scp", verifyPass8M4Scp)
	t.Run("exclude_and_host_add", verifyPass8M4ExcludeAndHostAdd)
}

func verifyPass8M4ParseAddr(t *testing.T) {
	u, h, p, err := utils.ParseAddr("openssh:alice@web:2222")
	if err != nil || u != "alice" || h != "openssh:web" || p != 2222 {
		t.Fatalf("ParseAddr(openssh:alice@web:2222) = (%q, %q, %d, %v)", u, h, p, err)
	}
	u2, h2, p2, err := utils.ParseAddr("openssh:web")
	if err != nil || u2 != "" || h2 != "openssh:web" || p2 != 0 {
		t.Fatalf("ParseAddr(openssh:web) = (%q, %q, %d, %v)", u2, h2, p2, err)
	}
	for _, bad := range []string{"openssh:", "openssh: web", "openssh:openssh:web"} {
		if _, _, _, err := utils.ParseAddr(bad); err == nil {
			t.Errorf("ParseAddr(%q) expected error, got nil", bad)
		}
	}
}

func verifyPass8M4SshAndSftp(t *testing.T) {
	for _, mode := range []string{"positional", "flag"} {
		so := NewSshOptions()
		if mode == "positional" {
			so.args = []string{"openssh:alice@web:2222", "uptime"}
		} else {
			so.Host = "openssh:alice@web:2222"
		}
		if err := so.parseArgs(); err != nil {
			t.Fatalf("ssh parseArgs (%s): %v", mode, err)
		}
		if so.Host != "openssh:web" || so.User != "alice" || so.Port != 2222 || so.Target.Selector != "openssh:web" {
			t.Errorf("ssh (%s) parsed = host:%q user:%q port:%d sel:%q", mode, so.Host, so.User, so.Port, so.Target.Selector)
		}
	}

	sftpOpts := NewSftpOptions()
	sftpOpts.Port = 2299
	if err := sftpOpts.Complete(nil, []string{"openssh:alice@web:2222"}); err != nil {
		t.Fatalf("sftp Complete: %v", err)
	}
	if err := sftpOpts.parseArgs(); err != nil {
		t.Fatalf("sftp parseArgs: %v", err)
	}
	if sftpOpts.Host != "openssh:web" || sftpOpts.User != "alice" || sftpOpts.Port != 2299 {
		t.Errorf("sftp parsed = host:%q user:%q port:%d, want openssh:web alice 2299", sftpOpts.Host, sftpOpts.User, sftpOpts.Port)
	}
}

func verifyPass8M4Exec(t *testing.T) {
	hExec, uExec, pExec, consumed, err := parsePositionalHost([]string{"openssh:alice@web:2222", "id"})
	if err != nil || hExec != "openssh:web" || uExec != "alice" || pExec != 2222 || consumed != 1 {
		t.Fatalf("exec parsePositionalHost = (%q, %q, %d, %d, %v)", hExec, uExec, pExec, consumed, err)
	}
	hostsFlag, err := utils.ParseHosts("openssh:alice@web:2222", "", "")
	if err != nil || len(hostsFlag) != 1 || hostsFlag[0].Host != "openssh:web" || hostsFlag[0].User != "alice" || hostsFlag[0].Port != 2222 {
		t.Fatalf("ParseHosts(openssh:...) = (%+v, %v)", hostsFlag, err)
	}
	csvPath := filepath.Join(t.TempDir(), "hosts.csv")
	if err := os.WriteFile(csvPath, []byte("host,port\nopenssh:bob@web,2200\n"), 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	csvHosts, err := utils.ParseHosts("", "", csvPath)
	if err != nil || len(csvHosts) != 1 || csvHosts[0].Host != "openssh:web" || csvHosts[0].User != "bob" || csvHosts[0].Port != 2200 {
		t.Fatalf("ParseHosts(csv) = (%+v, %v)", csvHosts, err)
	}
}

func verifyPass8M4Scp(t *testing.T) {

	scpCases := []struct {
		raw      string
		wantUser string
		wantHost string
		wantPath string
		wantErr  bool
	}{
		{raw: "openssh:alice@web:/tmp/out", wantUser: "alice", wantHost: "openssh:web", wantPath: "/tmp/out"},
		{raw: "openssh:web:22:file", wantHost: "openssh:web", wantPath: "22:file"},
		{raw: "openssh:[::1]:/tmp/v6", wantHost: "openssh:::1", wantPath: "/tmp/v6"},
		{raw: "openssh:web", wantErr: true},
		{raw: "openssh:openssh:web:/tmp/out", wantErr: true},
		{raw: "openssh:dir/web:/tmp/out", wantErr: true},
	}
	for _, tc := range scpCases {
		pi, err := parsePath(tc.raw)
		if (err != nil) != tc.wantErr {
			t.Errorf("parsePath(%q) err=%v, wantErr=%v", tc.raw, err, tc.wantErr)
			continue
		}
		if tc.wantErr {
			continue
		}
		if !pi.IsRemote || pi.User != tc.wantUser || pi.Host != tc.wantHost || pi.Port != 0 || pi.Path != tc.wantPath {
			t.Errorf("parsePath(%q) = %+v", tc.raw, pi)
		}
	}
}

func verifyPass8M4ExcludeAndHostAdd(t *testing.T) {
	repo := setupTestRepository(t)
	cands := []utils.ExcludeTargetInfo{
		{NodeID: "openssh:web", OpenSSHAlias: "web", User: "alice", Port: 22, UnmanagedHosts: []string{"web", "openssh:web"}},
	}
	if _, err := utils.ResolveExcludesForTargets(repo, []string{"openssh:openssh:web"}, cands); err == nil {
		t.Fatal("expected error for malformed double prefix openssh:openssh:web")
	}
	exclValid, err := utils.ResolveExcludesForTargets(repo, []string{"openssh:web"}, cands)
	if err != nil {
		t.Fatalf("ResolveExcludesForTargets(valid): %v", err)
	}
	if !utils.IsTargetExcluded(exclValid, cands[0]) {
		t.Fatal("valid exclude openssh:web must exclude openssh:web")
	}

	addCmd := hostcmd.NewCmdInventoryAdd()
	addCmd.SetOut(io.Discard)
	addCmd.SetErr(io.Discard)
	addCmd.SetArgs([]string{"--skip-verify", "--user", "alice", "openssh:web"})
	if err := addCmd.Execute(); err == nil {
		t.Fatal("expected xops host add openssh:web to fail validation")
	}
}

func TestPass8_M5_ReserveJumpMasterForHandoffAtomicNonPersistent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, _ := net.SplitHostPort(fix.Address)
	fixPort, _ := strconv.Atoi(portStr)

	tmpDir := shortControlTempDir(t)
	jumpSock := filepath.Join(tmpDir, "pass8-m5-jump.sock")
	targetSock := filepath.Join(tmpDir, "pass8-m5-target.sock")

	_, connector := buildPass7JumpConnector(t, fixHost, fixPort, jumpSock, "no", targetSock, "5m")
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, "p7-target")
	if err != nil {
		t.Fatalf("Connect(p7-target): %v", err)
	}
	defer func() { _ = client.Close() }()

	jumpMaster := ssh.GetActiveMuxServer(jumpSock)
	if jumpMaster == nil || jumpMaster.PersistEnabled() || !connector.HasMasterSession(jumpMaster) {
		t.Fatalf("expected connector-owned non-persistent jumpMaster, got %v", jumpMaster)
	}

	var reserved, released []*ssh.MuxServer
	ok, dead := reserveJumpMasterForHandoff(connector, jumpMaster, &reserved, &released)
	if !ok || dead || len(reserved) != 1 || len(released) != 0 {
		t.Fatalf("reserveJumpMasterForHandoff = (ok=%v dead=%v reserved=%d released=%d), want (true false 1 0)",
			ok, dead, len(reserved), len(released))
	}

	// While reserved, concurrent mux clients must be rejected atomically instead of entering during the handoff window.
	if muxCli, dialErr := ssh.DialMuxClient(ctx, jumpSock); dialErr == nil {
		fwd := ssh.ForwardRequest{Type: ssh.ForwardLocal, ListenHost: "127.0.0.1", ConnectHost: "127.0.0.1", ConnectPort: uint32(fixPort)}
		_, openErr := muxCli.OpenForward(ctx, fwd)
		_ = muxCli.Close()
		if openErr == nil {
			t.Fatal("concurrent mux client OpenForward succeeded while non-persistent jump master was reserved for handoff")
		}
	}

	// Rolling back restores admission without killing the foreground-owned non-persistent master.
	rollbackHandoffReservation(connector, reserved, released)
	if isMasterClosed(jumpMaster) || !connector.HasMasterSession(jumpMaster) {
		t.Fatal("rollbackHandoffReservation closed or released non-persistent jump master unexpectedly")
	}

	muxCli2, err := ssh.DialMuxClient(ctx, jumpSock)
	if err != nil {
		t.Fatalf("DialMuxClient after rollback: %v", err)
	}
	defer func() { _ = muxCli2.Close() }()
	fwd2 := ssh.ForwardRequest{Type: ssh.ForwardLocal, ListenHost: "127.0.0.1", ConnectHost: "127.0.0.1", ConnectPort: uint32(fixPort)}
	if _, err := muxCli2.OpenForward(ctx, fwd2); err != nil {
		t.Fatalf("OpenForward after rollback failed: %v", err)
	}
	_ = muxCli2.CloseForward(ctx, fwd2)
}

func TestPass8_L3_SftpFlagsAlignedWithNativeOpenSSH(t *testing.T) {
	sftpCmd := NewCmdSftp()

	portFlag := sftpCmd.Flags().Lookup("port")
	if portFlag == nil || portFlag.Shorthand != "P" {
		t.Fatalf("sftp --port flag = %+v, want shorthand -P", portFlag)
	}
	cipherFlag := sftpCmd.Flags().Lookup("cipher")
	if cipherFlag == nil || cipherFlag.Shorthand != "c" {
		t.Fatalf("sftp --cipher flag = %+v, want shorthand -c", cipherFlag)
	}
	if f := sftpCmd.Flags().Lookup("login"); f != nil {
		t.Errorf("sftp unexpectedly registered --login flag: %+v", f)
	}
	if f := sftpCmd.Flags().ShorthandLookup("l"); f != nil {
		t.Errorf("sftp unexpectedly registered -l shorthand: %+v", f)
	}
	if f := sftpCmd.Flags().ShorthandLookup("p"); f != nil {
		t.Errorf("sftp unexpectedly registered -p shorthand: %+v", f)
	}

	for _, args := range [][]string{
		{"-P", "0", "example.com"},
		{"--port=0", "example.com"},
	} {
		cmdZero := NewCmdSftp()
		cmdZero.SetOut(io.Discard)
		cmdZero.SetErr(io.Discard)
		cmdZero.SetArgs(args)
		if err := cmdZero.Execute(); err == nil || !strings.Contains(err.Error(), "1") {
			t.Errorf("sftp %v expected explicit zero-port validation error, got %v", args, err)
		}
	}
}

func TestPass8_M5_DrainOwnedMastersRetiresDependentsOfStoppedJumpMaster(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, _ := net.SplitHostPort(fix.Address)
	fixPort, _ := strconv.Atoi(portStr)

	tmpDir := shortControlTempDir(t)
	jumpSock := filepath.Join(tmpDir, "pass8-drain-jump.sock")
	targetSock := filepath.Join(tmpDir, "pass8-drain-target.sock")

	repo, connector := buildPass7JumpConnector(t, fixHost, fixPort, jumpSock, "5m", targetSock, "5m")
	defer func() { _ = connector.CloseAll() }()

	client, err := connector.Connect(ctx, "p7-target")
	if err != nil {
		t.Fatalf("Connect(p7-target): %v", err)
	}
	defer func() { _ = client.Close() }()

	jumpMaster := ssh.GetActiveMuxServer(jumpSock)
	targetMaster := ssh.GetActiveMuxServer(targetSock)
	if jumpMaster == nil || targetMaster == nil {
		t.Fatalf("expected active jumpMaster (%v) and targetMaster (%v)", jumpMaster, targetMaster)
	}

	mc, err := ssh.DialMuxClient(ctx, jumpSock)
	if err != nil {
		t.Fatalf("DialMuxClient(jump): %v", err)
	}
	stopErr := mc.StopListening(ctx)
	_ = mc.Close()
	if stopErr != nil {
		t.Fatalf("StopListening(jump): %v", stopErr)
	}

	if err := drainOwnedMasters(ctx, connector); err != nil {
		t.Fatalf("drainOwnedMasters returned error: %v", err)
	}
	if !isMasterClosed(jumpMaster) {
		t.Fatal("expected stopped jumpMaster to be closed after drainOwnedMasters")
	}
	if !isMasterClosed(targetMaster) {
		t.Fatal("expected dependent targetMaster to be synchronously retired when stopped jumpMaster closed")
	}
	ready, wErr := waitAndReleaseMastersForHandoffWithProvider(ctx, connector, repo, targetMaster, targetSock)
	if wErr != nil || ready {
		t.Fatalf("expected waitAndReleaseMastersForHandoffWithProvider to abort (false, nil), got (%v, %v)", ready, wErr)
	}
}
