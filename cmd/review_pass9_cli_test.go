package cmd

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestPass9_ScpNativeOpenSSHFlagsAlignment(t *testing.T) {
	scpCmd := NewCmdScp()
	if f := scpCmd.Flags().Lookup("login"); f != nil {
		t.Errorf("scp unexpectedly registered --login flag: %+v", f)
	}
	if f := scpCmd.Flags().ShorthandLookup("l"); f != nil {
		t.Errorf("scp unexpectedly registered -l shorthand: %+v", f)
	}
	if f := scpCmd.Flags().Lookup("port"); f == nil || f.Shorthand != "P" {
		t.Errorf("scp port flag = %+v, want -P/--port", f)
	}
	if f := scpCmd.Flags().Lookup("cipher"); f == nil || f.Shorthand != "c" {
		t.Errorf("scp cipher flag = %+v, want -c/--cipher", f)
	}

	opts := NewScpOptions()
	if err := scpCmd.ParseFlags([]string{"-P", "2222", "-c", "aes256-gcm@openssh.com", "-o", "User=alice"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	// Apply flag values parsed by scpCmd via Complete on a bound command.
	boundCmd := NewCmdScp()
	boundCmd.SetArgs([]string{"-P", "2222", "-c", "aes256-gcm@openssh.com", "-o", "User=alice", "./local.txt", "bob@web:/tmp/remote.txt"})
	if err := boundCmd.ParseFlags([]string{"-P", "2222", "-c", "aes256-gcm@openssh.com", "-o", "User=alice"}); err != nil {
		t.Fatalf("boundCmd.ParseFlags: %v", err)
	}
	opts.Port, _ = boundCmd.Flags().GetUint16("port")
	opts.CipherSpec, _ = boundCmd.Flags().GetString("cipher")
	opts.control.Options, _ = boundCmd.Flags().GetStringArray("option")
	if err := opts.Complete(boundCmd, []string{"./local.txt", "bob@web:/tmp/remote.txt"}); err != nil {
		t.Fatalf("ScpOptions.Complete: %v", err)
	}
	ctrlOpts, err := opts.toSessionControlOptions()
	if err != nil {
		t.Fatalf("toSessionControlOptions: %v", err)
	}
	if ctrlOpts.Options == nil || ctrlOpts.Options.Ciphers() != "aes256-gcm@openssh.com" {
		t.Errorf("scp -c Ciphers = %v, want aes256-gcm@openssh.com", ctrlOpts.Options)
	}
	if opts.User != "alice" {
		t.Errorf("scp -o User=alice gave User=%q, want alice", opts.User)
	}
	srcPI, err := parsePath("bob@web:/tmp/remote.txt")
	if err != nil {
		t.Fatalf("parsePath(bob@web:...): %v", err)
	}
	u, _, p, _ := opts.resolveUserAndPort(srcPI)
	if u != "bob" || p != 2222 {
		t.Errorf("resolveUserAndPort(bob@web with -o User=alice -P 2222) = (%q, %d), want (bob, 2222)", u, p)
	}
}

func TestPass9_H2_IdentityOptionPersistenceAndLiteralFlag(t *testing.T) {
	// 1. -o IdentityFile=none stays out of o.IdentityFile and never persists <cwd>/none.
	sshCmd := NewCmdSsh()
	if err := sshCmd.ParseFlags([]string{"-o", "IdentityFile=none"}); err != nil {
		t.Fatalf("ParseFlags(-o IdentityFile=none): %v", err)
	}
	opts := NewSshOptions()
	opts.control.Options, _ = sshCmd.Flags().GetStringArray("option")
	if err := ApplyGeneralOptions(opts, opts.control.Options, sshCmd.Flags()); err != nil {
		t.Fatalf("ApplyGeneralOptions(-o IdentityFile=none): %v", err)
	}
	if opts.IdentityFile != "" {
		t.Errorf("opts.IdentityFile = %q, want empty for non-persistable IdentityFile=none", opts.IdentityFile)
	}
	if !slices.Equal(opts.IdentityFiles, []string{"none"}) {
		t.Errorf("opts.IdentityFiles = %v, want [none]", opts.IdentityFiles)
	}
	ident := models.Identity{User: "alice", AuthType: "auto"}
	if updateIdentityFields(&ident, opts) {
		t.Errorf("updateIdentityFields mutated identity %+v for IdentityFile=none", ident)
	}
	if ident.KeyPath != "" || ident.AuthType != "auto" {
		t.Errorf("identity modified: %+v", ident)
	}

	// 2. -i none treats "none" as literal path <cwd>/none (matching OpenSSH_10.6p2) while appending -o IdentityFile.
	optsMixed := NewSshOptions()
	optsMixed.IdentityFiles = []string{"none"}
	optsMixed.control.Options = []string{"IdentityFile=~/extra_key"}
	mixedCmd := NewCmdSsh()
	if err := mixedCmd.ParseFlags([]string{"-i", "none", "-o", "IdentityFile=~/extra_key"}); err != nil {
		t.Fatalf("ParseFlags(mixed): %v", err)
	}
	if err := ApplyGeneralOptions(optsMixed, []string{"IdentityFile=~/extra_key"}, mixedCmd.Flags()); err != nil {
		t.Fatalf("ApplyGeneralOptions(mixed): %v", err)
	}
	if !strings.HasSuffix(optsMixed.IdentityFile, filepath.Join("", "none")) {
		t.Errorf("literal -i none gave IdentityFile=%q, want <cwd>/none", optsMixed.IdentityFile)
	}
	if len(optsMixed.IdentityFiles) != 2 || optsMixed.IdentityFiles[1] != "~/extra_key" {
		t.Errorf("mixed IdentityFiles = %v, want [<cwd>/none ~/extra_key]", optsMixed.IdentityFiles)
	}
}

func TestPass9_H6_MuxDaemonArgsAndDrainAcrossControlMasterNo(t *testing.T) {
	// 1. H6.2 & H6.3: buildMuxDaemonSpec keeps ordered IdentityFiles (including none) and ProxyCommand=none.
	opts := NewSshOptions()
	opts.Host = "edge"
	opts.IdentityFiles = []string{"/tmp/k1", "none", "/tmp/k2"}
	opts.IdentityFile = "/tmp/k1"
	opts.control.Options = []string{"ProxyCommand=none", "ProxyCommand=nc %h %p", "IdentityFile=/tmp/k2"}
	spec := opts.buildMuxDaemonSpec("openssh:edge", "/tmp/edge.sock", nil)
	if !slices.Equal(spec.IdentityFiles, []string{"/tmp/k1", "none", "/tmp/k2"}) {
		t.Errorf("buildMuxDaemonSpec(nil).IdentityFiles = %v, want [/tmp/k1 none /tmp/k2]", spec.IdentityFiles)
	}
	if !slices.Contains(spec.Options, "ProxyCommand=none") {
		t.Errorf("buildMuxDaemonSpec(nil) missing ProxyCommand=none in %v", spec.Options)
	}

	// Non-nil master (real target handoff) preserves -o ProxyCommand=none as well.
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, portStr, _ := net.SplitHostPort(fix.Address)
	fixPort, _ := strconv.Atoi(portStr)

	tmpDir := shortControlTempDir(t)
	jump1Sock := filepath.Join(tmpDir, "p9-j1.sock")
	targetSock := filepath.Join(tmpDir, "p9-t.sock")

	repo := setupTestRepository(t)
	cfg := repo.Snapshot()
	cfg.Hosts.Set("h-p9", models.Host{Address: fixHost, Port: uint16(fixPort)})
	cfg.Identities.Set("id-p9", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("p9-jump1", models.Node{
		HostRef:     "h-p9",
		IdentityRef: "id-p9",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterYes,
			Path:    jump1Sock,
			Persist: "5m",
		}),
	})
	cfg.Nodes.Set("p9-jump2-nocm", models.Node{
		HostRef:     "h-p9",
		IdentityRef: "id-p9",
		ProxyJump:   "p9-jump1",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master: ssh.ControlMasterNo,
		}),
	})
	cfg.Nodes.Set("p9-target", models.Node{
		HostRef:     "h-p9",
		IdentityRef: "id-p9",
		ProxyJump:   "p9-jump2-nocm",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master:  ssh.ControlMasterYes,
			Path:    targetSock,
			Persist: "5m",
		}),
	})
	store := config.NewDefaultStore(filepath.Join(tmpDir, "cfg.yaml"), filepath.Join(tmpDir, "cfg.key"))
	savedRepo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	adp := adapter.NewSSHAdapter(savedRepo, adapter.WithNonInteractive(true))
	connector := newPass6Connector(adp)
	defer func() { _ = connector.CloseAll() }()

	cli, err := connector.Connect(ctx, "p9-target")
	if err != nil {
		t.Fatalf("Connect(p9-target across ControlMaster=no): %v", err)
	}
	defer func() { _ = cli.Close() }()

	j1Master := ssh.GetActiveMuxServer(jump1Sock)
	tMaster := ssh.GetActiveMuxServer(targetSock)
	if j1Master == nil || tMaster == nil {
		t.Fatalf("expected active j1Master=%v and tMaster=%v", j1Master, tMaster)
	}

	optsTarget := NewSshOptions()
	optsTarget.Host = "p9-target"
	optsTarget.control.Options = []string{"ProxyCommand=none", "ProxyCommand=nc %h %p"}
	withMasterSpec := optsTarget.buildMuxDaemonSpec("p9-target", targetSock, tMaster)
	if !slices.Contains(withMasterSpec.Options, "ProxyCommand=none") {
		t.Errorf("buildMuxDaemonSpec(with master) stripped ProxyCommand=none: %v", withMasterSpec.Options)
	}

	// Stop outer j1Master and confirm drainOwnedMastersWithProvider traverses p9-jump2-nocm to retire tMaster.
	mc, err := ssh.DialMuxClient(ctx, jump1Sock)
	if err != nil {
		t.Fatalf("DialMuxClient(jump1): %v", err)
	}
	stopErr := mc.StopListening(ctx)
	_ = mc.Close()
	if stopErr != nil {
		t.Fatalf("StopListening(jump1): %v", stopErr)
	}
	if err := drainOwnedMastersWithProvider(ctx, savedRepo, connector); err != nil {
		t.Fatalf("drainOwnedMastersWithProvider: %v", err)
	}
	if !isMasterClosed(j1Master) || !isMasterClosed(tMaster) {
		t.Fatalf("expected both j1Master (closed=%v) and tMaster across ControlMaster=no (closed=%v) closed",
			isMasterClosed(j1Master), isMasterClosed(tMaster))
	}
}

func TestPass9_M4_HostAddEditPortZeroAndReservedAlias(t *testing.T) {
	t.Setenv("XOPS_CONFIG_DIR", t.TempDir())

	for _, args := range [][]string{
		{"--skip-verify", "--port", "0", "web", "192.0.2.10"},
		{"--skip-verify", "--user", "alice", "-a", "openssh", "192.0.2.10"},
		{"--skip-verify", "--user", "alice", "-a", "openssh:web", "192.0.2.10"},
	} {
		addCmd := hostcmd.NewCmdInventoryAdd()
		addCmd.SetOut(io.Discard)
		addCmd.SetErr(io.Discard)
		addCmd.SetArgs(args)
		if err := addCmd.Execute(); err == nil {
			t.Errorf("xops host add %v succeeded, want validation error", args)
		}
	}

	seedCmd := hostcmd.NewCmdInventoryAdd()
	seedCmd.SetOut(io.Discard)
	seedCmd.SetErr(io.Discard)
	seedCmd.SetArgs([]string{"--skip-verify", "--user", "alice", "-a", "valid-alias", "192.0.2.10"})
	if err := seedCmd.Execute(); err != nil {
		t.Fatalf("seed host add failed: %v", err)
	}

	for _, args := range [][]string{
		{"valid-alias", "-p", "0"},
		{"valid-alias", "-a", "openssh"},
		{"valid-alias", "-a", "openssh:sub"},
	} {
		editCmd := hostcmd.NewCmdInventoryEdit()
		editCmd.SetOut(io.Discard)
		editCmd.SetErr(io.Discard)
		editCmd.SetArgs(args)
		if err := editCmd.Execute(); err == nil {
			t.Errorf("xops host edit %v succeeded, want validation error", args)
		}
	}
}

func TestPass9_L1_ExplicitEmptyFlagsRejected(t *testing.T) {
	// ssh empty value flags
	for _, flagArgs := range [][]string{
		{"-c", "", "web"},
		{"-e", "", "web"},
		{"-S", "", "web"},
		{"-F", "", "web"},
		{"-l", "", "web"},
		{"-J", "", "web"},
		{"-i", "", "web"},
		{"-O", "", "web"},
	} {
		cmd := NewCmdSsh()
		opts := NewSshOptions()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.ParseFlags(flagArgs[:2]); err != nil {
			t.Fatalf("ssh ParseFlags(%v): %v", flagArgs, err)
		}
		// Ensure Complete path rejects empty flag rather than silently ignoring it.
		if err := ApplyGeneralOptions(opts, opts.control.Options, cmd.Flags()); err == nil {
			t.Errorf("ssh ApplyGeneralOptions(%v) = nil, want explicit empty flag error", flagArgs)
		}
	}

	// scp empty flags
	for _, flagArgs := range [][]string{
		{"-c", ""},
		{"-S", ""},
		{"-F", ""},
		{"-J", ""},
		{"-i", ""},
	} {
		cmd := NewCmdScp()
		if err := cmd.ParseFlags(flagArgs); err != nil {
			t.Fatalf("scp ParseFlags(%v): %v", flagArgs, err)
		}
		if err := ApplyGeneralOptions(NewSshOptions(), nil, cmd.Flags()); err == nil {
			t.Errorf("scp ApplyGeneralOptions(%v) = nil, want explicit empty flag error", flagArgs)
		}
	}

	// sftp empty flags
	for _, flagArgs := range [][]string{
		{"-c", ""},
		{"-S", ""},
		{"-F", ""},
		{"-J", ""},
		{"-i", ""},
	} {
		cmd := NewCmdSftp()
		if err := cmd.ParseFlags(flagArgs); err != nil {
			t.Fatalf("sftp ParseFlags(%v): %v", flagArgs, err)
		}
		if err := ApplyGeneralOptions(NewSshOptions(), nil, cmd.Flags()); err == nil {
			t.Errorf("sftp ApplyGeneralOptions(%v) = nil, want explicit empty flag error", flagArgs)
		}
	}

	// exec: -S "" fails in ApplyGeneralOptions, whereas -c "" (--cmd) hits exec's own "explicit command must not be empty"!
	execEmptySocket := NewCmdExec()
	if err := execEmptySocket.ParseFlags([]string{"-S", ""}); err != nil {
		t.Fatalf("exec ParseFlags(-S ''): %v", err)
	}
	if err := ApplyGeneralOptions(NewSshOptions(), nil, execEmptySocket.Flags()); err == nil {
		t.Error("exec ApplyGeneralOptions(-S '') = nil, want error")
	}

	execEmptyCmd := NewCmdExec()
	if err := execEmptyCmd.ParseFlags([]string{"-c", ""}); err != nil {
		t.Fatalf("exec ParseFlags(-c ''): %v", err)
	}
	eo := NewExecOptions()
	err := eo.Complete(execEmptyCmd, []string{"web"})
	if err == nil || !strings.Contains(err.Error(), "explicit command must not be empty") {
		t.Errorf("exec Complete(-c '') = %v, want 'explicit command must not be empty'", err)
	}
}
