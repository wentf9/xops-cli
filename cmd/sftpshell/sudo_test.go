package sftpshell

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/creack/pty"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestShell_WithSudoOption(t *testing.T) {
	s := &Shell{}
	WithSudo(true)(s)
	if !s.sudo {
		t.Errorf("expected s.sudo to be true")
	}
	if !s.transferConfig.Sudo {
		t.Errorf("expected s.transferConfig.Sudo to be true")
	}

	s2 := &Shell{}
	WithSudo(false)(s2)
	if s2.sudo {
		t.Errorf("expected s2.sudo to be false")
	}
	if s2.transferConfig.Sudo {
		t.Errorf("expected s2.transferConfig.Sudo to be false")
	}
}

func TestShell_New_InheritsSudoFromClient(t *testing.T) {
	sftpCli := &sftp.Client{}
	sftp.WithSudo(true)(sftpCli)
	sshCli := &ssh.Client{}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()

	shell, err := New(t.Context(), sftpCli, sshCli, r, w, w)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if !shell.sudo {
		t.Errorf("expected shell.sudo to inherit true from sftp.Client")
	}
	if !shell.transferConfig.Sudo {
		t.Errorf("expected shell.transferConfig.Sudo to be true")
	}

	// Overriding with WithSudo(false)
	shell2, err := New(t.Context(), sftpCli, sshCli, r, w, w, WithSudo(false))
	if err != nil {
		t.Fatalf("New with WithSudo(false) failed: %v", err)
	}
	if shell2.sudo {
		t.Errorf("expected shell2.sudo to be overridden to false")
	}
	if shell2.transferConfig.Sudo {
		t.Errorf("expected shell2.transferConfig.Sudo to be overridden to false")
	}
}

func TestShell_RefreshClient_PreservesSudo(t *testing.T) {
	var gotSudo bool
	mockFactory := func(ctx context.Context, sshCli *ssh.Client, opts ...sftp.Option) (*sftp.Client, error) {
		cfg := &sftp.Client{}
		for _, opt := range opts {
			opt(cfg)
		}
		gotSudo = cfg.Config().Sudo
		return cfg, nil
	}

	s := &Shell{}
	WithSudo(true)(s)
	sshCli := &ssh.Client{}
	err := s.refreshClient(t.Context(), nil, sshCli, mockFactory, s.transferConfig)
	if err != nil {
		t.Fatalf("refreshClient failed: %v", err)
	}
	if !gotSudo {
		t.Errorf("expected WithSudo(true) to be passed to factory during refreshClient")
	}
}

func TestShell_HandleExec_WithSudo(t *testing.T) {
	var executedCmd atomic.Pointer[string]
	rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
		executedCmd.Store(&cmd)
	})
	defer cleanup()

	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeSudoer,
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterBash,
			LaunchDialect: ssh.LaunchPOSIX,
		},
	}
	sshCli := ssh.NewTestClientWithRaw(rawClient, connCfg)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	s := &Shell{
		batch:     true,
		sudo:      true,
		sshClient: sshCli,
		stdout:    &stdout,
		stderr:    &stderr,
	}

	err := s.handleExec(t.Context(), []string{"whoami"})
	if err != nil {
		t.Fatalf("handleExec failed: %v", err)
	}

	cmdPtr := executedCmd.Load()
	if cmdPtr == nil {
		t.Fatal("expected command to be executed on server")
	}
	if !strings.HasPrefix(*cmdPtr, "sudo ") {
		t.Errorf("expected executed command to start with 'sudo ', got: %s", *cmdPtr)
	}
	if !strings.Contains(*cmdPtr, "whoami") {
		t.Errorf("expected executed command to contain 'whoami', got: %s", *cmdPtr)
	}
}

func TestShell_HandleShell_WithSudo_RejectsNoneMode(t *testing.T) {
	sshCli := ssh.NewTestClientWithRaw(nil, ssh.ConnectionConfig{
		NodeID:   "test-node",
		SudoMode: ssh.SudoModeNone,
	})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	s := &Shell{
		sudo:      true,
		sshClient: sshCli,
		stdin:     r,
		stdout:    &stdout,
		stderr:    &stderr,
	}

	err = s.handleShell(t.Context())
	if err == nil {
		t.Fatal("expected error from ShellWithSudoIO with SudoModeNone, got nil")
	}
	if !strings.Contains(err.Error(), "privilege escalation is not supported") {
		t.Errorf("expected error to mention unsupported privilege escalation, got: %v", err)
	}
}

func TestShell_HandleExec_WithSudo_DefaultConfig_Interactive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("interactive PTY execution is unsupported on Windows")
	}
	var executedCmd atomic.Pointer[string]
	rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
		executedCmd.Store(&cmd)
	})
	defer cleanup()

	// Node with default execution config (nil Execution)
	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeSudoer,
	}
	sshCli := ssh.NewTestClientWithRaw(rawClient, connCfg)

	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()

	s := &Shell{
		batch:     false,
		sudo:      true,
		sshClient: sshCli,
		stdin:     slave,
		stdout:    slave,
		stderr:    slave,
	}

	err = s.handleExec(t.Context(), []string{"whoami"})
	if err != nil {
		t.Fatalf("handleExec in interactive mode with default config failed: %v", err)
	}

	cmdPtr := executedCmd.Load()
	if cmdPtr == nil {
		t.Fatal("expected command to be executed on server")
	}
	if !strings.HasPrefix(*cmdPtr, "sudo ") {
		t.Errorf("expected executed command to start with 'sudo ', got: %s", *cmdPtr)
	}
	if !strings.Contains(*cmdPtr, "whoami") {
		t.Errorf("expected executed command to contain 'whoami', got: %s", *cmdPtr)
	}
}

func TestShell_HandleExec_WithSudo_DefaultConfig_Batch(t *testing.T) {
	var executedCmd atomic.Pointer[string]
	rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
		executedCmd.Store(&cmd)
	})
	defer cleanup()

	// Node with default execution config (nil Execution)
	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeSudoer,
	}
	sshCli := ssh.NewTestClientWithRaw(rawClient, connCfg)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	s := &Shell{
		batch:     true,
		sudo:      true,
		sshClient: sshCli,
		stdout:    &stdout,
		stderr:    &stderr,
	}

	err := s.handleExec(t.Context(), []string{"whoami"})
	if err != nil {
		t.Fatalf("handleExec in batch mode with default config failed: %v", err)
	}

	cmdPtr := executedCmd.Load()
	if cmdPtr == nil {
		t.Fatal("expected command to be executed on server")
	}
	if !strings.HasPrefix(*cmdPtr, "sudo ") {
		t.Errorf("expected executed command to start with 'sudo ', got: %s", *cmdPtr)
	}
	if !strings.Contains(*cmdPtr, "whoami") {
		t.Errorf("expected executed command to contain 'whoami', got: %s", *cmdPtr)
	}
}

func TestShell_HandleExec_WithSudo_DefaultConfig_WithCwd_Interactive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("interactive PTY execution is unsupported on Windows")
	}
	var executedCmd atomic.Pointer[string]
	rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
		executedCmd.Store(&cmd)
	})
	defer cleanup()

	// Node with default execution config (nil Execution) and non-empty cwd
	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeSudoer,
	}
	sshCli := ssh.NewTestClientWithRaw(rawClient, connCfg)

	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()

	s := &Shell{
		cwd:       "/var/log",
		batch:     false,
		sudo:      true,
		sshClient: sshCli,
		stdin:     slave,
		stdout:    slave,
		stderr:    slave,
	}

	err = s.handleExec(t.Context(), []string{"whoami"})
	if err != nil {
		t.Fatalf("handleExec in interactive mode with default config and cwd failed: %v", err)
	}

	cmdPtr := executedCmd.Load()
	if cmdPtr == nil {
		t.Fatal("expected command to be executed on server")
	}
	if !strings.HasPrefix(*cmdPtr, "sudo ") {
		t.Errorf("expected executed command to start with 'sudo ', got: %s", *cmdPtr)
	}
	if !strings.Contains(*cmdPtr, "/var/log") {
		t.Errorf("expected executed command to contain '/var/log', got: %s", *cmdPtr)
	}
	if !strings.Contains(*cmdPtr, "whoami") {
		t.Errorf("expected executed command to contain 'whoami', got: %s", *cmdPtr)
	}
}

func TestShell_HandleExec_WithSudo_DefaultConfig_WithCwd_Batch(t *testing.T) {
	var executedCmd atomic.Pointer[string]
	rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
		executedCmd.Store(&cmd)
	})
	defer cleanup()

	// Node with default execution config (nil Execution) and non-empty cwd
	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeSudoer,
	}
	sshCli := ssh.NewTestClientWithRaw(rawClient, connCfg)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	s := &Shell{
		cwd:       "/var/log",
		batch:     true,
		sudo:      true,
		sshClient: sshCli,
		stdout:    &stdout,
		stderr:    &stderr,
	}

	err := s.handleExec(t.Context(), []string{"whoami"})
	if err != nil {
		t.Fatalf("handleExec in batch mode with default config and cwd failed: %v", err)
	}

	cmdPtr := executedCmd.Load()
	if cmdPtr == nil {
		t.Fatal("expected command to be executed on server")
	}
	if !strings.HasPrefix(*cmdPtr, "sudo ") {
		t.Errorf("expected executed command to start with 'sudo ', got: %s", *cmdPtr)
	}
	if !strings.Contains(*cmdPtr, "/var/log") {
		t.Errorf("expected executed command to contain '/var/log', got: %s", *cmdPtr)
	}
	if !strings.Contains(*cmdPtr, "whoami") {
		t.Errorf("expected executed command to contain 'whoami', got: %s", *cmdPtr)
	}
}

func TestShell_HandleExec_WithSudo_Interactive_WithCwd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("interactive PTY execution is unsupported on Windows")
	}
	var executedCmd atomic.Pointer[string]
	rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
		executedCmd.Store(&cmd)
	})
	defer cleanup()

	// Node configured with bash interpreter and SudoModeRoot
	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeRoot,
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterBash,
			LaunchDialect: ssh.LaunchPOSIX,
		},
	}
	sshCli := ssh.NewTestClientWithRaw(rawClient, connCfg)

	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()

	s := &Shell{
		batch:     false,
		sudo:      true,
		cwd:       "/tmp/testdir",
		sshClient: sshCli,
		stdin:     slave,
		stdout:    slave,
		stderr:    slave,
	}

	err = s.handleExec(t.Context(), []string{"ls"})
	if err != nil {
		t.Fatalf("handleExec in interactive mode with cwd failed: %v", err)
	}

	cmdPtr := executedCmd.Load()
	if cmdPtr == nil {
		t.Fatal("expected command to be executed on server")
	}
	if !strings.Contains(*cmdPtr, "/tmp/testdir") {
		t.Errorf("expected executed command to contain '/tmp/testdir', got: %s", *cmdPtr)
	}
	if !strings.Contains(*cmdPtr, "ls") {
		t.Errorf("expected executed command to contain 'ls', got: %s", *cmdPtr)
	}
}

func TestShell_RefreshClient_PreservesSudo_WithOldClient(t *testing.T) {
	var gotSudo bool
	mockFactory := func(ctx context.Context, sshCli *ssh.Client, opts ...sftp.Option) (*sftp.Client, error) {
		cfg := &sftp.Client{}
		for _, opt := range opts {
			opt(cfg)
		}
		gotSudo = cfg.Config().Sudo
		return cfg, nil
	}

	s := &Shell{sudo: true}
	s.transferConfig.Sudo = true

	// oldClient without sudo
	oldCli := &sftp.Client{}
	s.client = oldCli

	sshCli := &ssh.Client{}
	err := s.refreshClient(t.Context(), oldCli, sshCli, mockFactory, oldCli.Config())
	if err != nil {
		t.Fatalf("refreshClient failed: %v", err)
	}
	if !gotSudo {
		t.Errorf("expected factory to receive Sudo: true")
	}
	if !s.transferConfig.Sudo {
		t.Errorf("expected shell.transferConfig.Sudo to remain true")
	}
}

func TestShell_HandleExec_WithSudo_BatchSeparateStdoutStderr(t *testing.T) {
	var executedCmd atomic.Pointer[string]
	rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
		executedCmd.Store(&cmd)
	})
	defer cleanup()

	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeSudoer,
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterBash,
			LaunchDialect: ssh.LaunchPOSIX,
		},
	}
	sshCli := ssh.NewTestClientWithRaw(rawClient, connCfg)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	s := &Shell{
		batch:     true,
		sudo:      true,
		sshClient: sshCli,
		stdout:    &stdout,
		stderr:    &stderr,
	}

	err := s.handleExec(t.Context(), []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("handleExec failed: %v", err)
	}
	if executedCmd.Load() == nil {
		t.Fatal("expected command to execute")
	}
}

func TestShell_HandleExec_WithSudo_WorkingDirPreservesExecutionConfig(t *testing.T) {
	var executedCmd atomic.Pointer[string]
	rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
		executedCmd.Store(&cmd)
	})
	defer cleanup()

	initialExec := &ssh.ExecutionConfig{
		Interpreter:   ssh.InterpreterBash,
		LaunchDialect: ssh.LaunchPOSIX,
	}
	connCfg := ssh.ConnectionConfig{
		SudoMode:  ssh.SudoModeRoot,
		Execution: initialExec,
	}
	sshCli := ssh.NewTestClientWithRaw(rawClient, connCfg)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	s := &Shell{
		batch:     true,
		sudo:      true,
		cwd:       "/var/log",
		sshClient: sshCli,
		stdout:    &stdout,
		stderr:    &stderr,
	}

	err := s.handleExec(t.Context(), []string{"ls"})
	if err != nil {
		t.Fatalf("handleExec failed: %v", err)
	}

	// Execution() on sshCli must still have InterpreterBash, not wiped or mutated
	if s.sshClient.Execution().Interpreter != ssh.InterpreterBash {
		t.Errorf("expected Execution().Interpreter to remain InterpreterBash, got: %s", s.sshClient.Execution().Interpreter)
	}
}

func TestShell_HandleExec_WithSudo_LaunchDialectOnly_WithCwd(t *testing.T) {
	// ExecutionConfig with LaunchPOSIX but empty Interpreter
	cfg := &ssh.ExecutionConfig{
		LaunchDialect: ssh.LaunchPOSIX,
	}

	// Without setting InterpreterBash, FormatWorkingDirCommand fails because EffectiveInterpreter is InterpreterServer
	_, err := ssh.FormatWorkingDirCommand("/var/log", "whoami", cfg)
	if err == nil || !strings.Contains(err.Error(), "server interpreter does not support inheriting working directory") {
		t.Fatalf("expected server interpreter error without bash fallback, got: %v", err)
	}

	// In handleExec, formatCfg is cloned and Interpreter is set to InterpreterBash when s.sudo is true
	formatCfg := cfg.Clone()
	formatCfg.Interpreter = ssh.InterpreterBash
	formatted, err := ssh.FormatWorkingDirCommand("/var/log", "whoami", formatCfg)
	if err != nil {
		t.Fatalf("FormatWorkingDirCommand failed with cloned bash config: %v", err)
	}
	if !strings.Contains(formatted, "cd -- '/var/log'") {
		t.Errorf("expected cd -- '/var/log' in formatted command, got: %s", formatted)
	}
	if !strings.Contains(formatted, "whoami") {
		t.Errorf("expected whoami in formatted command, got: %s", formatted)
	}

	// End-to-end execution with LaunchDialect only and cwd
	var executedCmd atomic.Pointer[string]
	rawClient, cleanup := startMockSSHExecServer(t, func(cmd string) {
		executedCmd.Store(&cmd)
	})
	defer cleanup()

	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeRoot,
		Execution: &ssh.ExecutionConfig{
			LaunchDialect: ssh.LaunchPOSIX,
		},
	}
	sshCli := ssh.NewTestClientWithRaw(rawClient, connCfg)

	t.Run("Interactive", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("interactive PTY execution is unsupported on Windows")
		}
		master, slave, err := pty.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = master.Close(); _ = slave.Close() }()

		s := &Shell{
			batch:     false,
			sudo:      true,
			cwd:       "/var/log",
			sshClient: sshCli,
			stdin:     slave,
			stdout:    slave,
			stderr:    slave,
		}

		err = s.handleExec(t.Context(), []string{"whoami"})
		if err != nil {
			t.Fatalf("handleExec in interactive mode with launch_dialect only failed: %v", err)
		}
		cmdPtr := executedCmd.Load()
		if cmdPtr == nil {
			t.Fatal("expected command to be executed on server")
		}
		if !strings.Contains(*cmdPtr, "/var/log") {
			t.Errorf("expected executed command to contain '/var/log', got: %s", *cmdPtr)
		}
		if !strings.Contains(*cmdPtr, "whoami") {
			t.Errorf("expected whoami in formatted command, got: %s", *cmdPtr)
		}
	})

	t.Run("Batch", func(t *testing.T) {
		executedCmd.Store(nil)
		sBatch := &Shell{
			batch:     true,
			sudo:      true,
			cwd:       "/var/log",
			sshClient: sshCli,
			stdout:    &bytes.Buffer{},
			stderr:    &bytes.Buffer{},
		}
		if err := sBatch.handleExec(t.Context(), []string{"whoami"}); err != nil {
			t.Fatalf("handleExec in batch mode with launch_dialect only failed: %v", err)
		}
		if cmdPtr := executedCmd.Load(); cmdPtr == nil || !strings.Contains(*cmdPtr, "/var/log") {
			t.Fatalf("expected batch command with '/var/log', got: %v", cmdPtr)
		}
	})
}

func TestShell_HandleExec_WithSudo_ExplicitServerInterpreter_Rejected(t *testing.T) {
	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeSudoer,
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterServer,
			LaunchDialect: ssh.LaunchPOSIX,
		},
	}
	sshCli := ssh.NewTestClient(connCfg)

	t.Run("Interactive", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("interactive PTY execution is unsupported on Windows")
		}
		master, slave, err := pty.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = master.Close(); _ = slave.Close() }()

		// Interactive mode with explicit InterpreterServer must fail validation
		sInteractive := &Shell{
			batch:     false,
			sudo:      true,
			sshClient: sshCli,
			stdin:     slave,
			stdout:    slave,
			stderr:    slave,
		}
		if err := sInteractive.handleExec(t.Context(), []string{"whoami"}); err == nil {
			t.Fatal("expected error for explicit server interpreter with sudo in interactive mode, got nil")
		}
	})

	t.Run("Batch", func(t *testing.T) {
		// Batch mode with explicit InterpreterServer must also fail validation
		sBatch := &Shell{
			batch:     true,
			sudo:      true,
			sshClient: sshCli,
			stdout:    &bytes.Buffer{},
			stderr:    &bytes.Buffer{},
		}
		if err := sBatch.handleExec(t.Context(), []string{"whoami"}); err == nil {
			t.Fatal("expected error for explicit server interpreter with sudo in batch mode, got nil")
		}
	})
}

func TestShell_HandleExec_WithSudoSu_UnconfiguredExecution_AvoidsConfiguredSuRejection(t *testing.T) {
	connCfg := ssh.ConnectionConfig{
		SudoMode: ssh.SudoModeSu,
	}
	client := ssh.NewTestClient(connCfg)

	// Simulated probe result (e.g. bash detected on remote host)
	probedBashCfg := &ssh.ExecutionConfig{
		Interpreter:   ssh.InterpreterBash,
		LaunchDialect: ssh.LaunchPOSIX,
	}

	// When probedBashCfg was passed directly into RunInteractiveWithSudoExecutionIO
	// (the bug before this fix), it triggered configuredSudoOptions which rejected configured su:
	errWithProbed := client.RunInteractiveWithSudoExecutionIO(t.Context(), "whoami", probedBashCfg, ssh.InteractiveIO{})
	if errWithProbed == nil || !strings.Contains(errWithProbed.Error(), "configured su execution is not supported") {
		t.Fatalf("expected 'configured su execution is not supported' when probed config is passed, got: %v", errWithProbed)
	}

	// When client.Execution() is passed (the fix: nil when unconfigured),
	// it delegates to RunInteractiveWithSudoIO and does NOT fail with "configured su execution is not supported":
	if client.Execution() != nil {
		t.Fatal("expected unconfigured client.Execution() to be nil")
	}
	errWithNil := client.RunInteractiveWithSudoExecutionIO(t.Context(), "whoami", client.Execution(), ssh.InteractiveIO{})
	if errWithNil != nil && strings.Contains(errWithNil.Error(), "configured su execution is not supported") {
		t.Fatalf("did not expect 'configured su execution is not supported' when client.Execution() is nil, got: %v", errWithNil)
	}
}
