package playbook_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/playbook"
)

type fixtureSecrets struct{}

func (fixtureSecrets) ResolveSecret(ctx context.Context, _ ssh.SecretRequest) ([]byte, error) {
	return []byte(sshfixture.Password), ctx.Err()
}

type fixtureTrust struct{ key cryptoSSH.PublicKey }

func (t fixtureTrust) Verify(ctx context.Context, _ ssh.HostKeyRequest, key cryptoSSH.PublicKey) error {
	if !bytes.Equal(t.key.Marshal(), key.Marshal()) {
		return errors.New("fixture host key changed")
	}
	return ctx.Err()
}

func setupFixtureProvider(t *testing.T, server *sshfixture.Server, exec *ssh.ExecutionConfig) (config.ConfigProvider, *ssh.Connector) {
	t.Helper()
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Execution:  exec,
	}

	cfg.Hosts.Set("fixture-host", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("fixture-id", models.Identity{User: "test", AuthType: "password"})
	cfg.Nodes.Set("node-1", models.Node{
		HostRef:     "fixture-host",
		IdentityRef: "fixture-id",
		Execution:   exec,
		SudoMode:    models.SudoModeRoot,
	})
	cfg.Nodes.Set("node-2", models.Node{
		HostRef:     "fixture-host",
		IdentityRef: "fixture-id",
		Execution:   exec,
		SudoMode:    models.SudoModeRoot,
	})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	connector := adapter.NewConnector(provider,
		ssh.WithSecretResolver(fixtureSecrets{}),
		ssh.WithHostKeyVerifier(fixtureTrust{server.HostKey}),
	)
	return provider, connector
}

func findEnsureMarker(cmd string) string {
	const prefix = "__XOPS_ENSURE_"
	idx := strings.Index(cmd, prefix)
	if idx < 0 {
		return ""
	}
	rest := cmd[idx:]
	end := strings.Index(rest[len(prefix):], "__")
	if end < 0 {
		return ""
	}
	return rest[:len(prefix)+end+2]
}

// TestPlaybook_ScriptSourceBytesFrozen verifies that all targets execute the exact
// frozen bytes read during preloading, even if the file on disk is modified or deleted afterwards.
func TestPlaybook_ScriptSourceBytesFrozen(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(command string, channel cryptoSSH.Channel) {
			data, _ := io.ReadAll(channel)
			_, _ = channel.Write(data)
			_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	exec := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
	provider, connector := setupFixtureProvider(t, server, exec)

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "test.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho original-version\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	pb := &playbook.Playbook{
		Name:    "frozen-script-test",
		Targets: playbook.Targets{Nodes: []string{"node-1", "node-2"}},
		Steps: []playbook.Step{
			{Name: "run-frozen-script", Script: scriptPath},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)

	// Tamper with file before running - Run should preload once at start
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho TAMPERED\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Engine.Run preloads the script cache:
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}

	// Now modify the file again after start:
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\necho SECOND_TAMPER\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Verify both nodes ran the preloaded version (which was TAMPERED at preloading time, but NOT SECOND_TAMPER)
	for _, hr := range report.Hosts {
		if hr.Status != playbook.HostStatusSuccess {
			t.Fatalf("host %s failed: %+v", hr.NodeID, hr)
		}
		if len(hr.Steps) != 1 {
			t.Fatalf("expected 1 step, got %d", len(hr.Steps))
		}
		if !bytes.Contains([]byte(hr.Steps[0].Output), []byte("TAMPERED")) {
			t.Errorf("host %s output %q does not contain TAMPERED", hr.NodeID, hr.Steps[0].Output)
		}
		if bytes.Contains([]byte(hr.Steps[0].Output), []byte("SECOND_TAMPER")) {
			t.Errorf("host %s output %q contained SECOND_TAMPER", hr.NodeID, hr.Steps[0].Output)
		}
	}
}

// TestPlaybook_NonRetryableBoundaries verifies that unknown outcomes and cleanup/IO errors
// are strictly NOT retried even when step.Retries > 0.
func TestPlaybook_NonRetryableBoundaries(t *testing.T) {
	t.Run("ExecutionUnknown outcome is not retried", testRetryExecutionUnknown)
	t.Run("Protocol IOErr is not retried", testRetryProtocolIOErr)
	t.Run("Cleanup error is not retried", testRetryCleanupErr)
	t.Run("Confirmed completed failure is retried", testRetryConfirmedCompletedFailure)
}

func testRetryExecutionUnknown(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var attempts atomic.Int32
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			attempts.Add(1)
			_ = ch.Close()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)
	pb := &playbook.Playbook{
		Name:    "retry-unknown-test",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name:       "unknown-step",
				Shell:      "echo test",
				Retries:    3,
				RetryDelay: playbook.Duration{Duration: 10 * time.Millisecond},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}
	if n := attempts.Load(); n != 1 {
		t.Fatalf("attempts = %d, want 1 (must not retry unknown outcome)", n)
	}
	if len(report.Hosts) != 1 || len(report.Hosts[0].Steps) != 1 {
		t.Fatalf("unexpected report hosts: %+v", report.Hosts)
	}
	res := report.Hosts[0].Steps[0]
	if res.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want failed", res.Status)
	}
	if res.Outcome != ssh.ExecutionUnknown {
		t.Fatalf("outcome = %v, want ExecutionUnknown", res.Outcome)
	}
}

func testRetryProtocolIOErr(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var attempts atomic.Int32
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			attempts.Add(1)
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			_ = ch.Close()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)
	pb := &playbook.Playbook{
		Name:    "retry-ioerr-test",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name:       "ioerr-step",
				Shell:      "echo test",
				Retries:    3,
				RetryDelay: playbook.Duration{Duration: 10 * time.Millisecond},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}
	if n := attempts.Load(); n != 1 {
		t.Fatalf("attempts = %d, want 1 (must not retry IOErr)", n)
	}
	if len(report.Hosts) != 1 || len(report.Hosts[0].Steps) != 1 {
		t.Fatalf("unexpected report hosts: %+v", report.Hosts)
	}
	res := report.Hosts[0].Steps[0]
	if res.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want failed", res.Status)
	}
	if res.IOErr == nil {
		t.Fatalf("expected IOErr, got nil")
	}
}

func testRetryCleanupErr(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)
	pb := &playbook.Playbook{
		Name:    "retry-cleanup-test",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name:       "cleanup-err-step",
				Shell:      "fake",
				Retries:    3,
				RetryDelay: playbook.Duration{Duration: 10 * time.Millisecond},
			},
		},
	}

	code := uint32(1)
	var attempts atomic.Int32
	engine := playbook.NewEngine(pb, provider, connector)
	engine.SetDispatchStepFnForTest(func(ctx context.Context, client *ssh.Client, step playbook.Step, useSudo bool, node models.Node) playbook.StepResult {
		attempts.Add(1)
		return playbook.StepResult{
			StepName:   step.Name,
			Status:     playbook.StatusFailed,
			Outcome:    ssh.ExecutionCompleted,
			ExitCode:   &code,
			CleanupErr: errors.New("channel close timeout"),
			Retryable:  false,
		}
	})

	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}
	if n := attempts.Load(); n != 1 {
		t.Fatalf("attempts = %d, want 1 (must not retry when cleanup error is present)", n)
	}
	if len(report.Hosts) != 1 || len(report.Hosts[0].Steps) != 1 {
		t.Fatalf("unexpected report hosts: %+v", report.Hosts)
	}
	res := report.Hosts[0].Steps[0]
	if res.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want failed", res.Status)
	}
}

func testRetryConfirmedCompletedFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var attempts atomic.Int32
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			attempts.Add(1)
			_, _ = ch.Write([]byte("failed command\n"))
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			_ = ch.Close()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)
	pb := &playbook.Playbook{
		Name:    "retry-confirmed-failure-test",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name:       "confirmed-fail-step",
				Shell:      "exit 1",
				Retries:    2,
				RetryDelay: playbook.Duration{Duration: 5 * time.Millisecond},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}
	if n := attempts.Load(); n != 3 {
		t.Fatalf("attempts = %d, want 3 (1 initial + 2 retries)", n)
	}
	if len(report.Hosts) != 1 || len(report.Hosts[0].Steps) != 1 {
		t.Fatalf("unexpected report hosts: %+v", report.Hosts)
	}
	res := report.Hosts[0].Steps[0]
	if res.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want failed", res.Status)
	}
	if res.ExitCode == nil || *res.ExitCode != 1 {
		t.Fatalf("exit code = %v, want 1", res.ExitCode)
	}
}

var execBashFixture = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}

func TestPlaybook_EnsureProtocol_Check0Skipped(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				_, _ = ch.Write([]byte("\n" + marker + ":0\n"))
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
				return
			}
			t.Fatal("action should not be called when check is 0")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	pb := &playbook.Playbook{
		Name:    "ensure-skipped",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-check-0",
				Ensure: &playbook.EnsureSpec{
					Check:  "test 1 -eq 1",
					Action: "touch /tmp/must_not_exist_action_1",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(report.Hosts) != 1 || len(report.Hosts[0].Steps) != 1 {
		t.Fatalf("unexpected host steps: %+v", report.Hosts)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusSkipped {
		t.Fatalf("status = %s, err = %v, out = %q, want StatusSkipped", stepRes.Status, stepRes.Err, stepRes.Output)
	}
}

func TestPlaybook_EnsureProtocol_Check127Failed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				_, _ = ch.Write([]byte("not found\n" + marker + ":127\n"))
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{127}))
				return
			}
			t.Fatal("action must not be executed on check 127")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	pb := &playbook.Playbook{
		Name:    "ensure-127",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-check-127",
				Ensure: &playbook.EnsureSpec{
					Check:  "/nonexistent_executable_binary_12345",
					Action: "touch /tmp/must_not_exist_action_2",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed", stepRes.Status)
	}
	if stepRes.Err == nil || !strings.Contains(stepRes.Err.Error(), "127") {
		t.Fatalf("expected error mentioning 127, got: %v", stepRes.Err)
	}
}

func TestPlaybook_EnsureProtocol_EarlyStartupExitMissingFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				_, _ = ch.Write([]byte("fatal error in profile\n"))
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
				return
			}
			t.Fatal("action must not be executed when check result frame is missing")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	pb := &playbook.Playbook{
		Name:    "ensure-missing-frame",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-check-missing-frame",
				Ensure: &playbook.EnsureSpec{
					Check:  "test -f /somefile",
					Action: "touch /tmp/must_not_exist_action_3",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed", stepRes.Status)
	}
	if stepRes.Err == nil || !strings.Contains(stepRes.Err.Error(), "result frame missing") {
		t.Fatalf("expected result frame missing error, got: %v", stepRes.Err)
	}
}

func TestPlaybook_EnsureProtocol_ServerInterpreterRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	execServer := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}
	providerServer, connectorServer := setupFixtureProvider(t, server, execServer)

	pb := &playbook.Playbook{
		Name:    "ensure-server-rejected",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-server",
				Ensure: &playbook.EnsureSpec{
					Check:  "test -f /somefile",
					Action: "touch /somefile",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, providerServer, connectorServer)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed", stepRes.Status)
	}
	if stepRes.Err == nil || !strings.Contains(stepRes.Err.Error(), "server interpreter") {
		t.Fatalf("expected server interpreter error, got: %v", stepRes.Err)
	}
}

func TestPlaybook_EnsureProtocol_RemediateSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	checkCount := 0
	actionRan := false

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				checkCount++
				if checkCount == 1 {
					// 1st check: not satisfied
					_, _ = ch.Write([]byte("\n" + marker + ":1\n"))
					_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
					return
				}
				// 2nd check (verify): satisfied
				_, _ = ch.Write([]byte("\n" + marker + ":0\n"))
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
				return
			}
			// Action
			actionRan = true
			_, _ = ch.Write([]byte("action executed ok\n"))
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	pb := &playbook.Playbook{
		Name:    "ensure-remediate-success",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-remediate",
				Ensure: &playbook.EnsureSpec{
					Check:  "test -f /tmp/app.lock",
					Action: "touch /tmp/app.lock",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !actionRan {
		t.Fatal("expected action to have run")
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusChanged {
		t.Fatalf("status = %s, want StatusChanged; err = %v", stepRes.Status, stepRes.Err)
	}
}

func TestPlaybook_EnsureProtocol_RemediateVerifyFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	checkCount := 0

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				checkCount++
				// Both check 1 and verify check return exit 1
				_, _ = ch.Write([]byte("\n" + marker + ":1\n"))
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
				return
			}
			// Action succeeds
			_, _ = ch.Write([]byte("action ran\n"))
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	pb := &playbook.Playbook{
		Name:    "ensure-remediate-verify-fail",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-verify-fail",
				Ensure: &playbook.EnsureSpec{
					Check:  "test -f /tmp/app.lock",
					Action: "touch /tmp/app.lock",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed", stepRes.Status)
	}
	if stepRes.Err == nil || !strings.Contains(stepRes.Err.Error(), "still not satisfied") {
		t.Fatalf("expected verify failure error, got: %v", stepRes.Err)
	}
}

func TestPlaybook_SudoSignalTerminationPreserved(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			_, _ = io.WriteString(ch, "signal-out\n")
			msg := struct {
				Signal     string
				CoreDumped bool
				ErrorMsg   string
				Lang       string
			}{
				Signal: "TERM",
			}
			_, _ = ch.SendRequest("exit-signal", false, cryptoSSH.Marshal(msg))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	execBashFixture := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	sudoTrue := true
	pb := &playbook.Playbook{
		Name:    "sudo-signal-test",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name:  "sudo-kill",
				Shell: "kill-me",
				Sudo:  &sudoTrue,
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed", stepRes.Status)
	}
	if stepRes.Signal != "TERM" {
		t.Fatalf("stepRes.Signal = %q, want %q", stepRes.Signal, "TERM")
	}
	if stepRes.ExitCode != nil {
		t.Fatalf("stepRes.ExitCode = %v, want nil", *stepRes.ExitCode)
	}
	if stepRes.Outcome != ssh.ExecutionCompleted {
		t.Fatalf("stepRes.Outcome = %v, want %v", stepRes.Outcome, ssh.ExecutionCompleted)
	}
}

func TestPlaybook_EnsureProtocol_SignalTerminationRejectedPlanned(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				// Bash EXIT trap writes frame :0 even when killed by SIGTERM
				_, _ = ch.Write([]byte("\n" + marker + ":0\n"))
				msg := struct {
					Signal     string
					CoreDumped bool
					ErrorMsg   string
					Lang       string
				}{
					Signal: "TERM",
				}
				_, _ = ch.SendRequest("exit-signal", false, cryptoSSH.Marshal(msg))
				_ = ch.Close()
				return
			}
			t.Fatal("action must not be executed when check terminated by signal")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	pb := &playbook.Playbook{
		Name:    "ensure-signal-planned",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-signal-planned-step",
				Ensure: &playbook.EnsureSpec{
					Check:  "kill -TERM $$",
					Action: "touch /tmp/must_not_exist_action_sig_planned",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed (must reject signal termination despite frame :0)", stepRes.Status)
	}
	if stepRes.Signal != "TERM" {
		t.Fatalf("signal = %q, want TERM", stepRes.Signal)
	}
	if stepRes.ExitCode != nil {
		t.Fatalf("exit code = %v, want nil", *stepRes.ExitCode)
	}
	if stepRes.Err == nil || !strings.Contains(stepRes.Err.Error(), "TERM") {
		t.Fatalf("expected error mentioning signal TERM, got: %v", stepRes.Err)
	}
}

func TestPlaybook_EnsureProtocol_SignalTerminationRejectedSudo(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				_, _ = ch.Write([]byte("\n" + marker + ":0\n"))
				msg := struct {
					Signal     string
					CoreDumped bool
					ErrorMsg   string
					Lang       string
				}{
					Signal: "TERM",
				}
				_, _ = ch.SendRequest("exit-signal", false, cryptoSSH.Marshal(msg))
				_ = ch.Close()
				return
			}
			t.Fatal("action must not be executed when sudo check terminated by signal")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)
	sudoTrue := true

	pb := &playbook.Playbook{
		Name:    "ensure-signal-sudo",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-signal-sudo-step",
				Sudo: &sudoTrue,
				Ensure: &playbook.EnsureSpec{
					Check:  "kill -TERM $$",
					Action: "touch /tmp/must_not_exist_action_sig_sudo",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed (must reject sudo signal termination)", stepRes.Status)
	}
	if stepRes.Signal != "TERM" {
		t.Fatalf("signal = %q, want TERM", stepRes.Signal)
	}
	if stepRes.ExitCode != nil {
		t.Fatalf("exit code = %v, want nil", *stepRes.ExitCode)
	}
	if stepRes.Err == nil || !strings.Contains(stepRes.Err.Error(), "TERM") {
		t.Fatalf("expected error mentioning signal TERM, got: %v", stepRes.Err)
	}
}

func TestPlaybook_EnsureProtocol_SignalTerminationRejectedLegacy(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				_, _ = ch.Write([]byte("\n" + marker + ":0\n"))
				msg := struct {
					Signal     string
					CoreDumped bool
					ErrorMsg   string
					Lang       string
				}{
					Signal: "TERM",
				}
				_, _ = ch.SendRequest("exit-signal", false, cryptoSSH.Marshal(msg))
				_ = ch.Close()
				return
			}
			t.Fatal("action must not be executed when legacy check terminated by signal")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	// Legacy mode: ExecutionConfig is nil
	provider, connector := setupFixtureProvider(t, server, nil)

	pb := &playbook.Playbook{
		Name:    "ensure-signal-legacy",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-signal-legacy-step",
				Ensure: &playbook.EnsureSpec{
					Check:  "kill -TERM $$",
					Action: "touch /tmp/must_not_exist_action_sig_legacy",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed (must reject legacy signal termination)", stepRes.Status)
	}
	if stepRes.Signal != "TERM" {
		t.Fatalf("signal = %q, want TERM", stepRes.Signal)
	}
	if stepRes.ExitCode != nil {
		t.Fatalf("exit code = %v, want nil", *stepRes.ExitCode)
	}
	if stepRes.Err == nil || !strings.Contains(stepRes.Err.Error(), "TERM") {
		t.Fatalf("expected error mentioning signal TERM, got: %v", stepRes.Err)
	}
}

func TestPlaybook_EnsureProtocol_SignalTerminationRejectedVerifyCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	checkCount := 0
	actionRan := false

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				checkCount++
				if checkCount == 1 {
					// 1st check: needs action
					_, _ = ch.Write([]byte("\n" + marker + ":1\n"))
					_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
					_ = ch.Close()
					return
				}
				// 2nd check (verify check): terminates by signal TERM despite frame :0
				_, _ = ch.Write([]byte("\n" + marker + ":0\n"))
				msg := struct {
					Signal     string
					CoreDumped bool
					ErrorMsg   string
					Lang       string
				}{
					Signal: "TERM",
				}
				_, _ = ch.SendRequest("exit-signal", false, cryptoSSH.Marshal(msg))
				_ = ch.Close()
				return
			}
			// Action succeeds
			actionRan = true
			_, _ = ch.Write([]byte("action ran\n"))
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			_ = ch.Close()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	pb := &playbook.Playbook{
		Name:    "ensure-signal-verify",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-signal-verify-step",
				Ensure: &playbook.EnsureSpec{
					Check:  "test -f /tmp/app.lock",
					Action: "touch /tmp/app.lock",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(t.Context())
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !actionRan {
		t.Fatal("action should have run before verify check")
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed (must reject signal termination in verify check)", stepRes.Status)
	}
	if stepRes.Signal != "TERM" {
		t.Fatalf("signal = %q, want TERM", stepRes.Signal)
	}
	if stepRes.ExitCode != nil {
		t.Fatalf("exit code = %v, want nil", *stepRes.ExitCode)
	}
	if stepRes.Err == nil || !strings.Contains(stepRes.Err.Error(), "TERM") {
		t.Fatalf("expected error mentioning signal TERM, got: %v", stepRes.Err)
	}
}

func TestPlaybook_EnsureProtocol_ExecutionTimeoutRejectedPlanned_Check0(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				// Bash emits frame :0 and exit status 0, but leaves channel open until timeout
				_, _ = ch.Write([]byte("\n" + marker + ":0\n"))
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
				time.Sleep(300 * time.Millisecond)
				_ = ch.Close()
				return
			}
			t.Fatal("action must not be executed")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	execBashFixture := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	pb := &playbook.Playbook{
		Name:    "ensure-timeout-planned-check0",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-timeout-check0",
				Ensure: &playbook.EnsureSpec{
					Check:  "echo ok",
					Action: "touch /tmp/must_not_exist_action_timeout",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	runCtx, runCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer runCancel()

	report, err := engine.Run(runCtx)
	if err == nil {
		t.Fatal("expected playbook execution canceled error on runCtx expiry")
	}
	if report == nil || len(report.Hosts) == 0 || len(report.Hosts[0].Steps) == 0 {
		t.Fatalf("expected host step report, got: %+v", report)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed (must reject timeout even when frame :0 received)", stepRes.Status)
	}
	if stepRes.Outcome != ssh.ExecutionUnknown {
		t.Fatalf("outcome = %v, want ExecutionUnknown", stepRes.Outcome)
	}
	if stepRes.Err == nil || (!strings.Contains(stepRes.Err.Error(), "timed out") && !strings.Contains(stepRes.Err.Error(), "deadline exceeded")) {
		t.Fatalf("expected timeout error, got: %v", stepRes.Err)
	}
}

func TestPlaybook_EnsureProtocol_ExecutionTimeoutRejectedPlanned_Check1(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	actionRan := false
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			marker := findEnsureMarker(cmd)
			if marker != "" {
				// Bash emits frame :1 and exit status 1, but leaves channel open until timeout
				_, _ = ch.Write([]byte("\n" + marker + ":1\n"))
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
				time.Sleep(300 * time.Millisecond)
				_ = ch.Close()
				return
			}
			actionRan = true
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			_ = ch.Close()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	execBashFixture := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
	provider, connector := setupFixtureProvider(t, server, execBashFixture)

	pb := &playbook.Playbook{
		Name:    "ensure-timeout-planned-check1",
		Targets: playbook.Targets{Nodes: []string{"node-1"}},
		Steps: []playbook.Step{
			{
				Name: "ensure-timeout-check1",
				Ensure: &playbook.EnsureSpec{
					Check:  "test -f /nonexistent",
					Action: "touch /tmp/must_not_run_action_timeout",
				},
			},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	runCtx, runCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer runCancel()

	report, err := engine.Run(runCtx)
	if err == nil {
		t.Fatal("expected playbook execution canceled error on runCtx expiry")
	}
	if actionRan {
		t.Fatal("action must not run when check timed out")
	}
	if report == nil || len(report.Hosts) == 0 || len(report.Hosts[0].Steps) == 0 {
		t.Fatalf("expected host step report, got: %+v", report)
	}
	stepRes := report.Hosts[0].Steps[0]
	if stepRes.Status != playbook.StatusFailed {
		t.Fatalf("status = %s, want StatusFailed (must reject timeout even when frame :1 received)", stepRes.Status)
	}
	if stepRes.Outcome != ssh.ExecutionUnknown {
		t.Fatalf("outcome = %v, want ExecutionUnknown", stepRes.Outcome)
	}
	if stepRes.Err == nil || (!strings.Contains(stepRes.Err.Error(), "timed out") && !strings.Contains(stepRes.Err.Error(), "deadline exceeded")) {
		t.Fatalf("expected timeout error, got: %v", stepRes.Err)
	}
}
