package playbook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
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

type executionTestProvider struct{ cfg ssh.ClientConfig }

func (p executionTestProvider) GetConfig(string) (*ssh.ClientConfig, error) {
	cfg := p.cfg
	return &cfg, nil
}

type executionTestTrust struct{ key cryptoSSH.PublicKey }

func (v executionTestTrust) Verify(ctx context.Context, _ ssh.HostKeyRequest, key cryptoSSH.PublicKey) error {
	if !bytes.Equal(v.key.Marshal(), key.Marshal()) {
		return fmt.Errorf("fixture host key changed")
	}
	return ctx.Err()
}

func executionTestClient(t *testing.T, handler func(string, cryptoSSH.Channel)) (*ssh.Client, *sshfixture.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{ExecHandler: handler})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	connector := ssh.NewConnector(executionTestProvider{ssh.ClientConfig{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", Password: sshfixture.Password, SudoMode: ssh.SudoModeRoot}}, ssh.WithHostKeyVerifier(executionTestTrust{server.HostKey}))
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Error(err)
		}
	})
	client, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestPlaybookSudoShellAndEnsureHonorLoginFalse(t *testing.T) {
	no := false
	cfg := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}
	for _, ensure := range []bool{false, true} {
		t.Run(map[bool]string{false: "shell", true: "ensure check action verify"}[ensure], func(t *testing.T) {
			commands := make(chan string, 4)
			var checks atomic.Int32
			marker := regexp.MustCompile(`__XOPS_ENSURE_[a-f0-9]+__`)
			client, server := executionTestClient(t, func(command string, ch cryptoSSH.Channel) {
				commands <- command
				if _, err := io.Copy(io.Discard, ch); err != nil {
					t.Error(err)
					return
				}
				status := uint32(0)
				if frame := marker.FindString(command); frame != "" {
					if checks.Add(1) == 1 {
						status = 1
					}
					if _, err := fmt.Fprintf(ch, "\n%s:%d\n", frame, status); err != nil {
						t.Error(err)
						return
					}
				}
				if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{status})); err != nil {
					t.Error(err)
				}
			})
			e := &Engine{}
			var result StepResult
			want := int32(1)
			if ensure {
				result = e.runEnsure(t.Context(), client, &EnsureSpec{Check: "check", Action: "action"}, cfg, true, models.Node{})
				want = 3
			} else {
				result = e.runShell(t.Context(), client, "action", cfg, true, models.Node{})
			}
			if result.Status != StatusChanged || result.Err != nil || server.Executed.Load() != want {
				t.Fatalf("configured sudo failed: %+v commands=%d", result, server.Executed.Load())
			}
			for range want {
				if got := <-commands; !strings.HasPrefix(got, "bash -c ") || strings.Contains(got, "bash -l -c") {
					t.Fatalf("login option lost: %q", got)
				}
			}
		})
	}
}

func TestPlaybookShebangRejectsIncompatibleNodeDialectBeforeScript(t *testing.T) {
	for _, dialect := range []ssh.LaunchDialect{ssh.LaunchCmd, ssh.LaunchPowerShell, ssh.LaunchUnknown} {
		t.Run(string(dialect), func(t *testing.T) {
			client, server := executionTestClient(t, nil)
			e := &Engine{scriptSources: map[string][]byte{"script": []byte("#!/bin/bash\necho script")}}
			result := e.runScript(t.Context(), client, "script", nil, false, models.Node{Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: dialect}})
			if !errors.Is(result.Err, ssh.ErrExecutionValidation) || result.Outcome != ssh.ExecutionNotStarted || server.Executed.Load() != 0 {
				t.Fatalf("script dispatched with incompatible dialect: %+v", result)
			}
		})
	}
}

func testClassifyJoinedErrors(t *testing.T) {
	t.Helper()
	dummyExit := &cryptoSSH.ExitError{}
	cleanupErr := errors.New("close session: transport broken")
	ioErr := errors.New("output copy failed: broken pipe")

	// 1. ExitError joined with cleanup error -> CleanupErr populated, not retryable
	resCleanup := classifySessionResult(errors.Join(dummyExit, cleanupErr), "out")
	if resCleanup.CleanupErr == nil || !strings.Contains(resCleanup.CleanupErr.Error(), "close session") {
		t.Fatalf("expected CleanupErr populated, got: %v", resCleanup.CleanupErr)
	}
	if resCleanup.Retryable {
		t.Fatal("expected Retryable to be false when cleanup error is present")
	}

	// 2. ExitError joined with I/O error -> IOErr populated, not retryable
	resIO := classifySessionResult(errors.Join(dummyExit, ioErr), "out")
	if resIO.IOErr == nil || !strings.Contains(resIO.IOErr.Error(), "output copy failed") {
		t.Fatalf("expected IOErr populated, got: %v", resIO.IOErr)
	}
	if resIO.Retryable {
		t.Fatal("expected Retryable to be false when IO error is present")
	}

	// 3. ExitError joined with context.Canceled -> ExecutionUnknown, not retryable
	resCancel := classifySessionResult(errors.Join(dummyExit, context.Canceled), "out")
	if resCancel.Outcome != ssh.ExecutionUnknown {
		t.Fatalf("expected Outcome ExecutionUnknown, got: %v", resCancel.Outcome)
	}
	if resCancel.Retryable {
		t.Fatal("expected Retryable to be false when canceled")
	}

	// 4. Wrapped error containing joined ExitError + cleanupErr
	wrappedJoined := fmt.Errorf("failed to run command: %w, output: %s", errors.Join(dummyExit, cleanupErr), "out")
	resWrapped := classifySessionResult(wrappedJoined, "out")
	if resWrapped.CleanupErr == nil {
		t.Fatal("expected CleanupErr populated from wrapped joined error")
	}
	if resWrapped.Retryable {
		t.Fatal("expected Retryable to be false for wrapped joined cleanup error")
	}

	// 5. extractExecutionLayerError: confirmed nonzero CommandExitError is allowed
	one := uint32(1)
	cmdExitErr := &ssh.CommandExitError{ExitCode: &one}
	if err := extractExecutionLayerError(cmdExitErr); err != nil {
		t.Fatalf("expected nil for confirmed CommandExitError, got: %v", err)
	}

	// 6. extractExecutionLayerError: deadline error joined with CommandExitError is rejected
	deadlineErr := fmt.Errorf("wait for SSH command: %w", context.DeadlineExceeded)
	joinedDeadline := errors.Join(cmdExitErr, deadlineErr)
	extracted := extractExecutionLayerError(joinedDeadline)
	if extracted == nil || !errors.Is(extracted, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded error extracted, got: %v", extracted)
	}

	// 7. extractExecutionLayerError: cancellation error is rejected
	cancelErr := fmt.Errorf("wait for SSH command: %w", context.Canceled)
	extractedCancel := extractExecutionLayerError(errors.Join(cmdExitErr, cancelErr))
	if extractedCancel == nil || !errors.Is(extractedCancel, context.Canceled) {
		t.Fatalf("expected canceled error extracted, got: %v", extractedCancel)
	}
}

func testRunStepRetrySafeguards(t *testing.T) {
	t.Helper()
	one := uint32(1)

	// Case A: dispatch returns nonzero exit with CleanupErr -> do NOT retry
	var attemptsA atomic.Int32
	engineA := &Engine{}
	engineA.SetDispatchStepFnForTest(func(context.Context, *ssh.Client, Step, bool, models.Node) StepResult {
		attemptsA.Add(1)
		return StepResult{
			Status:     StatusFailed,
			Outcome:    ssh.ExecutionCompleted,
			ExitCode:   &one,
			CleanupErr: errors.New("close session failed"),
			Retryable:  false,
		}
	})

	step := Step{
		Name:       "test-step",
		Retries:    2,
		RetryDelay: Duration{Duration: 5 * time.Millisecond},
	}
	resA := engineA.runStep(t.Context(), nil, step, false, models.Node{})
	if resA.Status != StatusFailed {
		t.Fatalf("expected StatusFailed, got: %s", resA.Status)
	}
	if attemptsA.Load() != 1 {
		t.Fatalf("expected exactly 1 attempt (no retry) when CleanupErr present, got: %d", attemptsA.Load())
	}
	if resA.CleanupErr == nil {
		t.Fatal("expected CleanupErr to be preserved in StepResult")
	}

	// Case B: dispatch returns clean nonzero exit -> RETRY
	var attemptsB atomic.Int32
	engineB := &Engine{}
	engineB.SetDispatchStepFnForTest(func(context.Context, *ssh.Client, Step, bool, models.Node) StepResult {
		attemptsB.Add(1)
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionCompleted,
			ExitCode:  &one,
			Retryable: true,
		}
	})
	resB := engineB.runStep(t.Context(), nil, step, false, models.Node{})
	if resB.Status != StatusFailed {
		t.Fatalf("expected StatusFailed, got: %s", resB.Status)
	}
	if attemptsB.Load() != 3 {
		t.Fatalf("expected 3 attempts (initial + 2 retries) for clean nonzero exit, got: %d", attemptsB.Load())
	}

	// Case C: dispatch returns nonzero exit with ExecutionErr (deadline exceeded) -> do NOT retry
	var attemptsC atomic.Int32
	engineC := &Engine{}
	engineC.SetDispatchStepFnForTest(func(context.Context, *ssh.Client, Step, bool, models.Node) StepResult {
		attemptsC.Add(1)
		return StepResult{
			Status:    StatusFailed,
			Outcome:   ssh.ExecutionUnknown,
			ExitCode:  &one,
			Err:       fmt.Errorf("wait for SSH command: %w", context.DeadlineExceeded),
			Retryable: false,
		}
	})
	resC := engineC.runStep(t.Context(), nil, step, false, models.Node{})
	if resC.Status != StatusFailed {
		t.Fatalf("expected StatusFailed, got: %s", resC.Status)
	}
	if attemptsC.Load() != 1 {
		t.Fatalf("expected exactly 1 attempt (no retry) when execution timed out, got: %d", attemptsC.Load())
	}
	if resC.Retryable {
		t.Fatal("expected Retryable to be false on execution timeout")
	}
}

func testRealClientNonzeroCleanExit(t *testing.T) {
	t.Helper()
	client, _ := executionTestClient(t, func(command string, ch cryptoSSH.Channel) {
		if _, err := io.Copy(io.Discard, ch); err != nil {
			t.Error(err)
			return
		}
		if strings.Contains(command, "fail") {
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			return
		}
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
	})

	e := &Engine{}
	// Legacy shell clean nonzero exit
	resLegacy := e.runShellLegacy(t.Context(), client, "fail-cmd", false)
	if resLegacy.Status != StatusFailed {
		t.Fatalf("expected StatusFailed, got %s", resLegacy.Status)
	}
	if resLegacy.Outcome != ssh.ExecutionCompleted {
		t.Fatalf("expected ExecutionCompleted, got %v", resLegacy.Outcome)
	}
	if resLegacy.ExitCode == nil || *resLegacy.ExitCode != 1 {
		t.Fatalf("expected ExitCode 1, got %v", resLegacy.ExitCode)
	}
	if !resLegacy.Retryable {
		t.Fatal("expected clean nonzero exit to be retryable")
	}
	if resLegacy.CleanupErr != nil || resLegacy.IOErr != nil {
		t.Fatalf("expected no cleanup/IO errors, got cleanup=%v io=%v", resLegacy.CleanupErr, resLegacy.IOErr)
	}

	// Sudo shell clean nonzero exit
	no := false
	execBash := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}
	resSudo := e.runShellEffective(t.Context(), client, "fail-cmd", execBash, true)
	if resSudo.Status != StatusFailed {
		t.Fatalf("expected StatusFailed for sudo, got %s", resSudo.Status)
	}
	if resSudo.Outcome != ssh.ExecutionCompleted {
		t.Fatalf("expected ExecutionCompleted for sudo, got %v", resSudo.Outcome)
	}
	if resSudo.ExitCode == nil || *resSudo.ExitCode != 1 {
		t.Fatalf("expected ExitCode 1 for sudo, got %v", resSudo.ExitCode)
	}
	if !resSudo.Retryable {
		t.Fatal("expected clean nonzero exit with sudo to be retryable")
	}
}

func testRealClientPlannedTimeoutNotRetryable(t *testing.T) {
	t.Helper()
	// Planned shell nonzero exit with execution timeout -> must NOT be retryable
	clientTimeout, _ := executionTestClient(t, func(command string, ch cryptoSSH.Channel) {
		if _, err := io.Copy(io.Discard, ch); err != nil {
			t.Error(err)
			return
		}
		if strings.Contains(command, "fail-timeout") {
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			time.Sleep(300 * time.Millisecond)
			_ = ch.Close()
			return
		}
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
	})

	no := false
	execBash := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}
	e := &Engine{}

	cmdCtx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	resTimeout := e.runShellEffective(cmdCtx, clientTimeout, "fail-timeout", execBash, false)
	if resTimeout.Status != StatusFailed {
		t.Fatalf("expected StatusFailed for timed out planned shell, got %s", resTimeout.Status)
	}
	if resTimeout.Outcome != ssh.ExecutionUnknown {
		t.Fatalf("expected ExecutionUnknown for timed out planned shell, got %v", resTimeout.Outcome)
	}
	if resTimeout.ExitCode == nil || *resTimeout.ExitCode != 1 {
		t.Fatalf("expected ExitCode 1, got %v", resTimeout.ExitCode)
	}
	if resTimeout.Retryable {
		t.Fatal("expected timed-out planned shell to NOT be retryable")
	}
	if resTimeout.Err == nil || !strings.Contains(resTimeout.Err.Error(), "deadline exceeded") {
		t.Fatalf("expected deadline exceeded in Err, got %v", resTimeout.Err)
	}
}

func TestPlaybook_PreserveAdditionalErrorsBeforeRetryable(t *testing.T) {
	t.Run("classify joined errors", testClassifyJoinedErrors)
	t.Run("runStep retry loop respects safeguards", testRunStepRetrySafeguards)
	t.Run("real client nonzero clean exit vs joined error", testRealClientNonzeroCleanExit)
	t.Run("real client planned timeout not retryable", testRealClientPlannedTimeoutNotRetryable)
}

func TestPlaybook_ScriptCacheRefreshedPerRun(t *testing.T) {
	dir := t.TempDir()
	script1Path := filepath.Join(dir, "script1.sh")
	script2Path := filepath.Join(dir, "script2.sh")

	if err := os.WriteFile(script1Path, []byte("#!/bin/bash\necho v1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script2Path, []byte("#!/bin/bash\necho s2\n"), 0755); err != nil {
		t.Fatal(err)
	}

	pb := &Playbook{
		Name: "test-script-refresh",
		Steps: []Step{
			{Name: "step-1", Script: script1Path},
			{Name: "step-2", Script: script2Path},
		},
	}

	e := &Engine{pb: pb}

	// 1. Initial preload
	if err := e.preloadScripts(); err != nil {
		t.Fatalf("initial preloadScripts failed: %v", err)
	}
	if string(e.scriptSources[script1Path]) != "#!/bin/bash\necho v1\n" {
		t.Fatalf("expected script1 v1, got: %s", string(e.scriptSources[script1Path]))
	}

	// 2. Modify script1 on disk and preload again on SAME engine instance
	if err := os.WriteFile(script1Path, []byte("#!/bin/bash\necho v2-updated\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := e.preloadScripts(); err != nil {
		t.Fatalf("second preloadScripts failed: %v", err)
	}
	if string(e.scriptSources[script1Path]) != "#!/bin/bash\necho v2-updated\n" {
		t.Fatalf("expected script1 refreshed to v2-updated, got: %s", string(e.scriptSources[script1Path]))
	}

	// 3. Partial preload failure: remove script2 so reading it fails
	if err := os.Remove(script2Path); err != nil {
		t.Fatal(err)
	}
	err := e.preloadScripts()
	if err == nil {
		t.Fatal("expected preloadScripts to fail when script2 is missing")
	}
	if e.scriptSources != nil {
		t.Fatalf("expected scriptSources to be nil after failed preload, got: %+v", e.scriptSources)
	}

	// 4. Restore script2 and ensure subsequent preload recovers cleanly
	if err := os.WriteFile(script2Path, []byte("#!/bin/bash\necho s2-restored\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := e.preloadScripts(); err != nil {
		t.Fatalf("recovered preloadScripts failed: %v", err)
	}
	if string(e.scriptSources[script2Path]) != "#!/bin/bash\necho s2-restored\n" {
		t.Fatalf("expected script2 restored, got: %s", string(e.scriptSources[script2Path]))
	}
	if string(e.scriptSources[script1Path]) != "#!/bin/bash\necho v2-updated\n" {
		t.Fatalf("expected script1 to still be v2-updated, got: %s", string(e.scriptSources[script1Path]))
	}
}

type snapshotTrackingProvider struct {
	config.ConfigProvider
	snapshotCount atomic.Int32
}

func (p *snapshotTrackingProvider) Snapshot() *config.Configuration {
	p.snapshotCount.Add(1)
	return p.ConfigProvider.Snapshot()
}

func TestPlaybook_SnapshotGlobalExecutionOncePerRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			if _, err := io.Copy(io.Discard, ch); err != nil {
				t.Error(err)
				return
			}
			if strings.Contains(cmd, "__XOPS_ENSURE_") {
				re := regexp.MustCompile(`__XOPS_ENSURE_[a-f0-9]+__`)
				if match := re.FindString(cmd); match != "" {
					_, _ = fmt.Fprintf(ch, "\n%s:0\n", match)
				}
			}
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	execBash := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Execution:  execBash,
	}
	cfg.Hosts.Set("host-1", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("node-1", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
	})

	baseProvider := config.NewProviderWithoutOpenSSH(cfg)
	trackingProv := &snapshotTrackingProvider{ConfigProvider: baseProvider}
	connector := adapter.NewConnector(baseProvider, ssh.WithHostKeyVerifier(executionTestTrust{server.HostKey}))
	t.Cleanup(func() { _ = connector.CloseAll() })

	scriptDir := t.TempDir()
	scriptFile := filepath.Join(scriptDir, "test.sh")
	if err := os.WriteFile(scriptFile, []byte("#!/bin/bash\necho script-run\n"), 0755); err != nil {
		t.Fatal(err)
	}

	pb := &Playbook{
		Name:    "multi-step-snapshot-test",
		Targets: Targets{Nodes: []string{"node-1"}},
		Steps: []Step{
			{Name: "step-shell", Shell: "echo hello"},
			{Name: "step-script", Script: scriptFile},
			{Name: "step-ensure", Ensure: &EnsureSpec{Check: "echo check", Action: "echo action"}},
		},
	}

	engine := NewEngine(pb, trackingProv, connector)

	// Run 1: Must call Snapshot() exactly ONCE across all 3 steps + ensure check
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("first engine.Run failed: %v", err)
	}
	if len(report.Hosts) == 0 || report.Hosts[0].Status != HostStatusSuccess {
		t.Fatalf("steps failed in run 1: %+v", report.Hosts)
	}
	if got := trackingProv.snapshotCount.Load(); got != 1 {
		t.Fatalf("expected Snapshot() called exactly 1 time during run 1, got: %d", got)
	}
	if engine.frozenGlobalExec == nil || engine.frozenGlobalExec.Interpreter != ssh.InterpreterBash {
		t.Fatalf("frozenGlobalExec not properly preserved: %+v", engine.frozenGlobalExec)
	}

	// Run 2: Running again takes exactly 1 new snapshot (total 2)
	report2, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("second engine.Run failed: %v", err)
	}
	if len(report2.Hosts) == 0 || report2.Hosts[0].Status != HostStatusSuccess {
		t.Fatalf("steps failed in run 2: %+v", report2.Hosts)
	}
	if got := trackingProv.snapshotCount.Load(); got != 2 {
		t.Fatalf("expected Snapshot() called exactly 2 times across two runs, got: %d", got)
	}
}

func TestPlaybook_FreezeNodeExecutionSettingsAlongsideGlobal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	server, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			if _, err := io.Copy(io.Discard, ch); err != nil {
				t.Error(err)
				return
			}
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	execServer := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Execution:  execServer,
	}
	cfg.Hosts.Set("host-1", models.Host{Address: host, Port: uint16(port)})
	cfg.Hosts.Set("host-2", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("id-1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("node-1", models.Node{HostRef: "host-1", IdentityRef: "id-1", Execution: execServer.Clone()})
	cfg.Nodes.Set("node-2", models.Node{HostRef: "host-2", IdentityRef: "id-1", Execution: execServer.Clone()})

	prov := config.NewProviderWithoutOpenSSH(cfg)
	connector := adapter.NewConnector(prov, ssh.WithHostKeyVerifier(executionTestTrust{server.HostKey}))
	t.Cleanup(func() { _ = connector.CloseAll() })

	pb := &Playbook{
		Name:     "freeze-node-settings-test",
		Targets:  Targets{Nodes: []string{"node-1", "node-2"}},
		Settings: Settings{Concurrency: 1},
		Steps: []Step{
			{Name: "step-1", Shell: "echo ok"},
		},
	}

	engine := NewEngine(pb, prov, connector)

	var node2ExecSeen atomic.Pointer[ssh.ExecutionConfig]
	origRunStep := engine.runStepFn
	engine.runStepFn = func(stepCtx context.Context, client *ssh.Client, step Step, sudo bool, node models.Node) StepResult {
		// When node-1 runs, mutate node-2 in the live provider to an incompatible config (Bash with Cmd dialect)
		if node.HostRef == "host-1" {
			cfg.Nodes.Set("node-2", models.Node{
				HostRef:     "host-2",
				IdentityRef: "id-1",
				Execution:   &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchCmd},
			})
		}
		if node.HostRef == "host-2" {
			node2ExecSeen.Store(node.Execution)
		}
		return origRunStep(stepCtx, client, step, sudo, node)
	}

	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}
	if len(report.Hosts) != 2 {
		t.Fatalf("expected 2 host reports, got: %d", len(report.Hosts))
	}
	for _, hr := range report.Hosts {
		if hr.Status != HostStatusSuccess {
			t.Fatalf("host %s failed: %+v", hr.NodeID, hr)
		}
	}

	seen := node2ExecSeen.Load()
	if seen == nil {
		t.Fatal("expected node-2 execution config to be captured")
	}
	if seen.Interpreter != ssh.InterpreterServer {
		t.Fatalf("expected node-2 to retain frozen InterpreterServer, got %v", seen.Interpreter)
	}
	if seen.LaunchDialect != ssh.LaunchPOSIX {
		t.Fatalf("expected node-2 to retain frozen LaunchPOSIX, got %v", seen.LaunchDialect)
	}
}
