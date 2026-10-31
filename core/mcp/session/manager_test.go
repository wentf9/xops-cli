package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	"go.uber.org/goleak"
)

type fakePTY struct {
	inR       *io.PipeReader
	inW       *io.PipeWriter
	outR      *io.PipeReader
	outW      *io.PipeWriter
	sigCh     chan string
	closed    chan struct{}
	mu        sync.Mutex
	signals   []string
	closeOnce sync.Once
	done      chan struct{}
}

func newFakePTY(handler func(in io.Reader, out io.Writer, sigCh <-chan string)) *fakePTY {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	sigCh := make(chan string, 8)
	closed := make(chan struct{})
	done := make(chan struct{})
	f := &fakePTY{
		inR:    inR,
		inW:    inW,
		outR:   outR,
		outW:   outW,
		sigCh:  sigCh,
		closed: closed,
		done:   done,
	}
	go func() {
		defer close(done)
		defer func() { _ = outW.Close() }()
		handler(inR, outW, sigCh)
	}()
	return f
}

func (f *fakePTY) Read(p []byte) (int, error)  { return f.outR.Read(p) }
func (f *fakePTY) Write(p []byte) (int, error) { return f.inW.Write(p) }
func (f *fakePTY) Signal(sig string) error {
	f.mu.Lock()
	select {
	case <-f.closed:
		f.mu.Unlock()
		return nil
	default:
	}
	f.signals = append(f.signals, sig)
	select {
	case f.sigCh <- sig:
	default:
	}
	f.mu.Unlock()
	_, _ = io.WriteString(f.outW, "^"+sig+"\n")
	return nil
}
func (f *fakePTY) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		close(f.closed)
		close(f.sigCh)
		f.mu.Unlock()
		_ = f.inR.Close()
		_ = f.inW.Close()
		_ = f.outR.Close()
		_ = f.outW.Close()
		<-f.done
	})
	return nil
}

var sentinelTokenPattern = regexp.MustCompile(`'DONE_([0-9a-f]+)'`)

// sentinelToken extracts the completion token from the printf sentinel line.
func sentinelToken(line string) (string, bool) {
	m := sentinelTokenPattern.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func runStatefulFakeShell(in io.Reader, out io.Writer, _ <-chan string) {
	cwd := "/root"
	env := map[string]string{}
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if tok, ok := sentinelToken(line); ok {
			_, _ = fmt.Fprintf(out, "\n___MCP_DONE_%s_0___\n", tok)
			continue
		}
		switch {
		case line == "" || strings.HasPrefix(line, "stty "):
		case strings.HasPrefix(line, "cd -- "):
			cwd = strings.Trim(strings.TrimPrefix(line, "cd -- "), "'")
		case strings.HasPrefix(line, "export "):
			if k, v, ok := strings.Cut(strings.TrimPrefix(line, "export "), "="); ok {
				env[k] = v
			}
		case line == "pwd":
			_, _ = io.WriteString(out, cwd+"\n")
		case line == "echo $FOO":
			_, _ = io.WriteString(out, env["FOO"]+"\n")
		}
	}
}

// newTestManager returns a manager and its shutdown function. Callers defer
// the shutdown after goleak.VerifyNone so it runs first.
func newTestManager(t *testing.T) (*Manager, func()) {
	t.Helper()
	mgr := NewManager(5 * time.Minute)
	return mgr, func() {
		if err := mgr.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	}
}

func TestManagerPersistentStateAndSignals(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	var createdCount int
	dial := func(context.Context) (ports.PTYSession, error) {
		createdCount++
		return newFakePTY(runStatefulFakeShell), nil
	}
	key := Key{Scope: "stdio", NodeID: "node-1", SessionName: "work"}
	run := func(cmd, cwd string) ExecuteResult {
		t.Helper()
		res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: cmd, Cwd: cwd})
		if err != nil {
			t.Fatalf("Execute %q: %v", cmd, err)
		}
		return res
	}

	if res := run("export FOO=bar", "/srv/app"); res.State != StateCompleted || res.ExitCode == nil || *res.ExitCode != 0 {
		t.Fatalf("expected completed exit 0, got %+v", res)
	}
	if res := run("pwd", ""); res.Output != "/srv/app" {
		t.Fatalf("expected persisted cwd /srv/app, got %q", res.Output)
	}
	if res := run("echo $FOO", ""); res.Output != "bar" {
		t.Fatalf("expected persisted env bar, got %q", res.Output)
	}
	if createdCount != 1 {
		t.Fatalf("expected 1 PTY dial, got %d", createdCount)
	}
	if res := run("SIGINT", ""); !strings.Contains(res.Output, "[Status: Signal SIGINT sent]") {
		t.Fatalf("unexpected signal output: %q", res.Output)
	}
}

func TestManagerTimeoutAndIncrementalPolling(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	releaseStep2 := make(chan struct{})
	dial := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, out io.Writer, _ <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "long-job" {
					_, _ = io.WriteString(out, "phase-1-started\n")
					continue
				}
				if tok, ok := sentinelToken(line); ok {
					<-releaseStep2
					_, _ = fmt.Fprintf(out, "phase-2-finished\n___MCP_DONE_%s_0___\n", tok)
				}
			}
		}), nil
	}

	key := Key{Scope: "stdio", NodeID: "node-1", SessionName: "bg"}
	res1, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "long-job", Timeout: 60 * time.Millisecond})
	if err != nil {
		t.Fatalf("Execute long-job: %v", err)
	}
	if res1.State != StateRunning || res1.ExitCode != nil || !strings.Contains(res1.Output, "phase-1-started") {
		t.Fatalf("expected running state without exit code, got %+v", res1)
	}

	// A new command while the previous one is in flight must be rejected
	// instead of being typed into the running program's stdin.
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "rm -rf /tmp/x"}); !errors.Is(err, ErrSessionBusy) {
		t.Fatalf("expected ErrSessionBusy, got %v", err)
	}

	close(releaseStep2)
	res2, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Timeout: time.Second})
	if err != nil {
		t.Fatalf("Poll output: %v", err)
	}
	if res2.State != StateCompleted || res2.ExitCode == nil || *res2.ExitCode != 0 || res2.Output != "phase-2-finished" {
		t.Fatalf("expected completed 'phase-2-finished' exit 0, got %+v", res2)
	}
}

// An echoed command line contains the token but not the contiguous sentinel
// prefix, and a malformed candidate must never be read as "exit 0".
func TestManagerIgnoresEchoedAndMalformedSentinel(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	release := make(chan struct{})
	dial := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, out io.Writer, _ <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				line := scanner.Text()
				tok, ok := sentinelToken(line)
				if !ok {
					continue
				}
				// Echo the raw command line and a malformed candidate first.
				_, _ = io.WriteString(out, line+"\n")
				_, _ = fmt.Fprintf(out, "___MCP_DONE_%s_%%d___\n", tok)
				<-release
				_, _ = fmt.Fprintf(out, "done\n___MCP_DONE_%s_7___\n", tok)
			}
		}), nil
	}
	key := Key{Scope: "stdio", NodeID: "n", SessionName: "echo"}
	res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "sudo -v", Timeout: 80 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateRunning || res.ExitCode != nil {
		t.Fatalf("echoed/malformed sentinel must not complete the command, got %+v", res)
	}
	close(release)
	res, err = mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateCompleted || res.ExitCode == nil || *res.ExitCode != 7 {
		t.Fatalf("expected completion with exit 7, got %+v", res)
	}
}

func TestManagerSessionLostIsNotSuccess(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	dial := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, out io.Writer, _ <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				if strings.TrimSpace(scanner.Text()) == "exit" {
					_, _ = io.WriteString(out, "bye\n")
					return
				}
			}
		}), nil
	}
	res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: Key{SessionName: "lost"}, Dial: dial, Command: "exit", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateLost || res.ExitCode != nil {
		t.Fatalf("expected lost state without exit code, got %+v", res)
	}
}

func TestManagerGenerationChangeRedials(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	var dials int
	dial := func(context.Context) (ports.PTYSession, error) {
		dials++
		return newFakePTY(runStatefulFakeShell), nil
	}
	key := Key{SessionName: "gen"}
	for _, gen := range []string{"v1", "v1", "v2"} {
		if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Generation: gen, Dial: dial, Command: "pwd"}); err != nil {
			t.Fatal(err)
		}
	}
	if dials != 2 {
		t.Fatalf("expected a redial only after generation change, got %d dials", dials)
	}
}

func TestManagerSessionLimit(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()
	mgr.maxSessions = 1
	mgr.maxTotalSessions = 2

	dial := func(context.Context) (ports.PTYSession, error) { return newFakePTY(runStatefulFakeShell), nil }
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: Key{Scope: "s1", SessionName: "a"}, Dial: dial, Command: "pwd"}); err != nil {
		t.Fatal(err)
	}
	// Second session in the same scope exceeds per-scope limit.
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: Key{Scope: "s1", SessionName: "b"}, Dial: dial, Command: "pwd"}); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("expected per-scope ErrTooManySessions, got %v", err)
	}
	// A different scope can still open a session up to maxTotalSessions.
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: Key{Scope: "s2", SessionName: "a"}, Dial: dial, Command: "pwd"}); err != nil {
		t.Fatalf("expected second scope to succeed, got %v", err)
	}
	// Third scope exceeds maxTotalSessions.
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: Key{Scope: "s3", SessionName: "a"}, Dial: dial, Command: "pwd"}); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("expected global ErrTooManySessions, got %v", err)
	}
}

func TestSignalDoesNotBypassBusyUntilCommandExits(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	dial := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, _ io.Writer, _ <-chan string) {
			// Simulate a wedged process that ignores signals and never prints
			// the completion sentinel until the PTY is closed.
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
			}
		}), nil
	}

	key := Key{Scope: "stdio", NodeID: "n", SessionName: "trap"}
	res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "trap '' INT; sleep 60", Timeout: 50 * time.Millisecond})
	if err != nil || res.State != StateRunning {
		t.Fatalf("expected running state, got res=%+v err=%v", res, err)
	}

	// Sending SIGINT when the process ignores it must keep the session in StateRunning.
	sigRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "SIGINT"})
	if err != nil {
		t.Fatal(err)
	}
	if sigRes.State != StateRunning || !strings.Contains(sigRes.Output, "command still running") {
		t.Fatalf("expected command still running after ignored SIGINT, got %+v", sigRes)
	}

	// Because the process is still running, a new command must still be rejected with ErrSessionBusy.
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "echo injected"}); !errors.Is(err, ErrSessionBusy) {
		t.Fatalf("expected ErrSessionBusy after ignored SIGINT, got %v", err)
	}

	// SIGKILL on the still-wedged session must deterministically return StateLost
	// and evict the session so the next command dials a fresh PTY.
	killRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "SIGKILL"})
	if err != nil {
		t.Fatal(err)
	}
	if killRes.State != StateLost || !strings.Contains(killRes.Output, "Session terminated by SIGKILL") {
		t.Fatalf("expected StateLost on SIGKILL of wedged session, got %+v", killRes)
	}

	nextRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: newFakePTYDialer(), Command: "pwd"})
	if err != nil || nextRes.State != StateCompleted || nextRes.Output != "/root" {
		t.Fatalf("expected fresh session after SIGKILL eviction, got res=%+v err=%v", nextRes, err)
	}
}

func TestSignalCompletesCommandAndIdleEOFClosesSession(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	dial := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, out io.Writer, sigCh <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if tok, ok := sentinelToken(line); ok {
					sig := <-sigCh
					if sig == "SIGINT" {
						_, _ = fmt.Fprintf(out, "interrupted\n___MCP_DONE_%s_130___\n", tok)
					}
					sig = <-sigCh
					if sig == "EOF" {
						return
					}
				}
			}
		}), nil
	}

	key := Key{Scope: "stdio", NodeID: "n", SessionName: "sig-complete"}
	res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "sleep 30", Timeout: 40 * time.Millisecond})
	if err != nil || res.State != StateRunning {
		t.Fatalf("expected running state, got res=%+v err=%v", res, err)
	}

	intRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "SIGINT"})
	if err != nil {
		t.Fatal(err)
	}
	if intRes.State != StateCompleted || intRes.ExitCode == nil || *intRes.ExitCode != 130 || !strings.Contains(intRes.Output, "[Status: Signal SIGINT sent]") {
		t.Fatalf("expected StateCompleted exit 130 on SIGINT, got %+v", intRes)
	}

	eofRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "EOF"})
	if err != nil {
		t.Fatal(err)
	}
	if eofRes.State != StateLost || !strings.Contains(eofRes.Output, "session closed") {
		t.Fatalf("expected StateLost when idle EOF closes shell, got %+v", eofRes)
	}
}

func TestChattySessionDoesNotDefeatSweepIdleAndMaxLifetime(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	baseNow := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	curNow := baseNow
	mgr.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}

	var outWriter io.Writer
	writerReady := make(chan struct{})
	dial := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, out io.Writer, _ <-chan string) {
			outWriter = out
			close(writerReady)
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				// Keep the shell alive and the command running (never emit sentinel).
			}
		}), nil
	}

	key := Key{Scope: "stdio", NodeID: "n", SessionName: "tail"}
	res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: key, Dial: dial, Command: "tail -f app.log", Timeout: 30 * time.Millisecond})
	if err != nil || res.State != StateRunning || !res.NewSession {
		t.Fatalf("expected new running session, got res=%+v err=%v", res, err)
	}
	<-writerReady

	// Advance clock to 1.5*idleTTL and emit chatty output from the process.
	nowMu.Lock()
	curNow = baseNow.Add(mgr.idleTTL + mgr.idleTTL/2)
	nowMu.Unlock()
	if _, err := io.WriteString(outWriter, "tick-1\n"); err != nil {
		t.Fatal(err)
	}
	// Session must still be alive before 2*idleTTL.
	mgr.SweepIdle(curNow)
	mgr.mu.Lock()
	sess := mgr.sessions[key]
	mgr.mu.Unlock()
	if sess == nil || sess.isClosed() {
		t.Fatal("expected busy session to remain alive before 2*idleTTL")
	}

	// Emit more output right before 2*idleTTL: without client Execute calls,
	// readLoop output must NOT extend lastActive past 2*idleTTL.
	if _, err := io.WriteString(outWriter, "tick-2\n"); err != nil {
		t.Fatal(err)
	}
	nowMu.Lock()
	curNow = baseNow.Add(2*mgr.idleTTL + time.Second)
	nowMu.Unlock()
	mgr.SweepIdle(curNow)

	mgr.mu.Lock()
	remaining := len(mgr.sessions)
	mgr.mu.Unlock()
	if remaining != 0 || !sess.isClosed() {
		t.Fatalf("expected chatty abandoned session to be swept and closed, got remaining=%d closed=%v", remaining, sess.isClosed())
	}

	// Test maxSessionLifetime: even when client Execute calls keep lastActive
	// well within idleTTL, the session still expires after maxSessionLifetime (12h).
	mgr.mu.Lock()
	mgr.idleTTL = 24 * time.Hour
	mgr.mu.Unlock()
	keyLife := Key{Scope: "stdio", NodeID: "n", SessionName: "long-lived"}
	firstRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: keyLife, Dial: newFakePTYDialer(), Command: "pwd"})
	if err != nil || !firstRes.NewSession {
		t.Fatalf("expected NewSession=true on creation, got res=%+v err=%v", firstRes, err)
	}
	nowMu.Lock()
	curNow = curNow.Add(maxSessionLifetime - time.Minute)
	nowMu.Unlock()
	midRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: keyLife, Dial: newFakePTYDialer(), Command: "pwd"})
	if err != nil || midRes.NewSession {
		t.Fatalf("expected existing session before maxSessionLifetime, got res=%+v err=%v", midRes, err)
	}
	// Only 2 minutes since last Execute (<< idleTTL), but past 12h since creation.
	nowMu.Lock()
	curNow = curNow.Add(2 * time.Minute)
	nowMu.Unlock()
	afterRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: keyLife, Dial: newFakePTYDialer(), Command: "pwd"})
	if err != nil || !afterRes.NewSession {
		t.Fatalf("expected session replacement (NewSession=true) after maxSessionLifetime, got res=%+v err=%v", afterRes, err)
	}
}

func TestSignalAndPollOnMissingOrReconfiguredSession(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	var dials int
	dial := func(context.Context) (ports.PTYSession, error) {
		dials++
		return newFakePTY(runStatefulFakeShell), nil
	}
	missingKey := Key{Scope: "stdio", NodeID: "n", SessionName: "ghost"}
	for _, cmd := range []string{"", "SIGINT", "EOF", "SIGKILL"} {
		if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: missingKey, Dial: dial, Command: cmd}); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound for cmd=%q on missing session, got %v", cmd, err)
		}
	}
	if dials != 0 {
		t.Fatalf("signal/poll on missing session must not dial a PTY, got %d dials", dials)
	}

	// When a session's generation changes, polling or signaling with the new
	// generation must close the stale session and include "reconfigured" in the
	// ErrSessionNotFound message (R5-5).
	reconfKey := Key{Scope: "stdio", NodeID: "n", SessionName: "reconf"}
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: reconfKey, Generation: "v1", Dial: dial, Command: "pwd"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: reconfKey, Generation: "v2", Dial: dial, Command: ""}); !errors.Is(err, ErrSessionNotFound) || !strings.Contains(err.Error(), "reconfigured") {
		t.Fatalf("expected ErrSessionNotFound with reconfigured reason, got %v", err)
	}
}

func TestConcurrentSignalInterruptsWaitingExecute(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	// Verify concurrent command/poll while a command is waiting in waitSentinel
	// returns ErrSessionInUse immediately, while a concurrent signal (SIGINT) is
	// delivered immediately and wakes the waiting command (R5-2).
	started := make(chan struct{})
	busyKey := Key{Scope: "stdio", NodeID: "n", SessionName: "busy-lock"}
	busyDial := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, out io.Writer, sigCh <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				if tok, ok := sentinelToken(scanner.Text()); ok {
					close(started)
					sig := <-sigCh
					if sig == "SIGINT" {
						_, _ = fmt.Fprintf(out, "interrupted\n___MCP_DONE_%s_130___\n", tok)
					}
				}
			}
		}), nil
	}

	type waitOutcome struct {
		res ExecuteResult
		err error
	}
	waitCh := make(chan waitOutcome, 1)
	go func() {
		res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: busyKey, Dial: busyDial, Command: "sleep 60", Timeout: time.Minute})
		waitCh <- waitOutcome{res: res, err: err}
	}()
	<-started

	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: busyKey, Dial: busyDial, Command: "pwd"}); !errors.Is(err, ErrSessionInUse) {
		t.Fatalf("expected immediate ErrSessionInUse on concurrent command, got %v", err)
	}
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: busyKey, Dial: busyDial, Command: ""}); !errors.Is(err, ErrSessionInUse) {
		t.Fatalf("expected immediate ErrSessionInUse on concurrent poll, got %v", err)
	}
	sigRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: busyKey, Dial: busyDial, Command: "SIGINT"})
	if err != nil || sigRes.State != StateRunning || !strings.Contains(sigRes.Output, "another call is waiting") {
		t.Fatalf("expected concurrent SIGINT to be delivered in flight, got res=%+v err=%v", sigRes, err)
	}
	outcome := <-waitCh
	if outcome.err != nil || outcome.res.State != StateCompleted || outcome.res.ExitCode == nil || *outcome.res.ExitCode != 130 {
		t.Fatalf("expected waiting Execute to complete with exit 130 after SIGINT, got %+v", outcome)
	}

	// Verify concurrent SIGKILL while a command is waiting in waitSentinel
	// forcibly closes the session and unblocks the waiting caller with StateLost.
	killStarted := make(chan struct{})
	killKey := Key{Scope: "stdio", NodeID: "n", SessionName: "kill-lock"}
	killDial := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, _ io.Writer, _ <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				if _, ok := sentinelToken(scanner.Text()); ok {
					close(killStarted)
				}
			}
		}), nil
	}
	killWaitCh := make(chan waitOutcome, 1)
	go func() {
		res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: killKey, Dial: killDial, Command: "sleep 60", Timeout: time.Minute})
		killWaitCh <- waitOutcome{res: res, err: err}
	}()
	<-killStarted

	killRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: killKey, Dial: killDial, Command: "SIGKILL"})
	if err != nil || killRes.State != StateLost {
		t.Fatalf("expected concurrent SIGKILL to return StateLost, got res=%+v err=%v", killRes, err)
	}
	killOutcome := <-killWaitCh
	if killOutcome.err != nil || killOutcome.res.State != StateLost {
		t.Fatalf("expected waiting Execute to unblock with StateLost after SIGKILL, got %+v", killOutcome)
	}
}

func newFakePTYDialer() func(context.Context) (ports.PTYSession, error) {
	return func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(runStatefulFakeShell), nil
	}
}

func TestManagerTinyIdleTTLDoesNotPanic(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr := NewManager(time.Nanosecond)
	defer func() { _ = mgr.Shutdown(context.Background()) }()

	if _, err := mgr.Execute(context.Background(), ExecuteRequest{
		Key:     Key{SessionName: "tiny"},
		Dial:    newFakePTYDialer(),
		Command: "pwd",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanTerminalOutputStripsStaleSentinelANSIAndCR(t *testing.T) {
	got := cleanTerminalOutput("^C\r\n___MCP_DONE_abcdef012345_130___\r\n\x1b[32mgreen\x1b[0m\n10%\r50%\r100%\r\n")
	want := "^C\ngreen\n100%"
	if got != want {
		t.Fatalf("cleanTerminalOutput mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestConcurrentDialEnforcesMaxSessionsAndReplacesStaleGeneration(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()
	mgr.maxSessions = 1

	// 1. R6-2: When maxSessions=1, findOrReserveSlot reserves the slot before
	// dialing so a second concurrent call for a different key is rejected with
	// ErrTooManySessions immediately without wasting a dial.
	firstDialing := make(chan struct{})
	releaseDial := make(chan struct{})
	var dialCount atomic.Int32
	dialBarrier := func(context.Context) (ports.PTYSession, error) {
		if dialCount.Add(1) == 1 {
			close(firstDialing)
		}
		<-releaseDial
		return newFakePTY(runStatefulFakeShell), nil
	}

	k1Done := make(chan error, 1)
	go func() {
		_, err := mgr.Execute(context.Background(), ExecuteRequest{
			Key:     Key{Scope: "s1", NodeID: "n", SessionName: "k1"},
			Dial:    dialBarrier,
			Command: "pwd",
		})
		k1Done <- err
	}()
	<-firstDialing

	_, err2 := mgr.Execute(context.Background(), ExecuteRequest{
		Key:     Key{Scope: "s1", NodeID: "n", SessionName: "k2"},
		Dial:    dialBarrier,
		Command: "pwd",
	})
	close(releaseDial)
	err1 := <-k1Done

	if err1 != nil || !errors.Is(err2, ErrTooManySessions) {
		t.Fatalf("expected k1=nil and k2=ErrTooManySessions, got err1=%v err2=%v", err1, err2)
	}
	if got := dialCount.Load(); got != 1 {
		t.Fatalf("expected pre-dial reservation to prevent second Dial, got dialCount=%d", got)
	}

	// 2. R6-5: While call A (generation v2) is blocked in Dial for the same key,
	// call B publishes a v1 session. Releasing A must replace the v1 session with
	// v2 and close the v1 PTY.
	mgr.maxSessions = DefaultMaxSessions
	aDialing := make(chan struct{})
	releaseA := make(chan struct{})
	var ptyV1, ptyV2 *fakePTY
	raceKey := Key{Scope: "s2", NodeID: "n", SessionName: "race-gen"}

	aDone := make(chan error, 1)
	go func() {
		_, err := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        raceKey,
			Generation: "v2",
			Dial: func(context.Context) (ports.PTYSession, error) {
				close(aDialing)
				<-releaseA
				ptyV2 = newFakePTY(runStatefulFakeShell)
				return ptyV2, nil
			},
			Command: "pwd",
		})
		aDone <- err
	}()
	<-aDialing

	if _, err := mgr.Execute(context.Background(), ExecuteRequest{
		Key:        raceKey,
		Generation: "v1",
		Dial: func(context.Context) (ports.PTYSession, error) {
			ptyV1 = newFakePTY(runStatefulFakeShell)
			return ptyV1, nil
		},
		Command: "pwd",
	}); err != nil {
		t.Fatalf("publish v1 during A's dial: %v", err)
	}

	close(releaseA)
	if err := <-aDone; err != nil {
		t.Fatalf("call A (v2) failed: %v", err)
	}
	select {
	case <-ptyV1.done:
	default:
		t.Fatal("expected stale v1 PTY to be closed when v2 published")
	}
	mgr.mu.Lock()
	cur := mgr.sessions[raceKey]
	mgr.mu.Unlock()
	if cur == nil || cur.generation != "v2" || cur.pty != ptyV2 {
		t.Fatalf("expected active session to be v2, got %+v", cur)
	}
}

func TestDialPanicReleasesSlotAndSameKeyDeduplicates(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	// 1. R7-3(a): If Dial panics, the reserved pending slot and inflight entry
	// must still be released by defer so subsequent calls in that scope succeed.
	mgr.maxSessions = 1
	panicScope := Key{Scope: "s-panic", NodeID: "n", SessionName: "p1"}
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic from Dial")
			}
		}()
		_, _ = mgr.Execute(context.Background(), ExecuteRequest{
			Key: panicScope,
			Dial: func(context.Context) (ports.PTYSession, error) {
				panic("boom")
			},
			Command: "pwd",
		})
	}()
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{
		Key:     panicScope,
		Dial:    newFakePTYDialer(),
		Command: "pwd",
	}); err != nil {
		t.Fatalf("expected slot to be released after Dial panic, got %v", err)
	}

	// 2. R7-3(b): Two concurrent calls for the same new Key and Generation must
	// share a single pending slot and dial only once, leaving room for another
	// key in the same scope (maxSessions=2) and returning NewSession=true to the
	// winning caller regardless of which goroutine wakes first after call.done.
	mgr.maxSessions = 2
	sameKey := Key{Scope: "s-dedup", NodeID: "n", SessionName: "shared"}
	otherKey := Key{Scope: "s-dedup", NodeID: "n", SessionName: "other"}
	sharedDialing := make(chan struct{})
	releaseSharedDial := make(chan struct{})
	var sharedDials atomic.Int32
	sharedDial := func(context.Context) (ports.PTYSession, error) {
		if sharedDials.Add(1) == 1 {
			close(sharedDialing)
		}
		<-releaseSharedDial
		return newFakePTY(runStatefulFakeShell), nil
	}

	type sharedOutcome struct {
		res ExecuteResult
		err error
	}
	shared1Done := make(chan sharedOutcome, 1)
	go func() {
		res, err := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        sameKey,
			Generation: "g1",
			Dial:       sharedDial,
			Command:    "pwd",
		})
		shared1Done <- sharedOutcome{res: res, err: err}
	}()
	<-sharedDialing

	shared2Done := make(chan sharedOutcome, 1)
	go func() {
		res, err := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        sameKey,
			Generation: "g1",
			Dial:       sharedDial,
			Command:    "pwd",
		})
		shared2Done <- sharedOutcome{res: res, err: err}
	}()

	waitForDialWaiters(t, mgr, sameKey, 1)

	// Opening otherKey while shared1 and shared2 are both in flight for sameKey
	// must succeed because sameKey only occupies 1 of the 2 scope slots.
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{
		Key:     otherKey,
		Dial:    newFakePTYDialer(),
		Command: "pwd",
	}); err != nil {
		t.Fatalf("expected otherKey to succeed with deduplicated pending slot, got %v", err)
	}

	close(releaseSharedDial)
	out1 := <-shared1Done
	out2 := <-shared2Done
	if got := sharedDials.Load(); got != 1 {
		t.Fatalf("expected concurrent same-key calls to dial once, got %d", got)
	}
	winner, loser := out1, out2
	if out1.err != nil {
		winner, loser = out2, out1
	}
	if winner.err != nil || !winner.res.NewSession {
		t.Fatalf("expected winning caller to succeed with NewSession=true, got winner=%+v loser=%+v", winner, loser)
	}
	if loser.err != nil && !errors.Is(loser.err, ErrSessionInUse) {
		t.Fatalf("expected second caller to either get ErrSessionInUse or run sequentially with NewSession=false, got %+v", loser)
	}
	if loser.err == nil && loser.res.NewSession {
		t.Fatalf("expected second caller not to report NewSession=true, got %+v", loser)
	}
}

func waitForDialWaiters(t *testing.T, mgr *Manager, key Key, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		mgr.mu.Lock()
		call := mgr.inflight[key]
		waiters := 0
		if call != nil {
			waiters = call.waiters
		}
		mgr.mu.Unlock()
		if waiters == want {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out waiting for %d inflight dial waiter(s) on %+v", want, key)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestConcurrentDialLeaderCancelAllowsWaiterRetry(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	// 1. R8-3 / R9-3: If the leader's dial fails because the leader's own ctx
	// was canceled, a deduplicated waiter whose context is still valid must
	// retry with its own dial rather than inheriting the leader's cancellation.
	cancelKey := Key{Scope: "s-cancel", NodeID: "n", SessionName: "retry-on-cancel"}
	leaderDialing := make(chan struct{})
	var cancelDials atomic.Int32
	cancelDial := func(dialCtx context.Context) (ports.PTYSession, error) {
		if cancelDials.Add(1) == 1 {
			close(leaderDialing)
			<-dialCtx.Done()
			return nil, fmt.Errorf("leader dial canceled: %w", dialCtx.Err())
		}
		return newFakePTY(runStatefulFakeShell), nil
	}

	type outcome struct {
		res ExecuteResult
		err error
	}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan outcome, 1)
	go func() {
		res, err := mgr.Execute(leaderCtx, ExecuteRequest{
			Key:        cancelKey,
			Generation: "g1",
			Dial:       cancelDial,
			Command:    "pwd",
		})
		leaderDone <- outcome{res: res, err: err}
	}()
	<-leaderDialing

	followerDone := make(chan outcome, 1)
	go func() {
		res, err := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        cancelKey,
			Generation: "g1",
			Dial:       cancelDial,
			Command:    "pwd",
		})
		followerDone <- outcome{res: res, err: err}
	}()

	waitForDialWaiters(t, mgr, cancelKey, 1)
	cancelLeader()

	leaderOut := <-leaderDone
	followerOut := <-followerDone
	if !errors.Is(leaderOut.err, context.Canceled) {
		t.Fatalf("expected canceled leader to fail with context.Canceled, got %+v", leaderOut)
	}
	if followerOut.err != nil || !followerOut.res.NewSession || followerOut.res.Output != "/root" {
		t.Fatalf("expected follower to retry dial and succeed with NewSession=true, got %+v", followerOut)
	}
	if got := cancelDials.Load(); got != 2 {
		t.Fatalf("expected follower to perform a second dial after leader cancellation, got %d dials", got)
	}

	// 2. R9-3: If the backend dial returns an error wrapping
	// context.DeadlineExceeded while the leader's ctx is NOT canceled (e.g.,
	// SSH TCP dial timeout to an unreachable target), concurrent waiters must
	// NOT retry and must all receive the dial timeout error immediately.
	timeoutKey := Key{Scope: "s-cancel", NodeID: "n", SessionName: "no-retry-on-dial-timeout"}
	timeoutDialing := make(chan struct{})
	releaseTimeoutDial := make(chan struct{})
	var createCalls atomic.Int32
	timeoutDial := func(context.Context) (ports.PTYSession, error) {
		if createCalls.Add(1) == 1 {
			close(timeoutDialing)
		}
		<-releaseTimeoutDial
		return nil, fmt.Errorf("dial timeout: %w", context.DeadlineExceeded)
	}

	tLeaderDone := make(chan outcome, 1)
	go func() {
		res, err := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        timeoutKey,
			Generation: "g1",
			Dial:       timeoutDial,
			Command:    "pwd",
		})
		tLeaderDone <- outcome{res: res, err: err}
	}()
	<-timeoutDialing

	tWaiter1Done := make(chan outcome, 1)
	tWaiter2Done := make(chan outcome, 1)
	for _, ch := range []chan outcome{tWaiter1Done, tWaiter2Done} {
		go func(doneCh chan outcome) {
			res, err := mgr.Execute(context.Background(), ExecuteRequest{
				Key:        timeoutKey,
				Generation: "g1",
				Dial:       timeoutDial,
				Command:    "pwd",
			})
			doneCh <- outcome{res: res, err: err}
		}(ch)
	}

	waitForDialWaiters(t, mgr, timeoutKey, 2)
	close(releaseTimeoutDial)

	for i, ch := range []chan outcome{tLeaderDone, tWaiter1Done, tWaiter2Done} {
		out := <-ch
		if !errors.Is(out.err, context.DeadlineExceeded) {
			t.Fatalf("caller %d: expected dial timeout wrapping DeadlineExceeded, got %+v", i, out)
		}
	}
	if got := createCalls.Load(); got != 1 {
		t.Fatalf("expected backend dial timeout not to trigger waiter retries (createCalls=1), got %d", got)
	}
}

type nonReentrantPTY struct {
	*fakePTY
	t                *testing.T
	activeWriters    atomic.Int32
	blockNext        atomic.Bool
	failBlockedWrite bool
	writeEntered     chan struct{}
	releaseWrite     chan struct{}
	eventsMu         sync.Mutex
	events           []string
}

func (p *nonReentrantPTY) Write(b []byte) (int, error) {
	if p.activeWriters.Add(1) != 1 {
		p.t.Errorf("concurrent PTY input operation detected in Write")
	}
	defer p.activeWriters.Add(-1)
	if p.blockNext.CompareAndSwap(true, false) {
		close(p.writeEntered)
		select {
		case <-p.releaseWrite:
		case <-p.closed:
			p.eventsMu.Lock()
			p.events = append(p.events, "write-closed")
			p.eventsMu.Unlock()
			return 0, io.ErrClosedPipe
		}
		p.eventsMu.Lock()
		p.events = append(p.events, "write")
		p.eventsMu.Unlock()
		if p.failBlockedWrite {
			return 0, io.ErrClosedPipe
		}
	}
	return p.fakePTY.Write(b)
}

func (p *nonReentrantPTY) Signal(sig string) error {
	writesStdin := sig == "SIGINT" || sig == "EOF"
	if writesStdin {
		if p.activeWriters.Add(1) != 1 {
			p.t.Errorf("concurrent PTY input operation detected in Signal(%s)", sig)
		}
		defer p.activeWriters.Add(-1)
	}
	p.eventsMu.Lock()
	p.events = append(p.events, "signal:"+sig)
	p.eventsMu.Unlock()
	return p.fakePTY.Signal(sig)
}

func TestSignalInFlightRequiresBusyAndSIGKILLAlwaysEvicts(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	// 1. R6-3 / R7-1: When execMu is held by an idle operation (sess.busy() == false),
	// a concurrent signal must return ErrSessionInUse instead of delivering an
	// in-flight signal and falsely claiming a command is running. Also verify that
	// if writing the command payload to the PTY fails, activeSentinel is cleared and
	// the failed session is evicted.
	idleKey := Key{Scope: "stdio", NodeID: "n", SessionName: "idle-lock"}
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: idleKey, Dial: newFakePTYDialer(), Command: "pwd"}); err != nil {
		t.Fatal(err)
	}
	mgr.mu.Lock()
	idleSess := mgr.sessions[idleKey]
	mgr.mu.Unlock()
	idleSess.execMu.Lock()
	_, sigErr := mgr.Execute(context.Background(), ExecuteRequest{Key: idleKey, Dial: newFakePTYDialer(), Command: "SIGINT"})
	idleSess.execMu.Unlock()
	if !errors.Is(sigErr, ErrSessionInUse) {
		t.Fatalf("expected ErrSessionInUse when signaling non-busy locked session, got %v", sigErr)
	}

	writeFailKey := Key{Scope: "stdio", NodeID: "n", SessionName: "write-fail"}
	writeFailDial := func(context.Context) (ports.PTYSession, error) {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		sigCh := make(chan string, 8)
		closed := make(chan struct{})
		done := make(chan struct{})
		f := &fakePTY{
			inR:    inR,
			inW:    inW,
			outR:   outR,
			outW:   outW,
			sigCh:  sigCh,
			closed: closed,
			done:   done,
		}
		go func() {
			defer close(done)
			defer func() { _ = outW.Close() }()
			scanner := bufio.NewScanner(inR)
			if scanner.Scan() {
				// Accept the initial stty setup line, then close input so the
				// command payload write fails immediately.
				_ = inR.Close()
			}
			<-closed
		}()
		return f, nil
	}
	if _, err := mgr.Execute(context.Background(), ExecuteRequest{Key: writeFailKey, Dial: writeFailDial, Command: "echo fail"}); err == nil {
		t.Fatal("expected error when PTY write fails")
	}
	mgr.mu.Lock()
	_, stillStored := mgr.sessions[writeFailKey]
	mgr.mu.Unlock()
	if stillStored {
		t.Fatal("expected session to be evicted after PTY write failure")
	}

	// 2. R6-4: Even if a busy command emits its completion sentinel within the
	// settle window when SIGKILL is sent, SIGKILL must still forcibly close and
	// evict the session and return StateLost.
	killKey := Key{Scope: "stdio", NodeID: "n", SessionName: "sigkill-completes"}
	var killedPTY *fakePTY
	killDial := func(context.Context) (ports.PTYSession, error) {
		killedPTY = newFakePTY(func(in io.Reader, out io.Writer, sigCh <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				if tok, ok := sentinelToken(scanner.Text()); ok {
					<-sigCh
					_, _ = fmt.Fprintf(out, "last-words\n___MCP_DONE_%s_137___\n", tok)
				}
			}
		})
		return killedPTY, nil
	}
	res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: killKey, Dial: killDial, Command: "sleep 30", Timeout: 40 * time.Millisecond})
	if err != nil || res.State != StateRunning {
		t.Fatalf("expected StateRunning, got res=%+v err=%v", res, err)
	}
	killRes, err := mgr.Execute(context.Background(), ExecuteRequest{Key: killKey, Dial: killDial, Command: "SIGKILL"})
	if err != nil || killRes.State != StateLost || !strings.Contains(killRes.Output, "Session terminated by SIGKILL") {
		t.Fatalf("expected SIGKILL to return StateLost and evict session, got res=%+v err=%v", killRes, err)
	}
	select {
	case <-killedPTY.done:
	default:
		t.Fatal("expected PTY to be closed after SIGKILL")
	}
	mgr.mu.Lock()
	_, stillPresent := mgr.sessions[killKey]
	mgr.mu.Unlock()
	if stillPresent {
		t.Fatal("expected session to be removed from manager after SIGKILL")
	}
}

func TestSIGKILLClosesAndEvictsEvenWhenSignalFailsOrContextShort(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	// R11-2: Even when sendSignal runs with execMu unlocked (backgrounded
	// command or idle session), SIGKILL must still close and evict the session
	// immediately if pty.Signal("SIGKILL") returns an error or the caller's
	// context has a short deadline (< signalSettleWindow).
	sigErrKey := Key{Scope: "stdio", NodeID: "n", SessionName: "sigkill-signal-error"}
	var sigErrBase *fakePTY
	sigErrDial := func(context.Context) (ports.PTYSession, error) {
		sigErrBase = newFakePTY(func(in io.Reader, _ io.Writer, _ <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
			}
		})
		return &failingSignalPTY{PTYSession: sigErrBase, err: errors.New("signal request rejected")}, nil
	}
	res, err := mgr.Execute(context.Background(), ExecuteRequest{Key: sigErrKey, Dial: sigErrDial, Command: "sleep 30", Timeout: 40 * time.Millisecond})
	if err != nil || res.State != StateRunning {
		t.Fatalf("expected StateRunning before SIGKILL with failing Signal, got res=%+v err=%v", res, err)
	}
	shortCtx, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	killRes, err := mgr.Execute(shortCtx, ExecuteRequest{Key: sigErrKey, Dial: sigErrDial, Command: "SIGKILL"})
	if err != nil || killRes.State != StateLost || !strings.Contains(killRes.Output, "Session terminated by SIGKILL") {
		t.Fatalf("expected SIGKILL to ignore Signal error and immediately evict session, got res=%+v err=%v", killRes, err)
	}
	select {
	case <-sigErrBase.done:
	default:
		t.Fatal("expected underlying PTY to be closed after SIGKILL even when Signal fails")
	}
	mgr.mu.Lock()
	_, sigErrStillPresent := mgr.sessions[sigErrKey]
	mgr.mu.Unlock()
	if sigErrStillPresent {
		t.Fatal("expected session to be removed from manager after SIGKILL with failing Signal")
	}
}

type failingSignalPTY struct {
	ports.PTYSession
	err error
}

func (p *failingSignalPTY) Signal(string) error {
	return p.err
}

func TestSignalInFlightSerializesAfterPayloadWrite(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	// R8-1: Concurrent in-flight signal arriving while Execute is writing the
	// command payload must serialize behind inputMu: no concurrent Write/Signal
	// reentrancy on the PTY and the signal is delivered strictly after the payload
	// write finishes.
	serialKey := Key{Scope: "stdio", NodeID: "n", SessionName: "serial-input"}
	nrPTY := &nonReentrantPTY{
		t:            t,
		writeEntered: make(chan struct{}),
		releaseWrite: make(chan struct{}),
		fakePTY: newFakePTY(func(in io.Reader, out io.Writer, sigCh <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if tok, ok := sentinelToken(line); ok && !strings.Contains(line, "sleep") {
					if sig := <-sigCh; sig == "SIGINT" {
						_, _ = fmt.Fprintf(out, "interrupted\n___MCP_DONE_%s_130___\n", tok)
					}
				}
			}
		}),
	}
	serialDial := func(context.Context) (ports.PTYSession, error) {
		return nrPTY, nil
	}
	mgr.mu.Lock()
	now := mgr.now()
	initSess := &managedSession{
		pty:        nrPTY,
		generation: "g1",
		createdAt:  now,
		notifyCh:   make(chan struct{}, 1),
		readerDone: make(chan struct{}),
	}
	initSess.touch(now)
	go initSess.readLoop()
	mgr.sessions[serialKey] = initSess
	mgr.mu.Unlock()

	nrPTY.blockNext.Store(true)
	type execOutcome struct {
		res ExecuteResult
		err error
	}
	cmdDone := make(chan execOutcome, 1)
	go func() {
		r, e := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        serialKey,
			Generation: "g1",
			Dial:       serialDial,
			Command:    "sleep 60",
			Timeout:    time.Minute,
		})
		cmdDone <- execOutcome{res: r, err: e}
	}()
	<-nrPTY.writeEntered

	sigEntering := make(chan struct{})
	sigDone := make(chan execOutcome, 1)
	go func() {
		close(sigEntering)
		r, e := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        serialKey,
			Generation: "g1",
			Dial:       serialDial,
			Command:    "SIGINT",
		})
		sigDone <- execOutcome{res: r, err: e}
	}()
	<-sigEntering
	time.Sleep(20 * time.Millisecond)
	select {
	case out := <-sigDone:
		t.Fatalf("expected SIGINT to wait for payload Write to complete, got early %+v", out)
	default:
	}
	close(nrPTY.releaseWrite)

	sigOut := <-sigDone
	if sigOut.err != nil || sigOut.res.State != StateRunning {
		t.Fatalf("expected in-flight SIGINT to succeed after payload write, got %+v", sigOut)
	}
	cmdOut := <-cmdDone
	if cmdOut.err != nil || cmdOut.res.State != StateCompleted || cmdOut.res.ExitCode == nil || *cmdOut.res.ExitCode != 130 {
		t.Fatalf("expected interrupted command to complete with exit 130, got %+v", cmdOut)
	}
	nrPTY.eventsMu.Lock()
	events := append([]string(nil), nrPTY.events...)
	nrPTY.eventsMu.Unlock()
	if len(events) != 2 || events[0] != "write" || events[1] != "signal:SIGINT" {
		t.Fatalf("expected PTY input order [write signal:SIGINT], got %v", events)
	}

	// Also verify that if the blocked payload Write fails, Execute clears
	// activeSentinel before releasing inputMu so a concurrent signal waiting on
	// inputMu observes !busy() and never delivers a signal to the failed PTY.
	failKey := Key{Scope: "stdio", NodeID: "n", SessionName: "serial-input-fail"}
	failPTY := &nonReentrantPTY{
		t:                t,
		failBlockedWrite: true,
		writeEntered:     make(chan struct{}),
		releaseWrite:     make(chan struct{}),
		fakePTY:          newFakePTY(runStatefulFakeShell),
	}
	mgr.mu.Lock()
	failSess := &managedSession{
		pty:        failPTY,
		generation: "g1",
		createdAt:  now,
		notifyCh:   make(chan struct{}, 1),
		readerDone: make(chan struct{}),
	}
	failSess.touch(now)
	go failSess.readLoop()
	mgr.sessions[failKey] = failSess
	mgr.mu.Unlock()

	failPTY.blockNext.Store(true)
	failCmdDone := make(chan execOutcome, 1)
	go func() {
		r, e := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        failKey,
			Generation: "g1",
			Command:    "sleep 60",
			Timeout:    time.Minute,
		})
		failCmdDone <- execOutcome{res: r, err: e}
	}()
	<-failPTY.writeEntered

	failSigEntering := make(chan struct{})
	failSigDone := make(chan execOutcome, 1)
	go func() {
		close(failSigEntering)
		r, e := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        failKey,
			Generation: "g1",
			Command:    "SIGINT",
		})
		failSigDone <- execOutcome{res: r, err: e}
	}()
	<-failSigEntering
	time.Sleep(20 * time.Millisecond)
	close(failPTY.releaseWrite)

	if out := <-failCmdDone; out.err == nil {
		t.Fatalf("expected failed payload Write to return error, got %+v", out)
	}
	failSigOut := <-failSigDone
	if !errors.Is(failSigOut.err, ErrSessionInUse) && !errors.Is(failSigOut.err, ErrSessionNotFound) {
		t.Fatalf("expected concurrent SIGINT after failed Write to fail with ErrSessionInUse or ErrSessionNotFound, got %+v", failSigOut)
	}
	failPTY.eventsMu.Lock()
	failEvents := append([]string(nil), failPTY.events...)
	failPTY.eventsMu.Unlock()
	if len(failEvents) != 1 || failEvents[0] != "write" {
		t.Fatalf("expected failed Write not to be followed by pty.Signal, got %v", failEvents)
	}
}

func TestSIGTERMAndSIGKILLBypassBlockedPayloadWrite(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	// R9-1: While Execute is blocked inside pty.Write (holding inputMu),
	// concurrent SIGTERM and SIGKILL must NOT block on inputMu. SIGTERM must
	// deliver immediately while pty.Write is still blocked, and SIGKILL must
	// complete promptly with StateLost, close the PTY (unblocking pty.Write),
	// and evict the session.
	killKey := Key{Scope: "stdio", NodeID: "n", SessionName: "blocked-write-kill"}
	killPTY := &nonReentrantPTY{
		t:            t,
		writeEntered: make(chan struct{}),
		releaseWrite: make(chan struct{}),
		fakePTY:      newFakePTY(runStatefulFakeShell),
	}
	mgr.mu.Lock()
	now := mgr.now()
	killSess := &managedSession{
		pty:        killPTY,
		generation: "g1",
		createdAt:  now,
		notifyCh:   make(chan struct{}, 1),
		readerDone: make(chan struct{}),
	}
	killSess.touch(now)
	go killSess.readLoop()
	mgr.sessions[killKey] = killSess
	mgr.mu.Unlock()

	type execOutcome struct {
		res ExecuteResult
		err error
	}
	killPTY.blockNext.Store(true)
	blockedCmdDone := make(chan execOutcome, 1)
	go func() {
		r, e := mgr.Execute(context.Background(), ExecuteRequest{
			Key:        killKey,
			Generation: "g1",
			Command:    "sleep 60",
			Timeout:    time.Minute,
		})
		blockedCmdDone <- execOutcome{res: r, err: e}
	}()
	<-killPTY.writeEntered

	termRes, termErr := mgr.Execute(context.Background(), ExecuteRequest{
		Key:        killKey,
		Generation: "g1",
		Command:    "SIGTERM",
	})
	if termErr != nil || termRes.State != StateRunning {
		t.Fatalf("expected SIGTERM to complete immediately while pty.Write is blocked, got res=%+v err=%v", termRes, termErr)
	}

	killRes, killErr := mgr.Execute(context.Background(), ExecuteRequest{
		Key:        killKey,
		Generation: "g1",
		Command:    "SIGKILL",
	})
	if killErr != nil || killRes.State != StateLost {
		t.Fatalf("expected SIGKILL to complete immediately with StateLost while pty.Write is blocked, got res=%+v err=%v", killRes, killErr)
	}
	if out := <-blockedCmdDone; out.err == nil {
		t.Fatalf("expected blocked Execute to unblock with write error after SIGKILL closed PTY, got %+v", out)
	}
	mgr.mu.Lock()
	_, killStillPresent := mgr.sessions[killKey]
	mgr.mu.Unlock()
	if killStillPresent {
		t.Fatal("expected session to be evicted after SIGKILL during blocked pty.Write")
	}
	killPTY.eventsMu.Lock()
	killEvents := append([]string(nil), killPTY.events...)
	killPTY.eventsMu.Unlock()
	if len(killEvents) != 3 || killEvents[0] != "signal:SIGTERM" || killEvents[1] != "signal:SIGKILL" || killEvents[2] != "write-closed" {
		t.Fatalf("expected events [signal:SIGTERM signal:SIGKILL write-closed], got %v", killEvents)
	}
}

func TestManagerFishAndCshPersistentSessions(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	for _, tc := range []struct {
		name       string
		dialect    ssh.LaunchDialect
		initSubstr string
		statusVar  string
		cwd        string
		wantCd     string
	}{
		{
			name:       "fish",
			dialect:    ssh.LaunchFish,
			initSubstr: "function fish_prompt; end",
			statusVar:  "$status",
			cwd:        `/tmp/a'b\c`,
			wantCd:     `cd -- '/tmp/a\'b\\c'`,
		},
		{
			name:       "csh",
			dialect:    ssh.LaunchCsh,
			initSubstr: "unset edit; set prompt=''; set prompt2=''; set rprompt='';",
			statusVar:  "\"$status\"",
			cwd:        "/tmp/dir'bang!",
			wantCd:     `cd -- '/tmp/dir'\''bang\!'`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lines []string
			var linesMu sync.Mutex
			dial := func(context.Context) (ports.PTYSession, error) {
				return newFakePTY(func(in io.Reader, out io.Writer, _ <-chan string) {
					scanner := bufio.NewScanner(in)
					for scanner.Scan() {
						line := scanner.Text()
						linesMu.Lock()
						lines = append(lines, line)
						linesMu.Unlock()
						if tok, ok := sentinelToken(line); ok {
							_, _ = fmt.Fprintf(out, "ok\n___MCP_DONE_%s_0___\n", tok)
						}
					}
				}), nil
			}
			res, err := mgr.Execute(context.Background(), ExecuteRequest{
				Key:        Key{Scope: "stdio", NodeID: "n1", SessionName: tc.name},
				Generation: "gen-" + tc.name,
				Dialect:    tc.dialect,
				Dial:       dial,
				Command:    "echo ok",
				Cwd:        tc.cwd,
			})
			if err != nil || res.State != StateCompleted || res.ExitCode == nil || *res.ExitCode != 0 || res.Output != "ok" {
				t.Fatalf("unexpected result for %s: res=%+v err=%v", tc.name, res, err)
			}
			linesMu.Lock()
			recorded := strings.Join(lines, "\n")
			linesMu.Unlock()
			if !strings.Contains(recorded, tc.initSubstr) || !strings.Contains(recorded, tc.wantCd) || !strings.Contains(recorded, tc.statusVar) {
				t.Fatalf("dialect %s session lines missing expected fragments:\n%s", tc.name, recorded)
			}
		})
	}
}

func TestCleanTerminalOutputStripsEchoedSentinelCmd(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "echoed posix sentinel with prompt",
			raw:  "hello world\r\nroot@freebsd:~ # printf '\\n%s%s_%d___\\n' '___MCP_' 'DONE_abcdef123456' \"$?\"\r\n",
			want: "hello world",
		},
		{
			name: "echoed fish sentinel",
			raw:  "data\nprintf '\\n%s%s_%d___\\n' '___MCP_' 'DONE_123456789abc' $status\n",
			want: "data",
		},
		{
			name: "echoed csh sentinel with prompt",
			raw:  "test\nuser@host> printf '\\n%s%s_%d___\\n' '___MCP_' 'DONE_deadbeef0011' \"$status\"\n",
			want: "test",
		},
		{
			name: "echoed sentinel standalone",
			raw:  "printf '\\n%s%s_%d___\\n' '___MCP_' 'DONE_0123456789ab' \"$?\"\n",
			want: "",
		},
		{
			name: "multiple echoed sentinels interleaved",
			raw:  "out1\nprintf '\\n%s%s_%d___\\n' '___MCP_' 'DONE_111111111111' \"$?\"\nout2\nprintf '\\n%s%s_%d___\\n' '___MCP_' 'DONE_222222222222' $status\n",
			want: "out1\nout2",
		},
		{
			name: "user printf not stripped",
			raw:  "printf 'hello %s' world\n",
			want: "printf 'hello %s' world",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cleanTerminalOutput(tc.raw); got != tc.want {
				t.Fatalf("cleanTerminalOutput mismatch:\ngot:  %q\nwant: %q", got, tc.want)
			}
		})
	}
}

func TestSessionInitCommandDialects(t *testing.T) {
	posix := sessionInitCommand(ssh.LaunchPOSIX)
	for _, expected := range []string{
		"set +o emacs 2>/dev/null",
		"set +o vi 2>/dev/null",
		"unsetopt zle PROMPT_SP 2>/dev/null",
		"PS1=''; PS2=''; PROMPT=''; PROMPT2=''",
		"stty -echo noflsh 2>/dev/null",
		"export TERM=dumb NO_COLOR=1 DEBIAN_FRONTEND=noninteractive GIT_TERMINAL_PROMPT=0 CI=true",
	} {
		if !strings.Contains(posix, expected) {
			t.Errorf("posix init command missing %q; got: %q", expected, posix)
		}
	}

	csh := sessionInitCommand(ssh.LaunchCsh)
	for _, expected := range []string{
		"unset edit",
		"set prompt=''",
		"set prompt2=''",
		"set rprompt=''",
		"stty -echo noflsh >& /dev/null",
		"setenv TERM dumb",
	} {
		if !strings.Contains(csh, expected) {
			t.Errorf("csh init command missing %q; got: %q", expected, csh)
		}
	}

	fish := sessionInitCommand(ssh.LaunchFish)
	for _, expected := range []string{
		"stty -echo noflsh 2>/dev/null",
		"function fish_prompt; end",
		"set -gx TERM dumb",
	} {
		if !strings.Contains(fish, expected) {
			t.Errorf("fish init command missing %q; got: %q", expected, fish)
		}
	}
}

func TestSendSignalActiveVsIdleWindow(t *testing.T) {
	defer goleak.VerifyNone(t)
	mgr, shutdown := newTestManager(t)
	defer shutdown()

	// 1. Idle session signal completes quickly via settleIdleSignal (100ms)
	idleKey := Key{Scope: "stdio", NodeID: "n1", SessionName: "idle-sig"}
	dialIdle := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, out io.Writer, _ <-chan string) {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				line := scanner.Text()
				if tok, ok := sentinelToken(line); ok {
					_, _ = fmt.Fprintf(out, "ready\n___MCP_DONE_%s_0___\n", tok)
				}
			}
		}), nil
	}
	// Initial command to establish session
	initRes, err := mgr.Execute(context.Background(), ExecuteRequest{
		Key:     idleKey,
		Dial:    dialIdle,
		Command: "echo ready",
	})
	if err != nil || initRes.State != StateCompleted {
		t.Fatalf("expected completed init, got res=%+v err=%v", initRes, err)
	}

	start := time.Now()
	sigRes, err := mgr.Execute(context.Background(), ExecuteRequest{
		Key:     idleKey,
		Dial:    dialIdle,
		Command: "SIGINT",
	})
	elapsed := time.Since(start)
	if err != nil || sigRes.State != StateIdle {
		t.Fatalf("expected idle SIGINT to return StateIdle, got res=%+v err=%v", sigRes, err)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("idle SIGINT took too long: %v (expected ~100ms)", elapsed)
	}

	// 2. Active command signal waits for sentinel and completes
	activeKey := Key{Scope: "stdio", NodeID: "n1", SessionName: "active-sig"}
	sigCh := make(chan string, 1)
	dialActive := func(context.Context) (ports.PTYSession, error) {
		return newFakePTY(func(in io.Reader, out io.Writer, sigs <-chan string) {
			var activeToken string
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				line := scanner.Text()
				if tok, ok := sentinelToken(line); ok {
					activeToken = tok
					// Don't respond yet, wait for signal
					select {
					case s := <-sigs:
						sigCh <- s
						// Exit with code 130 on SIGINT after short delay
						time.Sleep(50 * time.Millisecond)
						_, _ = fmt.Fprintf(out, "\n___MCP_DONE_%s_130___\n", activeToken)
					case <-time.After(5 * time.Second):
					}
				}
			}
		}), nil
	}

	// Run long-running command with short timeout so it enters StateRunning
	runRes, err := mgr.Execute(context.Background(), ExecuteRequest{
		Key:     activeKey,
		Dial:    dialActive,
		Command: "sleep 10",
		Timeout: 20 * time.Millisecond,
	})
	if err != nil || runRes.State != StateRunning {
		t.Fatalf("expected StateRunning, got res=%+v err=%v", runRes, err)
	}

	// Send SIGINT to active session
	sigActiveRes, err := mgr.Execute(context.Background(), ExecuteRequest{
		Key:     activeKey,
		Dial:    dialActive,
		Command: "SIGINT",
	})
	if err != nil || sigActiveRes.State != StateCompleted {
		t.Fatalf("expected StateCompleted after active SIGINT, got res=%+v err=%v", sigActiveRes, err)
	}
	if sigActiveRes.ExitCode == nil || *sigActiveRes.ExitCode != 130 {
		t.Fatalf("expected exit code 130, got %v", sigActiveRes.ExitCode)
	}
}
