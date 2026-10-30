package ssh

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

var errUnboundPrivilegeOutput = errors.New("privilege output bypassed ContextWriter")

type privilegeContextSink struct {
	raw, aware atomic.Int32
	entered    chan struct{}
	once       sync.Once
	block      bool
}

func (w *privilegeContextSink) Write([]byte) (int, error) {
	w.raw.Add(1)
	return 0, errUnboundPrivilegeOutput
}

func (w *privilegeContextSink) WriteContext(ctx context.Context, data []byte) (int, error) {
	w.aware.Add(1)
	if w.entered != nil {
		w.once.Do(func() { close(w.entered) })
	}
	if w.block {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return len(data), ctx.Err()
}

func TestPasswordSudoOutputUsesContextBinding(t *testing.T) {
	for _, script := range []bool{false, true} {
		t.Run(map[bool]string{false: "command", true: "script"}[script], func(t *testing.T) {
			setTestHome(t)
			addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", status: 7})
			client := exchangeTestClient(t, addr, SudoModeSudo, &recoveryTestUI{values: []string{"wrong", "valid"}}, &testRecorder{})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			sink := &privilegeContextSink{}
			var mu sync.Mutex
			options := []RunOption{WithStream(NewLockedWriter(&mu, sink), "[node] ")}
			execution := &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX}
			var err error
			if script {
				_, err = client.RunScriptWithSudoExecution(ctx, "echo chosen\n", execution, options...)
			} else {
				_, err = client.RunWithSudoExecution(ctx, "chosen", execution, options...)
			}
			var exitErr *cryptoSSH.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 7 {
				t.Fatalf("exit status lost: %v", err)
			}
			if sink.raw.Load() != 0 || sink.aware.Load() == 0 || evidence.commands.Load() != 1 {
				t.Fatalf("output unbound or command replayed: raw=%d aware=%d commands=%d error=%v", sink.raw.Load(), sink.aware.Load(), evidence.commands.Load(), err)
			}
		})
	}
}

func TestPasswordSudoBlockedStreamCancellation(t *testing.T) {
	for _, missingExit := range []bool{false, true} {
		t.Run(map[bool]string{false: "exit-status", true: "missing-exit"}[missingExit], func(t *testing.T) {
			setTestHome(t)
			addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", missingExit: missingExit})
			client := exchangeTestClient(t, addr, SudoModeSudo, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			sink := &privilegeContextSink{entered: make(chan struct{}), block: true}
			done, joined := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(joined)
				_, err := client.RunWithSudoExecution(ctx, "chosen", &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX}, WithStream(sink, ""))
				done <- err
			}()
			defer func() { cancel(); <-joined }()
			select {
			case <-sink.entered:
			case err := <-done:
				t.Fatalf("stream ended before context-aware write: %v", err)
			case <-ctx.Done():
				t.Fatal("stream did not start")
			}
			cancel()
			err := <-done
			var outputErr *OutputError
			if !errors.Is(err, context.Canceled) || !errors.As(err, &outputErr) || outputErr.Target != sink {
				t.Fatalf("cancellation or sink identity lost: %v", err)
			}
			if got := countSinkOutputErrors(err, sink); got != 1 {
				t.Fatalf("sink OutputError count = %d, want 1 in %v", got, err)
			}
			if evidence.commands.Load() != 1 || sink.raw.Load() != 0 {
				t.Fatal("command replayed or raw Write used")
			}
		})
	}
}

func countSinkOutputErrors(err error, target any) int {
	if err == nil {
		return 0
	}
	if outputErr, ok := err.(*OutputError); ok && outputErr.Target == target { //nolint:errorlint // intentionally counting distinct *OutputError nodes in the unwrap tree
		return 1
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		total := 0
		for _, child := range joined.Unwrap() {
			total += countSinkOutputErrors(child, target)
		}
		return total
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		return countSinkOutputErrors(unwrapped, target)
	}
	return 0
}

func TestPasswordSudoFileFailureRetainsSink(t *testing.T) {
	setTestHome(t)
	file, err := os.CreateTemp(t.TempDir(), "output-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid"})
	client := exchangeTestClient(t, addr, SudoModeSudo, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = client.RunWithSudoExecution(ctx, "chosen", &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX}, WithOutFile(file))
	var outputErr *OutputError
	if !errors.As(err, &outputErr) || !outputErr.TargetsFile(file) || evidence.commands.Load() != 1 {
		t.Fatalf("file error lost or replayed: %v", err)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatalf("borrowed file closed: %v", err)
	}
}
