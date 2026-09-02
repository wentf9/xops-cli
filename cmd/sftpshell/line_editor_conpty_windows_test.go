//go:build windows && integration

package sftpshell

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/conpty"
	"golang.org/x/sys/windows"
)

const conPTYHelperEnvironment = "XOPS_SFTP_CONPTY_HELPER"

type conPTYOutput struct {
	mu      sync.Mutex
	data    []byte
	updated chan struct{}
}

type conPTYHarness struct {
	t               *testing.T
	pty             *conpty.ConPty
	process         *os.Process
	processFinished bool
	output          *conPTYOutput
	readDone        chan error
	readerStarted   bool
	readerFinished  bool
}

func TestWindowsLineEditorConPTY(t *testing.T) {
	if os.Getenv(conPTYHelperEnvironment) == "1" {
		runWindowsLineEditorConPTYHelper(t)
		return
	}

	harness := newConPTYHarness(t)
	harness.start()

	waitForConPTYOutput(t, harness.output, "SFTP_PROMPT_1> ")
	writeConPTYInput(t, harness.pty, "pwd")
	waitForConPTYOutput(t, harness.output, "SFTP_PROMPT_1> pwd")
	writeConPTYInput(t, harness.pty, "\r")
	waitForConPTYOutput(t, harness.output, "HISTORY_READY")
	waitForConPTYOutput(t, harness.output, "SFTP_HISTORY> ")
	writeConPTYInput(t, harness.pty, "\x1b[A")
	waitForConPTYOutput(t, harness.output, "SFTP_HISTORY> pwd")
	writeConPTYInput(t, harness.pty, "\r")
	waitForConPTYOutput(t, harness.output, "HANDOFF_EDITOR_CLOSED")
	waitForConPTYOutput(t, harness.output, "sftp:/> ")
	writeConPTYInput(t, harness.pty, "exit")
	waitForConPTYOutput(t, harness.output, "sftp:/> exit")
	writeConPTYInput(t, harness.pty, "\r")
	waitForConPTYOutput(t, harness.output, "SHELL_EXITED")

	waitCtx, cancelWait := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelWait()
	processState, err := waitForConPTYProcess(waitCtx, harness.process)
	harness.processFinished = processState != nil
	if err != nil {
		t.Fatalf("wait for ConPTY helper failed: %v; output: %q", err, harness.output.String())
	}
	if processState == nil || !processState.Success() {
		t.Fatalf("ConPTY helper exited unsuccessfully; output: %q", harness.output.String())
	}
	if strings.Contains(harness.output.String(), "The operation completed successfully") {
		t.Fatalf("ConPTY output contains a false close error: %q", harness.output.String())
	}

	if err := harness.pty.Close(); err != nil {
		t.Fatalf("close ConPTY failed: %v", err)
	}
	select {
	case readErr := <-harness.readDone:
		harness.readerFinished = true
		if readErr == nil {
			t.Fatal("ConPTY output reader exited without an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ConPTY output reader did not exit after close")
	}
}

func newConPTYHarness(t *testing.T) *conPTYHarness {
	t.Helper()
	pty, err := conpty.New(100, 30, 0)
	if err != nil {
		t.Fatalf("create ConPTY failed: %v", err)
	}
	harness := &conPTYHarness{
		t:        t,
		pty:      pty,
		output:   &conPTYOutput{updated: make(chan struct{}, 1)},
		readDone: make(chan error, 1),
	}
	t.Cleanup(harness.cleanup)
	return harness
}

func (h *conPTYHarness) start() {
	h.t.Helper()
	helperArgs := []string{os.Args[0], "-test.run=^TestWindowsLineEditorConPTY$"}
	helperEnv := append(os.Environ(), conPTYHelperEnvironment+"=1")
	pid, processHandle, err := h.pty.Spawn(
		os.Args[0],
		helperArgs,
		&syscall.ProcAttr{Env: helperEnv},
	)
	if err != nil {
		h.t.Fatalf("start ConPTY helper failed: %v", err)
	}
	h.process, err = os.FindProcess(pid)
	if err != nil {
		terminateErr := windows.TerminateProcess(windows.Handle(processHandle), 1)
		closeErr := windows.CloseHandle(windows.Handle(processHandle))
		h.t.Fatalf(
			"find ConPTY helper process failed: %v; terminate process failed: %v; close process handle failed: %v",
			err,
			terminateErr,
			closeErr,
		)
	}
	if err := windows.CloseHandle(windows.Handle(processHandle)); err != nil {
		h.t.Fatalf("close spawned ConPTY process handle failed: %v", err)
	}
	h.readerStarted = true
	go readConPTYOutput(h.pty, h.output, h.readDone)
}

func (h *conPTYHarness) cleanup() {
	if h.process != nil && !h.processFinished {
		if killErr := h.process.Kill(); killErr != nil {
			h.t.Logf("kill ConPTY helper failed: %v", killErr)
		}
		if _, waitErr := h.process.Wait(); waitErr != nil {
			h.t.Logf("wait for killed ConPTY helper failed: %v", waitErr)
		}
	}
	if closeErr := h.pty.Close(); closeErr != nil {
		h.t.Logf("close ConPTY failed: %v", closeErr)
	}
	if !h.readerStarted || h.readerFinished {
		return
	}
	select {
	case <-h.readDone:
	case <-time.After(2 * time.Second):
		h.t.Errorf("ConPTY output reader did not exit during cleanup")
	}
}

func waitForConPTYProcess(ctx context.Context, process *os.Process) (*os.ProcessState, error) {
	type result struct {
		state *os.ProcessState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		state, err := process.Wait()
		done <- result{state: state, err: err}
	}()
	select {
	case waitResult := <-done:
		return waitResult.state, waitResult.err
	case <-ctx.Done():
		killErr := process.Kill()
		waitResult := <-done
		waitErr := fmt.Errorf("wait for ConPTY helper canceled: %w", ctx.Err())
		if killErr != nil {
			waitErr = fmt.Errorf("%w; kill ConPTY helper failed: %w", waitErr, killErr)
		}
		if waitResult.err != nil {
			waitErr = fmt.Errorf("%w; wait after killing ConPTY helper failed: %w", waitErr, waitResult.err)
		}
		return waitResult.state, waitErr
	}
}

func runWindowsLineEditorConPTYHelper(t *testing.T) {
	shell := &Shell{
		cwd:      "/",
		localCwd: t.TempDir(),
		stdin:    os.Stdin,
		stdout:   os.Stdout,
		stderr:   os.Stderr,
	}
	exerciseConPTYLineEditor(t, shell)
	if _, err := fmt.Fprint(os.Stdout, "\r\nHANDOFF_EDITOR_CLOSED\r\n"); err != nil {
		t.Fatalf("write handoff close marker failed: %v", err)
	}

	if err := shell.Run(t.Context()); err != nil {
		t.Fatalf("run SFTP shell through exit failed: %v", err)
	}
	if _, err := fmt.Fprint(os.Stdout, "\r\nSHELL_EXITED\r\n"); err != nil {
		t.Fatalf("write shell exit marker failed: %v", err)
	}
}

func exerciseConPTYLineEditor(t *testing.T, shell *Shell) {
	t.Helper()
	editor, err := newLineEditor(t.Context(), os.Stdin, os.Stdout, os.Stderr, "", shell)
	if err != nil {
		t.Fatalf("create line editor failed: %v", err)
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		if closeErr := editor.Close(); closeErr != nil {
			t.Errorf("close line editor after prompt failure failed: %v", closeErr)
		}
	}()
	line, promptErr := editor.Prompt(t.Context(), "SFTP_PROMPT_1> ")
	if promptErr != nil {
		t.Fatalf("read prompt failed: %v", promptErr)
	}
	if line != "pwd" {
		t.Fatalf("first prompt result = %q, want pwd", line)
	}
	if err := editor.AppendHistory(line); err != nil {
		t.Fatalf("append prompt history failed: %v", err)
	}
	if _, err := fmt.Fprint(os.Stdout, "\r\nHISTORY_READY\r\n"); err != nil {
		t.Fatalf("write history marker failed: %v", err)
	}
	historyLine, promptErr := editor.Prompt(t.Context(), "SFTP_HISTORY> ")
	if promptErr != nil {
		t.Fatalf("read history prompt failed: %v", promptErr)
	}
	if historyLine != line {
		t.Fatalf("history prompt result = %q, want %q", historyLine, line)
	}
	if err := editor.Close(); err != nil {
		t.Fatalf("close line editor failed: %v", err)
	}
	closed = true
}

func readConPTYOutput(reader io.Reader, output *conPTYOutput, done chan<- error) {
	buffer := make([]byte, 1024)
	for {
		read, err := reader.Read(buffer)
		if read > 0 {
			output.Append(buffer[:read])
		}
		if err != nil {
			done <- err
			return
		}
	}
}

func (o *conPTYOutput) Append(data []byte) {
	o.mu.Lock()
	o.data = append(o.data, data...)
	o.mu.Unlock()
	select {
	case o.updated <- struct{}{}:
	default:
	}
}

func (o *conPTYOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.data)
}

func waitForConPTYOutput(t *testing.T, output *conPTYOutput, expected string) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		if strings.Contains(output.String(), expected) {
			return
		}
		select {
		case <-output.updated:
		case <-timer.C:
			t.Fatalf("ConPTY output did not contain %q; output: %q", expected, output.String())
		}
	}
}

func writeConPTYInput(t *testing.T, writer io.Writer, input string) {
	t.Helper()
	written, err := io.WriteString(writer, input)
	if err != nil {
		t.Fatalf("write ConPTY input failed: %v", err)
	}
	if written != len(input) {
		t.Fatalf("ConPTY input bytes written = %d, want %d", written, len(input))
	}
}
