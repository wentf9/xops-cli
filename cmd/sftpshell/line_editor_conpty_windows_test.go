//go:build windows && integration

package sftpshell

import (
	"context"
	"errors"
	"fmt"
	"github.com/wentf9/xops-cli/internal/terminal"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/conpty"
	"golang.org/x/sys/windows"
)

const conPTYHelperEnvironment = "XOPS_SFTP_CONPTY_HELPER"

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

	waitForConPTYOutput(t, harness.output, "HOST_KEY_TRUST (yes/no)? ")
	writeConPTYInput(t, harness.pty, "yes")
	waitForConPTYOutput(t, harness.output, "HOST_KEY_TRUST (yes/no)? yes")
	writeConPTYInput(t, harness.pty, "\r")
	waitForConPTYOutput(t, harness.output, "HOST_KEY_ACCEPTED")

	waitForConPTYOutput(t, harness.output, "SFTP_PROMPT_1> ")
	harness.resize(72, 24)
	writeConPTYInput(t, harness.pty, "pwd")
	waitForConPTYOutput(t, harness.output, "SFTP_PROMPT_1> pwd")
	writeConPTYInput(t, harness.pty, "\r")
	waitForConPTYOutput(t, harness.output, "HISTORY_READY")
	waitForConPTYOutput(t, harness.output, "SFTP_HISTORY> ")
	writeConPTYInput(t, harness.pty, "\x1b[A")
	waitForConPTYOutput(t, harness.output, "SFTP_HISTORY> pwd")
	writeConPTYInput(t, harness.pty, "\r")
	for i, keys := range []string{"\x1b[3~pwd\r", "abc\x01\x1b[3~\r", "\x1b[200~ls\nexit\x1b[201~\r", "\x03", "\x04"} {
		waitForConPTYOutput(t, harness.output, fmt.Sprintf("SFTP_KEYS_%d>", i))
		writeConPTYInput(t, harness.pty, keys)
	}
	waitForConPTYOutput(t, harness.output, "SFTP_AHEAD_0>")
	writeConPTYInput(t, harness.pty, "pwd\rhelp\r")
	waitForConPTYOutput(t, harness.output, "SFTP_SEARCH>")
	writeConPTYInput(t, harness.pty, "\x12\x1b[200~needle\x1b[201~")
	waitForConPTYOutput(t, harness.output, "SFTP_SEARCH> get needle")
	writeConPTYInput(t, harness.pty, "\r\r")
	waitForConPTYOutput(t, harness.output, "lcp: overwrite local")
	writeConPTYInput(t, harness.pty, "\x03")
	waitForConPTYOutput(t, harness.output, "SFTP_PAGES>")
	writeConPTYInput(t, harness.pty, "put bin\t")
	waitForConPTYOutput(t, harness.output, "Page 1/3, 80 items")
	for _, step := range []struct{ keys, selected, page string }{
		{"\x1b[6~", "bin036\\", "2/3"},
		{"\x1b[6~", "bin072\\", "3/3"},
		{"\x1b[5~", "bin036\\", "2/3"},
		{"\x1b[Z", "bin035\\", "1/3"},
		{"\t", "bin036\\", "2/3"},
	} {
		writeConPTYInput(t, harness.pty, step.keys)
		waitForConPTYOutput(t, harness.output, "SFTP_PAGES> put "+step.selected)
		waitForConPTYOutput(t, harness.output, "Page "+step.page)
	}
	writeConPTYInput(t, harness.pty, "\r\t")
	waitForConPTYOutput(t, harness.output, "SFTP_PAGES> put bin036\\tool.txt")
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
		output:   newConPTYOutput(100, 30),
		readDone: make(chan error, 1),
	}
	t.Cleanup(harness.cleanup)
	return harness
}

// Record the resize before ConPTY can emit a redraw. Some Windows builds
// do not include an in-band size report in the output stream.
func (h *conPTYHarness) resize(cols, rows int) {
	h.t.Helper()
	h.output.Resize(cols, rows)
	if err := h.pty.Resize(cols, rows); err != nil {
		h.t.Fatal(err)
	}
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
	if err := i18n.Init("en"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	answer, err := terminal.NewPrompter(os.Stdin, os.Stdout).ReadLine(ctx, "HOST_KEY_TRUST (yes/no)? ")
	if err != nil || answer != "yes" {
		t.Fatalf("host key confirmation: %q, %v", answer, err)
	}
	if _, err := fmt.Fprint(os.Stdout, "HOST_KEY_ACCEPTED\r\n"); err != nil {
		t.Fatal(err)
	}

	shell := &Shell{
		cwd:      "/",
		localCwd: t.TempDir(),
		stdin:    os.Stdin,
		stdout:   os.Stdout,
		stderr:   os.Stderr,
	}
	exerciseConPTYLineEditor(t, shell)
	exerciseConPTYInteractiveCancellation(t)
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
	inputHandle := windows.Handle(os.Stdin.Fd())
	var originalMode uint32
	if err := windows.GetConsoleMode(inputHandle, &originalMode); err != nil {
		t.Fatal(err)
	}
	checkMode := func() {
		t.Helper()
		var current uint32
		if err := windows.GetConsoleMode(inputHandle, &current); err != nil {
			t.Fatal(err)
		}
		if current != originalMode {
			t.Fatalf("console mode = %#x, want %#x", current, originalMode)
		}
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
	checkMode()
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
	exerciseConPTYEditingKeys(t, editor, checkMode)
	for i := range 80 {
		if err := os.Mkdir(filepath.Join(shell.localCwd, fmt.Sprintf("bin%03d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(shell.localCwd, "bin036", "tool.txt"), []byte("test"))
	completed, completeErr := editor.Prompt(t.Context(), "SFTP_PAGES> ")
	if completeErr != nil || completed != "put "+filepath.Join("bin036", "tool.txt") {
		t.Fatalf("paged completion=%q, error=%v", completed, completeErr)
	}
	checkMode()
	cancelCtx, cancelPrompt := context.WithTimeout(t.Context(), 150*time.Millisecond)
	_, cancelErr := editor.Prompt(cancelCtx, "SFTP_CANCEL> ")
	cancelPrompt()
	if !errors.Is(cancelErr, context.DeadlineExceeded) {
		t.Fatalf("canceled prompt = %v", cancelErr)
	}
	checkMode()
	if err := editor.Close(); err != nil {
		t.Fatalf("close line editor failed: %v", err)
	}
	closed = true
}

func exerciseConPTYEditingKeys(t *testing.T, editor *lineEditor, checkMode func()) {
	t.Helper()
	for i, expected := range []struct {
		line string
		err  error
	}{
		{"pwd", nil}, {"bc", nil}, {"ls exit", nil}, {"", ErrPromptInterrupted}, {"", io.EOF},
	} {
		line, err := editor.Prompt(t.Context(), fmt.Sprintf("SFTP_KEYS_%d> ", i))
		if line != expected.line || !errors.Is(err, expected.err) {
			t.Fatalf("key round %d: %q, %v", i, line, err)
		}
		checkMode()
	}
	for i, want := range []string{"pwd", "help"} {
		line, err := editor.Prompt(t.Context(), fmt.Sprintf("SFTP_AHEAD_%d> ", i))
		if err != nil || line != want {
			t.Fatalf("type-ahead %d=%q, err=%v", i, line, err)
		}
		checkMode()
	}
	for _, command := range []string{"get needle", "rm other"} {
		if err := editor.AppendHistory(command); err != nil {
			t.Fatal(err)
		}
	}
	searched, searchErr := editor.Prompt(t.Context(), "SFTP_SEARCH> ")
	if searchErr != nil || searched != "get needle" {
		t.Fatalf("pasted search=%q, error=%v", searched, searchErr)
	}
	checkMode()
	exerciseConPTYConfirmationInterrupt(t, editor)
	checkMode()
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

func waitForConPTYOutput(t *testing.T, output *conPTYOutput, expected string) {
	t.Helper()
	cleanExpected := strings.TrimRight(expected, " ")
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		raw := output.String()
		stripped := stripANSI(raw)
		output.mu.Lock()
		stripped += "\n" + output.screen
		screenErr := output.screenErr
		output.mu.Unlock()
		if screenErr != nil {
			t.Fatal(screenErr)
		}
		if strings.Contains(stripped, cleanExpected) {
			return
		}
		select {
		case <-output.updated:
		case <-timer.C:
			t.Fatalf("ConPTY output did not contain %q; stripped output: %q; raw output: %q", expected, stripped, raw)
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

// Returning from an idle interactive command must leave the first character of
// the following SFTP prompt for the new line editor, even after repeated handoffs.
func exerciseConPTYInteractiveCancellation(t *testing.T) {
	t.Helper()
	for range 3 {
		input, err := terminal.DuplicateInteractiveInput(os.Stdin)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { var b [1]byte; _, err := input.Read(b[:]); done <- err }()
		if err := input.Interrupt(); err != nil {
			t.Error(err)
		}
		if err := input.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, io.EOF) {
			t.Fatalf("canceled interactive read: %v", err)
		}
	}
}

func exerciseConPTYConfirmationInterrupt(t *testing.T, editor *lineEditor) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"src", "dst"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(dir, "src", "a"), []byte("a"))
	writeTestFile(t, filepath.Join(dir, "src", "b"), []byte("b"))
	writeTestFile(t, filepath.Join(dir, "dst", "a"), []byte("original"))
	shell := &Shell{localCwd: dir, stdout: os.Stdout, stderr: os.Stderr, line: editor}
	err := shell.handleLocalCp(t.Context(), []string{"src/*", "dst"})
	if !errors.Is(err, ErrPromptInterrupted) {
		t.Fatalf("overwrite interruption=%v", err)
	}
	if err := shell.reportCommandError(err); err != nil {
		t.Fatalf("REPL cannot resume: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dst", "b")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("later file was copied: %v", err)
	}
	if got := string(readTestFile(t, filepath.Join(dir, "dst", "a"))); got != "original" {
		t.Fatal("first file was overwritten")
	}
}
