package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
)

const w11aHostileSeq = "\x1b]52;c;aGVsbG8=\x07\x1b[31m\x7f\u009b2J\u2028\u2029"

var w11aForbiddenControls = []string{"\x1b", "\x07", "\x7f", "\u009b", "\u2028", "\u2029", "\r"}

func assertW11aNoRawControls(t *testing.T, label, text string) {
	t.Helper()
	for _, bad := range w11aForbiddenControls {
		if strings.Contains(text, bad) {
			t.Fatalf("%s leaked raw control sequence %q in %q", label, bad, text)
		}
	}
}

// TestP7W11a_AB11L2_SanitizesPutSingleLocalAndStderrErrors verifies AB11-L2:
//   - putSingle sanitizes local (and remote) paths with sanitizeDisplayText
//     before writing the upload banner to stdout.
//   - reportCommandError sanitizes err.Error() via sanitizeDisplayText before
//     writing to stderr in interactive mode.
//   - Shell.Run sanitizes reconnect error text ("restore sftp client failed")
//     via sanitizeDisplayText before writing to stderr in interactive mode.
func TestP7W11a_AB11L2_SanitizesPutSingleLocalAndStderrErrors(t *testing.T) {
	t.Run("putSingle_sanitizes_local_path_on_stdout_and_error", testP7W11aPutSingleSanitization)
	t.Run("reportCommandError_sanitizes_stderr_output", testP7W11aReportCommandErrorSanitization)
	t.Run("run_reconnect_error_sanitizes_stderr_output", testP7W11aRunReconnectSanitization)
}

func testP7W11aPutSingleSanitization(t *testing.T) {
	h := newW8aShellTrackingHandler()
	localDir := t.TempDir()
	sh := newP7W7bShellWithHandlers(t, h.handlers(), "/", localDir)
	var stdout, stderr bytes.Buffer
	sh.stdout = &stdout
	sh.stderr = &stderr
	sh.batch = false

	hostileLocal := filepath.Join(localDir, "evil"+w11aHostileSeq+"file.txt")
	err := sh.putSingle(t.Context(), hostileLocal, "/remote/clean.txt")
	if stdout.Len() == 0 {
		t.Fatal("putSingle emitted empty stdout; expected sanitized uploading banner")
	}
	assertW11aNoRawControls(t, "putSingle stdout", stdout.String())
	if !strings.Contains(stdout.String(), "evil") || !strings.Contains(stdout.String(), "/remote/clean.txt") {
		t.Fatalf("putSingle stdout missing readable path portions: %q", stdout.String())
	}
	if err != nil {
		if reportErr := sh.reportCommandError(err); reportErr != nil {
			t.Fatalf("reportCommandError: %v", reportErr)
		}
		assertW11aNoRawControls(t, "putSingle reportCommandError stderr", stderr.String())
	}

	if runtime.GOOS == "windows" {
		return
	}
	stdout.Reset()
	realHostile := filepath.Join(localDir, "real\x1b[31m\x07ok.txt")
	if writeErr := os.WriteFile(realHostile, []byte("ok"), 0o600); writeErr == nil {
		_ = sh.putSingle(t.Context(), realHostile, "/remote/real.txt")
		bannerLine, _, _ := strings.Cut(stdout.String(), "\n")
		assertW11aNoRawControls(t, "putSingle real file banner", bannerLine)
		if !strings.Contains(bannerLine, "real") || !strings.Contains(bannerLine, "ok.txt") {
			t.Fatalf("putSingle real file banner lost readable text: %q", bannerLine)
		}
	}
}

func testP7W11aReportCommandErrorSanitization(t *testing.T) {
	var stdout, stderr bytes.Buffer
	sh := &Shell{
		stdout: &stdout,
		stderr: &stderr,
		batch:  false,
	}
	hostileErr := fmt.Errorf("remote failure: %sdetail\ninjected-line", w11aHostileSeq)
	if err := sh.reportCommandError(hostileErr); err != nil {
		t.Fatalf("reportCommandError returned unexpected error: %v", err)
	}
	got := stderr.String()
	if !strings.HasSuffix(got, "\n") {
		t.Fatalf("reportCommandError output missing trailing newline: %q", got)
	}
	body := strings.TrimSuffix(got, "\n")
	assertW11aNoRawControls(t, "reportCommandError stderr", body)
	if strings.Contains(body, "\n") {
		t.Fatalf("reportCommandError leaked embedded newline into stderr: %q", got)
	}
	if !strings.Contains(body, "remote failure:") || !strings.Contains(body, "detail") {
		t.Fatalf("reportCommandError lost readable message: %q", got)
	}
}

func testP7W11aRunReconnectSanitization(t *testing.T) {
	var stdout, stderr bytes.Buffer
	sh := &Shell{
		cwd:           "/",
		localCwd:      t.TempDir(),
		stdin:         io.NopCloser(strings.NewReader("ls\rexit\r")),
		stdout:        &stdout,
		stderr:        &stderr,
		batch:         false,
		sshClient:     &ssh.Client{},
		clientInvalid: true,
		newClientFn: func(context.Context, *ssh.Client, ...sftp.Option) (*sftp.Client, error) {
			return nil, fmt.Errorf("subsystem banner: %sbad-server\ninjected", w11aHostileSeq)
		},
	}
	if err := sh.Run(t.Context()); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Shell.Run returned unexpected error: %v", err)
	}
	got := stderr.String()
	if !strings.Contains(got, "restore sftp client failed:") {
		t.Fatalf("expected reconnect diagnostic on stderr, got: %q", got)
	}
	assertW11aNoRawControls(t, "Run reconnect stderr", got)
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.HasPrefix(line, "injected") {
			t.Fatalf("Run reconnect stderr leaked forged line: %q", got)
		}
	}
	if !strings.Contains(got, "bad-server") {
		t.Fatalf("Run reconnect stderr lost readable detail: %q", got)
	}
}
