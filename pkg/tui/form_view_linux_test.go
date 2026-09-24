//go:build linux

package tui

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"charm.land/huh/v2"
	"github.com/creack/pty"
	"github.com/hinshun/vt10x"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"go.uber.org/goleak"
)

type formScreenWriter struct {
	mu         sync.Mutex
	raw        strings.Builder
	cols, rows int
}

func (w *formScreenWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.raw.Write(p)
}

func (w *formScreenWriter) wait(t *testing.T, ctx context.Context, want string) {
	t.Helper()
	// Ignore protocol extensions unsupported by vt10x, preserving cursor
	// movement and erasure so assertions check visible cells, not output history.
	extensions := regexp.MustCompile(`\x1b\[[><=][0-9;:]*[um]|\x1b\[\?[0-9;]*\$p`)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		w.mu.Lock()
		raw := w.raw.String()
		w.mu.Unlock()
		screen := vt10x.New(vt10x.WithSize(w.cols, w.rows))
		// Run preserves OPOST/ONLCR on the PTY; apply the same cooked-output
		// newline mapping when replaying this writer's captured bytes.
		raw = strings.ReplaceAll(extensions.ReplaceAllString(raw, ""), "\n", "\r\n")
		if _, err := screen.Write([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(screen.String(), want) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %q on terminal screen:\n%s", want, screen.String())
		case <-ticker.C:
		}
	}
}

func TestProgramAliasConflictVisibleBeforeLeavingEditor(t *testing.T) {
	testProgramFieldCorrection(t, formCorrectionScenario{cols: 80, rows: 24, value: "taken", errorText: "alias_err_exists", submitKey: "\x13"})
}

func TestProgramLongFeedbackKeepsInputVisible(t *testing.T) {
	if !localizedFormTestProcess(t) {
		return
	}
	if err := i18n.Init("en"); err != nil {
		t.Fatal(err)
	}
	alias := strings.Repeat("a", 170)
	testProgramFieldCorrection(t, formCorrectionScenario{cols: 40, rows: 12, value: alias + "," + alias, errorText: "Duplicate alias in input:", submitKey: "\x13"})
}

func TestProgramTabValidationKeepsInputVisible(t *testing.T) {
	if !localizedFormTestProcess(t) {
		return
	}
	if err := i18n.Init("en"); err != nil {
		t.Fatal(err)
	}
	alias := strings.Repeat("a", 240)
	testProgramFieldCorrection(t, formCorrectionScenario{cols: 40, rows: 12, value: alias + "," + alias, errorText: "Duplicate alias in input:", submitKey: "\t"})
}

func TestProgramTagsRemainVisibleAfterFooterResize(t *testing.T) {
	testProgramFieldCorrection(t, formCorrectionScenario{cols: 80, rows: 24, value: "draft-tag,draft-tag", errorText: "tag_err_duplicate_input", submitKey: "\x13", tags: true})
}

func TestProgramVerificationConfirmationInSmallTerminal(t *testing.T) {
	if !localizedFormTestProcess(t) {
		return
	}
	if err := i18n.Init("en"); err != nil {
		t.Fatal(err)
	}
	for _, answer := range []string{"y", "n"} {
		t.Run(answer, func(t *testing.T) { testProgramVerificationAnswer(t, answer) })
	}
}

func testProgramVerificationAnswer(t *testing.T, answer string) {
	t.Helper()
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { assertProgramNoLeaks(t, baseline) })
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTUITestResource(t, master)
	defer closeTUITestResource(t, slave)
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 8}); err != nil {
		t.Fatal(err)
	}
	m := newVerificationLayoutTestModel(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	m.ctx = ctx
	output := &formScreenWriter{cols: 80, rows: 8}
	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		runErr = Run(ctx, m, slave, output)
	}()
	defer func() {
		cancel()
		<-done
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Errorf("run TUI: %v", runErr)
		}
	}()
	write := func(keys string) {
		t.Helper()
		if _, err := io.WriteString(master, keys); err != nil {
			t.Fatal(err)
		}
	}
	output.wait(t, ctx, i18n.T("tui_form_verification"))
	write("\r")
	output.wait(t, ctx, i18n.T("inventory_confirm_save_unverified")+" [y/N]")
	write(answer)
	if answer == "y" {
		output.wait(t, ctx, "[ ] root@192.0.2.1:22")
	} else {
		output.wait(t, ctx, i18n.T("tui_form_alias"))
	}
	write("\x03")
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("TUI did not exit")
	}
	if answer == "y" {
		if m.repository.Snapshot().Nodes.Count() != 1 {
			t.Fatal("confirmation did not save the node")
		}
	} else if m.repository.Snapshot().Nodes.Count() != 0 || m.form.State != huh.StateNormal || m.formState.user != "root" {
		t.Fatal("declining confirmation did not retain the unsaved draft")
	}
}

type formCorrectionScenario struct {
	cols, rows                  uint16
	value, errorText, submitKey string
	tags                        bool
}

func testProgramFieldCorrection(t *testing.T, scenario formCorrectionScenario) {
	t.Helper()
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { assertProgramNoLeaks(t, baseline) })
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTUITestResource(t, master)
	defer closeTUITestResource(t, slave)
	if err := pty.Setsize(master, &pty.Winsize{Cols: scenario.cols, Rows: scenario.rows}); err != nil {
		t.Fatal(err)
	}
	m := newAliasConflictTestModel(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	output := &formScreenWriter{cols: int(scenario.cols), rows: int(scenario.rows)}
	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		runErr = Run(ctx, m, slave, output)
	}()
	defer func() {
		cancel()
		<-done
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Errorf("run TUI: %v", runErr)
		}
	}()
	write := func(keys string) {
		t.Helper()
		if _, err := io.WriteString(master, keys); err != nil {
			t.Fatal(err)
		}
	}
	output.wait(t, ctx, "192.168.1.50")
	write("e")
	output.wait(t, ctx, i18n.T("tui_form_alias"))
	if scenario.tags {
		for _, field := range []string{"user", "address", "port", "auth_type", "password_action", "password", "key_path", "passphrase_action", "key_pass", "sudo_mode", "tags"} {
			write("\t")
			output.wait(t, ctx, "┃ "+i18n.T("tui_form_"+field))
		}
	}
	write("\x01\x0b\x1b[200~" + scenario.value + "\x1b[201~" + scenario.submitKey)
	output.wait(t, ctx, scenario.errorText)
	if scenario.tags {
		output.wait(t, ctx, "> "+scenario.value)
	}
	if m.repository.FindAlias("taken") != "other@192.0.2.2:22" {
		t.Fatal("failed save changed alias ownership")
	}
	write("\x01\x0bcorrected")
	output.wait(t, ctx, "> corrected")
	write("\x13")
	output.wait(t, ctx, i18n.Tf("tui_status_saved", map[string]any{"ID": formCredentialTestNodeID}))
	if scenario.tags {
		node, ok := m.repository.GetNode(formCredentialTestNodeID)
		if !ok || len(node.Tags) != 1 || node.Tags[0] != "corrected" {
			t.Fatal("corrected tags were not saved")
		}
	} else if m.repository.FindAlias("corrected") != formCredentialTestNodeID {
		t.Fatal("corrected alias was not saved")
	}
	write("\x03")
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("TUI did not exit")
	}
}
