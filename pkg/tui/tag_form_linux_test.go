//go:build linux

package tui

import (
	"context"
	"io"
	"testing"
	"time"

	pty "github.com/wentf9/xops-cli/internal/testpty"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"go.uber.org/goleak"
)

func TestProgramExistingTagVisibleAndRemovable(t *testing.T) {
	if !localizedFormTestProcess(t) {
		return
	}
	for _, lang := range []string{"zh", "en"} {
		t.Run(lang, func(t *testing.T) {
			if err := i18n.Init(lang); err != nil {
				t.Fatal(err)
			}
			testProgramExistingTag(t)
		})
	}
}

func testProgramExistingTag(t *testing.T) {
	t.Helper()
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { assertProgramNoLeaks(t, baseline) })
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTUITestResource(t, master)
	defer closeTUITestResource(t, slave)
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	m := newTagFormTestModel(t, "prod")
	// Model fields belong to Run; retain the safe repository handle before
	// starting the program so screen assertions cannot race a model update.
	repository := m.repository
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	output := &formScreenWriter{cols: 80, rows: 24}
	done, stop := startProgramTest(ctx, m, slave, output)
	defer stop()
	write := func(keys string) {
		t.Helper()
		if _, err := io.WriteString(master, keys); err != nil {
			t.Fatal(err)
		}
	}
	output.wait(t, ctx, "192.168.1.50")
	write(" g")
	output.wait(t, ctx, i18n.T("tui_tag_select"))
	// Assert visible cells before navigation and without a background reply.
	output.wait(t, ctx, "• prod")
	write("\x1b[B\r")
	output.wait(t, ctx, "┃ "+i18n.T("tui_tag_select"))
	write(" ")
	output.wait(t, ctx, "✓ prod")
	write("\r")
	output.wait(t, ctx, "┃ "+i18n.T("tui_tag_new_input"))
	write("\r")
	output.wait(t, ctx, i18n.Tf("tui_status_tag_removed", map[string]any{"Count": 1}))
	node, ok := repository.GetNode(formCredentialTestNodeID)
	if !ok || len(node.Tags) != 0 {
		t.Fatal("selected tag was not removed")
	}
	write("\x03")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("TUI did not exit")
	}
}
