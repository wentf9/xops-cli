//go:build linux || darwin

package cmd

import (
	"bytes"
	"testing"

	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/internal/testpty"
	"golang.org/x/term"
)

func TestSSHDiagnosticRawTerminalNewlines(t *testing.T) {
	master, slave, err := testpty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer closeSCPTestResource(t, master)
	defer closeSCPTestResource(t, slave)
	fd := int(slave.Fd()) // The test owns this terminal; no binding exists yet.
	original, err := term.MakeRaw(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := term.Restore(fd, original); err != nil {
			t.Error(err)
		}
	}()
	raw, err := term.GetState(fd)
	if err != nil {
		t.Fatal(err)
	}
	d, err := newSSHDiagnostics(t.Context(), slave, 1)
	if err != nil {
		t.Fatal(err)
	}
	d.ObserveDiagnostic(corelog.Diagnostic{Kind: corelog.Connected, NodeID: "fixture"})
	if err := d.finish(); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 256)
	n, err := master.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data[:n], []byte("\r\n")) {
		t.Fatalf("raw terminal newline changed: %q", data[:n])
	}
	after, err := term.GetState(fd)
	if err != nil || *after != *raw {
		t.Fatalf("borrowed terminal mode changed: %v", err)
	}
	if _, err := slave.Write([]byte("caller")); err != nil {
		t.Fatalf("borrowed terminal closed: %v", err)
	}
}
