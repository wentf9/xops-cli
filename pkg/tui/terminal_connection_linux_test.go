//go:build linux

package tui

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTUIEnterUsesOwnedSessionAndCurrentRepository(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTUITestResource(t, master) })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(filepath.Join("/dev/pts", strconv.Itoa(number)), os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTUITestResource(t, slave) })
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	ui := &terminalTestInteraction{password: "verified-password"}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	model, repo := terminalTestModel(t, newMemoryCredentialStore(), ui, WithContext(ctx))
	if _, cmd := model.handleEnter(); cmd == nil {
		t.Fatal("Enter did not schedule a terminal action")
	}
	action := model.terminalConnection
	var output bytes.Buffer
	action.SetStdin(slave)
	action.SetStdout(&output)
	action.SetStderr(&output)
	if err := action.Run(); err != nil {
		t.Fatal(err)
	}
	model.handleTerminalConnection(terminalConnectionResult{action: action})
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || *before != *after {
		t.Fatalf("terminal not restored: %v", err)
	}
	snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
	if err != nil || snapshot.Identity.LoginPasswordRef == nil || snapshot.Identity.Password != "" {
		t.Fatal("Enter did not update the same repository")
	}
	if model.terminalConnection != nil || model.listRevision != repo.View().Revision {
		t.Fatal("TUI returned with stale references")
	}
	if output.String() != "tui-shell\n" {
		t.Fatalf("unexpected shell output: %q", output.String())
	}
}
