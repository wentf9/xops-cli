//go:build windows

package fsx

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

func TestCreateExclusive_WindowsOwnerOnlySDAtCreation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	f, err := CreateExclusive(path, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("CreateExclusive failed: %v", err)
	}
	defer func() { _ = f.Close() }()

	sd, err := winsec.GetSecurityInfoByHandle(windows.Handle(f.Fd()))
	if err != nil {
		t.Fatalf("GetSecurityInfoByHandle failed: %v", err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatalf("sd.Control failed: %v", err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("expected SE_DACL_PROTECTED on CreateExclusive file, got control=%#x", ctrl)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("sd.DACL failed: %v", err)
	}
	if dacl.AceCount != 2 {
		t.Fatalf("expected 2 owner-only ACEs (CurrentUser + SYSTEM), got %d", dacl.AceCount)
	}
}

func TestSocketSlot_WindowsRealDirLockAndHandleACL(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "mux")
	if err := winsec.EnsureOwnerOnlyDirectory(dir); err != nil {
		t.Fatalf("EnsureOwnerOnlyDirectory failed: %v", err)
	}

	// Verify withDirLockOS actually serializes concurrent lockers (not a no-op).
	entered := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- withDirLockOS(dir, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	secondAcquired := make(chan error, 1)
	go func() {
		secondAcquired <- withDirLockOS(dir, func() error { return nil })
	}()

	select {
	case err := <-secondAcquired:
		close(release)
		<-holderDone
		t.Fatalf("second Windows dir lock acquired while first was still held (err=%v)", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	if err := <-holderDone; err != nil {
		t.Fatalf("first dir lock failed: %v", err)
	}
	select {
	case err := <-secondAcquired:
		if err != nil {
			t.Fatalf("second dir lock failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second Windows dir lock did not unblock after first released")
	}

	// Verify SocketSlot bind, handle-based socket ACL verification, dial, and Release.
	sockPath := filepath.Join(dir, "ctrl.sock")
	slot, err := BindSocketSlot(sockPath, nil)
	if err != nil {
		t.Fatalf("BindSocketSlot failed: %v", err)
	}
	if err := winsec.VerifyOwnerOnlySocketByHandle(sockPath); err != nil {
		_ = slot.Release()
		t.Fatalf("VerifyOwnerOnlySocketByHandle failed: %v", err)
	}

	acceptDone := make(chan struct{})
	go func(ln net.Listener) {
		defer close(acceptDone)
		if c, aErr := ln.Accept(); aErr == nil {
			_ = c.Close()
		}
	}(slot.Listener())

	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		_ = slot.Release()
		<-acceptDone
		t.Fatalf("dial Windows AF_UNIX socket failed: %v", err)
	}
	_ = conn.Close()
	if err := slot.Release(); err != nil {
		<-acceptDone
		t.Fatalf("Release failed: %v", err)
	}
	<-acceptDone

	if _, err := os.Lstat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still exists after Release: %v", err)
	}
}
