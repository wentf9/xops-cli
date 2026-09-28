//go:build windows

package sftpshell

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestHistoryRenameWindowsErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{windows.ERROR_ACCESS_DENIED, true},
		{&os.LinkError{Op: "rename", Err: windows.ERROR_SHARING_VIOLATION}, true},
		{windows.ERROR_FILE_NOT_FOUND, false},
		{windows.ERROR_PATH_NOT_FOUND, false},
		{windows.ERROR_DISK_FULL, false},
		{windows.ERROR_INVALID_PARAMETER, false},
		{context.DeadlineExceeded, false},
	} {
		if got := isHistoryRenameRetryable(tc.err); got != tc.want {
			t.Errorf("retry %v = %t, want %t", tc.err, got, tc.want)
		}
	}
}

func TestHistoryRenameRetriesWindowsOpenReader(t *testing.T) {
	source, destination := historyReplacementFixture(t)
	path, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		t.Fatal(err)
	}
	// Model a metadata reader or scanner that does not share delete access.
	handle, err := windows.CreateFile(path, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	reader := os.NewFile(uintptr(handle), destination)
	release := sync.OnceValue(reader.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	attempted := make(chan error, 1)
	done := make(chan error, 1)
	stopped := make(chan struct{})
	defer func() {
		if err := release(); err != nil {
			t.Error(err)
		}
		cancel()
		<-stopped
	}()
	go func() {
		defer close(stopped)
		var first sync.Once
		done <- retryHistoryRename(ctx, func() error {
			err := os.Rename(source, destination)
			first.Do(func() { attempted <- err })
			return err
		}, isHistoryRenameRetryable)
	}()
	select {
	case err := <-attempted:
		if err == nil || !isHistoryRenameRetryable(err) {
			t.Fatalf("open reader did not produce a sharing conflict: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("history replacement did not start")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("replacement failed after reader released: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("history replacement did not finish")
	}
	assertHistoryFileContent(t, destination, "new history")
}
