//go:build unix

package sftpshell

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
	"golang.org/x/sys/unix"
)

func TestP7W4a_CopyLocalFile_FIFODoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "stall.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}
	regPath := filepath.Join(dir, "reg.txt")
	if err := os.WriteFile(regPath, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		src, dst string
	}{
		{name: "fifo_source", src: fifoPath, dst: filepath.Join(dir, "out.txt")},
		{name: "fifo_dest", src: regPath, dst: fifoPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- copyLocalFile(tc.src, tc.dst) }()
			select {
			case err := <-done:
				if !errors.Is(err, fsx.ErrNonRegular) {
					t.Fatalf("copyLocalFile(%s) = %v, want fsx.ErrNonRegular", tc.name, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("copyLocalFile(%s) blocked on FIFO", tc.name)
			}
		})
	}
}
