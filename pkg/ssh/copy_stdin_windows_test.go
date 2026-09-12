//go:build windows

package ssh

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"
)

func TestCopyStdinWindowsEOF(t *testing.T) {
	src, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := src.WriteString("input"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var dst bytes.Buffer
	cancel, done, err := copyStdinTo(src, &dst)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cancel(); err != nil {
			t.Error(err)
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("normal EOF reported as failure: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stdin copy did not finish")
	}
	if dst.String() != "input" {
		t.Fatalf("copied %q", dst.String())
	}
}

func TestCopyStdinWindowsCancelPreservesNextInput(t *testing.T) {
	src, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	cancel, done, err := copyStdinTo(src, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise cancellation both before and during a pending read in repeated runs.
	if err := cancel(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("canceled copy failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled stdin copy did not finish")
	}
	if _, err := writer.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := io.ReadFull(src, b[:])
		if err == nil && b[0] != 'x' {
			err = io.ErrUnexpectedEOF
		}
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("next reader lost its first character")
	}
}
