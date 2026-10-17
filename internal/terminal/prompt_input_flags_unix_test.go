//go:build !windows

package terminal

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func promptInputFlags(t *testing.T, file *os.File) int {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var flagErr error
	if err := raw.Control(func(fd uintptr) { flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil {
		t.Fatal(err)
	}
	if flagErr != nil {
		t.Fatal(flagErr)
	}
	return flags
}

func TestDuplicatePromptInputPreservesBorrowedFlags(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	before := promptInputFlags(t, reader)
	input, err := DuplicatePromptInput(reader)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = input.Close()
		}
	}()
	if _, err := writer.Write([]byte("A")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1)
	if _, err := input.Read(data); err != nil || string(data) != "A" {
		t.Fatalf("duplicate read failed: %q %v", data, err)
	}
	if after := promptInputFlags(t, reader); after != before {
		t.Fatalf("borrowed flags changed during read: before=%#x after=%#x", before, after)
	}
	if err := input.Interrupt(); err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	if after := promptInputFlags(t, reader); after != before {
		t.Fatalf("borrowed flags changed during cleanup: before=%#x after=%#x", before, after)
	}
	if _, err := writer.Write([]byte("B")); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(data); err != nil || string(data) != "B" {
		t.Fatalf("borrowed input closed or later bytes consumed: %q %v", data, err)
	}
}
