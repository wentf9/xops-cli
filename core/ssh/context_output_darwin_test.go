//go:build darwin

package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func darwinOutputFlags(t *testing.T, file *os.File) (descriptor uintptr, flags int) {
	t.Helper()
	raw, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flagErr error
	if err := raw.Control(func(fd uintptr) { descriptor = fd; flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0) }); err != nil {
		t.Fatal(err)
	}
	if flagErr != nil {
		t.Fatal(flagErr)
	}
	return descriptor, darwinOutputStatusFlags(flags)
}

func darwinOutputStatusFlags(flags int) int {
	// XNU F_GETFL exposes FWASWRITTEN, which the kernel sets after a write,
	// including through a duplicate. It is history, not a caller-controlled
	// status flag (bsd/sys/fcntl.h and bsd/kern/sys_generic.c).
	const fWasWritten = 0x00010000
	return flags &^ fWasWritten
}

func TestDarwinOutputStatusFlags(t *testing.T) {
	const before = unix.O_WRONLY | unix.O_NONBLOCK
	if got := darwinOutputStatusFlags(before | 0x00010000); got != before {
		t.Fatalf("write history changed status flags: %#x", got)
	}
	for _, flag := range []int{unix.O_ACCMODE, unix.O_NONBLOCK, unix.O_APPEND, unix.O_ASYNC, unix.O_SYNC, unix.O_DSYNC} {
		if darwinOutputStatusFlags(before^flag) == before {
			t.Fatalf("caller flag change ignored: %#x", flag)
		}
	}
}

func TestDarwinOutputPausedTerminalCancellation(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()
	fd, before := darwinOutputFlags(t, slave)
	if err := unix.IoctlSetInt(int(fd), unix.TIOCSTOP, 0); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.IoctlSetInt(int(fd), unix.TIOCSTART, 0) }()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	bound, closeFn, supported, err := BindOutput(ctx, slave)
	if err != nil || !supported {
		t.Fatalf("terminal not bound: %v %v", supported, err)
	}
	done := make(chan error, 1)
	go func() { _, err := bound.Write(bytes.Repeat([]byte("x"), 1<<20)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("terminal deadline lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		_ = unix.IoctlSetInt(int(fd), unix.TIOCSTART, 0)
		_ = master.Close()
		<-done
		_ = closeFn()
		t.Fatal("paused terminal write did not cancel")
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	_, after := darwinOutputFlags(t, slave)
	if after != before {
		t.Fatalf("borrowed terminal flags changed: before=%#x after=%#x", before, after)
	}
}

func TestDarwinOutputNonblockingPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	_, before := darwinOutputFlags(t, writer)
	if before&unix.O_NONBLOCK == 0 {
		t.Fatal("Go pipe is not nonblocking")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	bound, closeFn, supported, err := BindOutput(ctx, writer)
	if err != nil || !supported {
		t.Fatalf("nonblocking pipe not bound: %v %v", supported, err)
	}
	done := make(chan error, 1)
	go func() { _, err := bound.Write(bytes.Repeat([]byte("x"), 1<<20)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("pipe deadline lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		_ = reader.Close()
		<-done
		_ = closeFn()
		t.Fatal("pipe write did not cancel")
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	_, after := darwinOutputFlags(t, writer)
	if after != before {
		t.Fatalf("borrowed pipe flags changed: before=%#x after=%#x", before, after)
	}
}

func TestDarwinOutputBlockingPipeRemainsUnsupported(t *testing.T) {
	var descriptors [2]int
	if err := unix.Pipe(descriptors[:]); err != nil {
		t.Fatal(err)
	}
	reader := os.NewFile(uintptr(descriptors[0]), "blocking read")
	writer := os.NewFile(uintptr(descriptors[1]), "blocking write")
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	_, before := darwinOutputFlags(t, writer)
	if before&unix.O_NONBLOCK != 0 {
		t.Fatal("blocking pipe fixture changed")
	}
	bound, closeFn, supported, err := BindOutput(t.Context(), writer)
	if err != nil || supported || bound != io.Writer(writer) {
		t.Fatalf("blocking pipe not preserved: %v %v", supported, err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	_, after := darwinOutputFlags(t, writer)
	if after != before {
		t.Fatalf("borrowed blocking pipe flags changed: before=%#x after=%#x", before, after)
	}
}

func TestDarwinOutputBorrowedTerminalRemainsUsable(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()
	bound, closeFn, supported, err := BindOutput(t.Context(), slave)
	if err != nil || !supported {
		t.Fatalf("terminal not bound: %v %v", supported, err)
	}
	if _, err := bound.Write([]byte("原生")); err != nil {
		t.Fatal(err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	if _, err := slave.Write([]byte("!")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("原生!"))
	if _, err := io.ReadFull(master, data); err != nil || string(data) != "原生!" {
		t.Fatalf("terminal output changed: %q %v", data, err)
	}
}
