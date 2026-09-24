//go:build windows

package terminal

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func newWindowsPipeTestInput(t *testing.T) (PromptInput, *os.File, *os.File) {
	t.Helper()
	source, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	return wrapWindowsPipeTestInput(t, source, writer), source, writer
}

func wrapWindowsPipeTestInput(t *testing.T, source, writer *os.File) PromptInput {
	t.Helper()
	input, err := DuplicatePromptInput(source)
	if err != nil {
		t.Fatal(errors.Join(err, source.Close(), writer.Close()))
	}
	t.Cleanup(func() {
		// Close the producer first so even the old, broken cancellation path
		// can unwind after a test timeout instead of hanging the test process.
		for _, closer := range []io.Closer{writer, input, source} {
			if err := closer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Error(err)
			}
		}
	})
	return input
}

func interruptWindowsPipeTestInput(t *testing.T, input PromptInput, readDone <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	interruptDone := make(chan error, 1)
	go func() { interruptDone <- input.Interrupt() }()
	select {
	case err := <-interruptDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("pipe cancellation blocked without producer data")
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("canceled pipe read = %v, want EOF", err)
		}
	case <-ctx.Done():
		t.Fatal("pipe reader did not exit after cancellation")
	}
}

func TestWindowsPipeInputIdleCancellationPreservesNextByte(t *testing.T) {
	input, source, writer := newWindowsPipeTestInput(t)
	readDone := make(chan error, 1)
	go func() { var b [1]byte; _, err := input.Read(b[:]); readDone <- err }()
	// Exercise an already waiting reader as well as the admission race covered
	// by TestWindowsPromptInputInterruptsPendingRead.
	time.Sleep(20 * time.Millisecond)
	interruptWindowsPipeTestInput(t, input, readDone)
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(source)
	if err != nil || string(data) != "x" {
		t.Fatalf("borrowed source after cancellation: %q, %v", data, err)
	}
}

func TestWindowsPipeInputBufferedDataAndEOF(t *testing.T) {
	input, _, writer := newWindowsPipeTestInput(t)
	want := strings.Repeat("界😀\x00\x1b[A", 20)
	if _, err := writer.WriteString(want); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	// Read in small pieces, then observe EOF after draining the closed pipe.
	var got bytes.Buffer
	var buffer [7]byte
	for {
		n, err := input.Read(buffer[:])
		got.Write(buffer[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if got.String() != want {
		t.Fatalf("pipe data changed: %q, want %q", got.String(), want)
	}
}

func TestWindowsPipeInputCancellationDoesNotConsumeBufferedData(t *testing.T) {
	input, source, writer := newWindowsPipeTestInput(t)
	if _, err := writer.WriteString("next"); err != nil {
		t.Fatal(err)
	}
	if err := input.Interrupt(); err != nil {
		t.Fatal(err)
	}
	var b [8]byte
	if n, err := input.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after cancellation: %d, %v", n, err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(source)
	if err != nil || string(data) != "next" {
		t.Fatalf("cancellation consumed queued input: %q, %v", data, err)
	}
}

func TestWindowsPipeInputCancelsConcurrentReaders(t *testing.T) {
	input, _, _ := newWindowsPipeTestInput(t)
	const readers = 8
	readDone := make(chan error, readers)
	for range readers {
		go func() { var b [1]byte; _, err := input.Read(b[:]); readDone <- err }()
	}
	interruptWindowsPipeTestInput(t, input, readDone)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for range readers - 1 {
		select {
		case err := <-readDone:
			if !errors.Is(err, io.EOF) {
				t.Fatalf("concurrent canceled read: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent pipe reader did not stop")
		}
	}
}

func TestWindowsPipeInputOverlappedPipe(t *testing.T) {
	name, err := windows.UTF16PtrFromString(`\\.\pipe\xops-input-test-` + rand.Text())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateNamedPipe(name,
		windows.PIPE_ACCESS_INBOUND|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := os.NewFile(uintptr(handle), "overlapped-pipe")
	// Connecting the client before any reads makes the pipe ready without a
	// pending ConnectNamedPipe operation or an extra background goroutine.
	writerHandle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(errors.Join(err, source.Close()))
	}
	writer := os.NewFile(uintptr(writerHandle), "pipe-writer")
	input := wrapWindowsPipeTestInput(t, source, writer)
	if _, err := writer.WriteString("ready"); err != nil {
		t.Fatal(err)
	}
	var b [5]byte
	if _, err := io.ReadFull(input, b[:]); err != nil || string(b[:]) != "ready" {
		t.Fatalf("overlapped pipe data: %q, %v", b, err)
	}
	readDone := make(chan error, 1)
	go func() { var next [1]byte; _, err := input.Read(next[:]); readDone <- err }()
	interruptWindowsPipeTestInput(t, input, readDone)
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("next"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(source)
	if err != nil || string(data) != "next" {
		t.Fatalf("overlapped pipe after handoff: %q, %v", data, err)
	}
}
