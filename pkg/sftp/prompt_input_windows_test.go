//go:build windows

package sftp

import (
	"io"
	"os"
	"testing"
	"time"
)

func TestWindowsPromptInputInterruptsPendingRead(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil {
			t.Logf("close source reader failed: %v", closeErr)
		}
		if closeErr := writer.Close(); closeErr != nil {
			t.Logf("close source writer failed: %v", closeErr)
		}
	}()

	input, err := duplicatePromptInput(reader)
	if err != nil {
		t.Fatalf("duplicate prompt input failed: %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, readErr := input.Read(buffer)
		readDone <- readErr
	}()

	if err := input.Interrupt(); err != nil {
		t.Fatalf("interrupt prompt input failed: %v", err)
	}
	select {
	case readErr := <-readDone:
		if readErr == nil {
			t.Fatal("pending read unexpectedly succeeded")
		}
		if readErr != io.EOF {
			t.Logf("pending read returned platform error after cancellation: %v", readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending prompt read was not interrupted")
	}
	if err := input.Close(); err != nil {
		t.Fatalf("close prompt input failed: %v", err)
	}
}
