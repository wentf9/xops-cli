package cmd

import (
	"errors"
	"fmt"
	"testing"
)

func TestSFTPConnectionLostErrorPreservesCause(t *testing.T) {
	waitErr := fmt.Errorf("remote closed transport")
	err := sftpConnectionLostError(waitErr)
	if !errors.Is(err, errSFTPConnectionLost) {
		t.Fatalf("expected connection-lost sentinel, got %v", err)
	}
	if !errors.Is(err, waitErr) {
		t.Fatalf("expected SSH Wait error to be preserved, got %v", err)
	}
}

func TestSFTPConnectionLostErrorHandlesCleanTransportClose(t *testing.T) {
	err := sftpConnectionLostError(nil)
	if !errors.Is(err, errSFTPConnectionLost) {
		t.Fatalf("expected connection-lost sentinel, got %v", err)
	}
}
