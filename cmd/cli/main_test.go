package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd"
)

func TestReportErrorSkipsFailedSCPOutput(t *testing.T) {
	for _, stream := range []string{"stderr", "stdout"} {
		t.Run(stream, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stderr")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			previous := os.Stderr
			os.Stderr = file
			defer func() { os.Stderr = previous }()
			reportError(errors.Join(errors.New("transfer failed"), fmt.Errorf("cleanup: %w", &cmd.SCPOutputError{Stream: stream, Err: os.ErrClosed})))
			data, err := os.ReadFile(path)
			if err != nil || len(data) != 0 {
				t.Fatalf("failed stderr was written again: %q %v", data, err)
			}
		})
	}
}

func TestReportErrorPreservesOrdinaryFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stderr")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	previous := os.Stderr
	os.Stderr = file
	defer func() { os.Stderr = previous }()
	reportError(errors.New("ordinary transfer failure"))
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "ordinary transfer failure") {
		t.Fatalf("ordinary error lost: %q %v", data, err)
	}
}
