package utils

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestReadSecretLineFromReader(t *testing.T) {
	t.Run("ReadsSingleLineAndPreservesRemainingBytes", func(t *testing.T) {
		input := "654321\nsecond-line\nthird-line"
		buf := bytes.NewBufferString(input)

		secret, err := ReadSecretLineFromReader(buf, 4096)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if secret != "654321" {
			t.Fatalf("expected '654321', got %q", secret)
		}

		remaining, err := io.ReadAll(buf)
		if err != nil {
			t.Fatalf("read remaining failed: %v", err)
		}
		if string(remaining) != "second-line\nthird-line" {
			t.Fatalf("expected remaining stream 'second-line\\nthird-line', got %q", string(remaining))
		}
	})

	t.Run("TrimsCRLF", func(t *testing.T) {
		buf := bytes.NewBufferString("otp-code-123\r\nnext")
		secret, err := ReadSecretLineFromReader(buf, 4096)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if secret != "otp-code-123" {
			t.Fatalf("expected 'otp-code-123', got %q", secret)
		}
	})

	t.Run("TrimsSurroundingWhitespace", func(t *testing.T) {
		buf := bytes.NewBufferString("   998877   \n")
		secret, err := ReadSecretLineFromReader(buf, 4096)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if secret != "998877" {
			t.Fatalf("expected '998877', got %q", secret)
		}
	})

	t.Run("ReadsUpToEOFWithoutNewline", func(t *testing.T) {
		buf := bytes.NewBufferString("no-newline-token")
		secret, err := ReadSecretLineFromReader(buf, 4096)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if secret != "no-newline-token" {
			t.Fatalf("expected 'no-newline-token', got %q", secret)
		}
	})

	t.Run("RejectsEmptyInput", func(t *testing.T) {
		buf := bytes.NewBufferString("\n")
		_, err := ReadSecretLineFromReader(buf, 4096)
		if err == nil {
			t.Fatal("expected error for empty input, got nil")
		}
	})

	t.Run("RespectsMaxBytesLimit", func(t *testing.T) {
		longLine := strings.Repeat("A", 100) + "\n"
		buf := bytes.NewBufferString(longLine)
		secret, err := ReadSecretLineFromReader(buf, 10)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(secret) != 10 {
			t.Fatalf("expected secret len 10, got len %d (%q)", len(secret), secret)
		}
	})
}
