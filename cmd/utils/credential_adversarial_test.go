package utils

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

func TestAdversarialReadSecretLineFromReader_Streaming(t *testing.T) {
	input := "line1\nline2\n"
	buf := bytes.NewBufferString(input)

	line1, err := ReadSecretLineFromReader(buf, 4096)
	if err != nil {
		t.Fatalf("line1 read failed: %v", err)
	}
	if line1 != "line1" {
		t.Fatalf("expected 'line1', got %q", line1)
	}

	line2, err := ReadSecretLineFromReader(buf, 4096)
	if err != nil {
		t.Fatalf("line2 read failed: %v", err)
	}
	if line2 != "line2" {
		t.Fatalf("expected 'line2', got %q", line2)
	}

	// Third read should fail because stream is now exhausted
	_, err = ReadSecretLineFromReader(buf, 4096)
	if err == nil {
		t.Fatal("expected error on empty buffer after reading all lines, got nil")
	}
}

func TestAdversarialReadSecretLineFromReader_EmptyAndWhitespace(t *testing.T) {
	t.Run("EmptyStream", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		_, err := ReadSecretLineFromReader(buf, 4096)
		if err == nil {
			t.Fatal("expected error on empty stream, got nil")
		}
		if !strings.Contains(err.Error(), "standard input is empty") {
			t.Fatalf("expected 'standard input is empty' error, got %v", err)
		}
	})

	t.Run("OnlyWhitespaceAndNewlines", func(t *testing.T) {
		vectors := []string{
			"\n",
			"\r\n",
			"   \n",
			"\t\t\r\n",
			"  \t  ",
		}
		for _, v := range vectors {
			buf := bytes.NewBufferString(v)
			_, err := ReadSecretLineFromReader(buf, 4096)
			if err == nil {
				t.Fatalf("vector %q should fail with empty error, got nil", v)
			}
		}
	})
}

func TestAdversarialReadSecretLineFromReader_NoTrailingNewline(t *testing.T) {
	input := "secret-without-newline"
	buf := bytes.NewBufferString(input)
	secret, err := ReadSecretLineFromReader(buf, 4096)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "secret-without-newline" {
		t.Fatalf("expected 'secret-without-newline', got %q", secret)
	}
}

func TestAdversarialReadSecretLineFromReader_100KBPayloads(t *testing.T) {
	t.Run("Payload100KB_NoNewline_BoundedTo4096", func(t *testing.T) {
		payload := make([]byte, 100*1024)
		for i := range payload {
			payload[i] = 'A'
		}
		buf := bytes.NewReader(payload)

		secret, err := ReadSecretLineFromReader(buf, 4096)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if int64(len(secret)) != 4096 {
			t.Fatalf("expected exactly 4096 bytes read, got %d", len(secret))
		}

		remainingBytes, err := io.ReadAll(buf)
		if err != nil {
			t.Fatalf("failed to read remaining bytes: %v", err)
		}
		expectedRemaining := len(payload) - 4096
		if len(remainingBytes) != expectedRemaining {
			t.Fatalf("expected %d remaining bytes, got %d", expectedRemaining, len(remainingBytes))
		}
	})

	t.Run("Payload100KB_NewlineAtOffset5000", func(t *testing.T) {
		payload := make([]byte, 100*1024)
		for i := range payload {
			payload[i] = 'B'
		}
		payload[5000] = '\n'
		buf := bytes.NewReader(payload)

		secret, err := ReadSecretLineFromReader(buf, 4096)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(secret) != 4096 {
			t.Fatalf("expected secret length 4096, got %d", len(secret))
		}

		nextByte := make([]byte, 1)
		_, err = buf.Read(nextByte)
		if err != nil {
			t.Fatalf("failed to read next byte: %v", err)
		}
		if nextByte[0] != 'B' {
			t.Fatalf("expected next byte 'B', got %c", nextByte[0])
		}
	})

	t.Run("Payload100KB_NewlineAtOffset200", func(t *testing.T) {
		payload := make([]byte, 100*1024)
		for i := range payload {
			payload[i] = 'C'
		}
		payload[200] = '\n'
		buf := bytes.NewReader(payload)

		secret, err := ReadSecretLineFromReader(buf, 4096)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(secret) != 200 {
			t.Fatalf("expected secret length 200, got %d", len(secret))
		}

		nextByte := make([]byte, 1)
		_, err = buf.Read(nextByte)
		if err != nil {
			t.Fatalf("failed to read next byte: %v", err)
		}
		if nextByte[0] != 'C' {
			t.Fatalf("expected next byte 'C', got %c", nextByte[0])
		}
	})

	t.Run("Payload100KB_RandomBinary_NoPanic", func(t *testing.T) {
		binaryData := make([]byte, 100*1024)
		_, _ = rand.Read(binaryData)
		binaryData[0] = 0x42
		buf := bytes.NewReader(binaryData)

		secret, err := ReadSecretLineFromReader(buf, 4096)
		if err != nil && !strings.Contains(err.Error(), "empty") {
			t.Fatalf("unexpected error on binary data: %v", err)
		}
		if int64(len(secret)) > 4096 {
			t.Fatalf("secret exceeded max bounds: %d > 4096", len(secret))
		}
	})
}
