package terminal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"
)

func TestPrompterReadLine(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	var out bytes.Buffer
	p := NewPrompter(reader, &out)

	go func() {
		_, _ = writer.WriteString("hello world\n")
	}()

	line, err := p.ReadLine(context.Background(), "input: ")
	if err != nil {
		t.Fatalf("ReadLine failed: %v", err)
	}
	if line != "hello world" {
		t.Fatalf("ReadLine got %q, want %q", line, "hello world")
	}
	if out.String() != "input: " {
		t.Fatalf("out got %q, want %q", out.String(), "input: ")
	}
}

func TestPrompterReadSecret(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	var out bytes.Buffer
	p := NewPrompter(reader, &out)

	go func() {
		_, _ = writer.WriteString("supersecret\n")
	}()

	secret, err := p.ReadSecret(context.Background(), "password: ")
	if err != nil {
		t.Fatalf("ReadSecret failed: %v", err)
	}
	if secret != "supersecret" {
		t.Fatalf("ReadSecret got %q, want %q", secret, "supersecret")
	}
	if out.String() != "password: " {
		t.Fatalf("out got %q, want %q", out.String(), "password: ")
	}
}

func TestPrompterPreCanceledContext(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	p := NewPrompter(reader, &bytes.Buffer{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = p.ReadLine(ctx, "prompt: ")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	_, err = p.ReadSecret(ctx, "prompt: ")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestPrompterCancelDuringReadLine(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	p := NewPrompter(reader, &bytes.Buffer{})
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		_, err := p.ReadLine(ctx, "prompt: ")
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadLine did not return on cancel")
	}
}

func TestPrompterCancelDuringReadSecret(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	p := NewPrompter(reader, &bytes.Buffer{})
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		_, err := p.ReadSecret(ctx, "secret: ")
		errCh <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadSecret did not return on cancel")
	}
}

func TestPrompterEOF(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	_ = writer.Close() // Close immediately
	defer func() {
		_ = reader.Close()
	}()

	p := NewPrompter(reader, &bytes.Buffer{})
	_, err = p.ReadLine(context.Background(), "")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}

	_, err = p.ReadSecret(context.Background(), "")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestPrompterReadLine_EditingControls(t *testing.T) {
	t.Run("backspace editing ascii and unicode", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatalf("create pipe failed: %v", err)
		}
		defer func() {
			_ = reader.Close()
		}()

		go func() {
			defer func() { _ = writer.Close() }()
			// 输入 yse, 退格两次删掉 se, 输入 es\n -> 结果应该是 yes
			_, _ = writer.WriteString("yse\b\bes\n")
		}()

		p := NewPrompter(reader, &bytes.Buffer{})
		line, err := p.ReadLine(context.Background(), "")
		if err != nil {
			t.Fatalf("ReadLine failed: %v", err)
		}
		if line != "yes" {
			t.Fatalf("ReadLine got %q, want %q", line, "yes")
		}
	})

	t.Run("backspace unicode rune", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatalf("create pipe failed: %v", err)
		}
		defer func() {
			_ = reader.Close()
		}()

		go func() {
			defer func() { _ = writer.Close() }()
			// 输入 你好, 退格一次删掉 好, 写入 们\n -> 结果应该是 你们
			_, _ = writer.WriteString("你好\x7f们\n")
		}()

		p := NewPrompter(reader, &bytes.Buffer{})
		line, err := p.ReadLine(context.Background(), "")
		if err != nil {
			t.Fatalf("ReadLine failed: %v", err)
		}
		if line != "你们" {
			t.Fatalf("ReadLine got %q, want %q", line, "你们")
		}
	})

	t.Run("ctrl-c cancels read", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatalf("create pipe failed: %v", err)
		}
		defer func() {
			_ = reader.Close()
		}()

		go func() {
			defer func() { _ = writer.Close() }()
			_, _ = writer.Write([]byte{3}) // Ctrl+C
		}()

		p := NewPrompter(reader, &bytes.Buffer{})
		_, err = p.ReadLine(context.Background(), "")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("ctrl-d eof on empty line", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatalf("create pipe failed: %v", err)
		}
		defer func() {
			_ = reader.Close()
		}()

		go func() {
			defer func() { _ = writer.Close() }()
			_, _ = writer.Write([]byte{4}) // Ctrl+D
		}()

		p := NewPrompter(reader, &bytes.Buffer{})
		_, err = p.ReadLine(context.Background(), "")
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected io.EOF, got %v", err)
		}
	})
}

func TestPrompterReadSecret_RestoreErrorPropagated(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	go func() {
		defer func() { _ = writer.Close() }()
		_, _ = writer.WriteString("mysecret\n")
	}()

	wantRestoreErr := errors.New("simulated restore terminal failure")

	p := &stdPrompter{
		stdin:      reader,
		stdout:     &bytes.Buffer{},
		isTerminal: func(fd int) bool { return true },
		makeRaw: func(fd int) (*term.State, error) {
			return &term.State{}, nil
		},
		restore: func(fd int, state *term.State) error {
			return wantRestoreErr
		},
	}

	secret, err := p.ReadSecret(context.Background(), "")
	if !errors.Is(err, wantRestoreErr) {
		t.Fatalf("expected restore error to be propagated, got %v", err)
	}
	if secret != "" {
		t.Fatalf("expected empty secret on restore error, got %q", secret)
	}
}

func TestPrompterReadSecret_MakeRawErrorPropagated(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	wantMakeRawErr := errors.New("simulated makeRaw failure")

	p := &stdPrompter{
		stdin:      reader,
		stdout:     &bytes.Buffer{},
		isTerminal: func(fd int) bool { return true },
		makeRaw: func(fd int) (*term.State, error) {
			return nil, wantMakeRawErr
		},
	}

	_, err = p.ReadSecret(context.Background(), "")
	if !errors.Is(err, wantMakeRawErr) {
		t.Fatalf("expected makeRaw error to be propagated, got %v", err)
	}
}

func TestPrompterReadSecret_CancellationRestoresTerminalAndEmitsNewline(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()

	restored := false
	stdoutBuf := &bytes.Buffer{}

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	p := &stdPrompter{
		stdin:      reader,
		stdout:     stdoutBuf,
		isTerminal: func(fd int) bool { return true },
		makeRaw: func(fd int) (*term.State, error) {
			return &term.State{}, nil
		},
		restore: func(fd int, state *term.State) error {
			restored = true
			return nil
		},
	}

	prompt := "Password: "
	secret, err := p.ReadSecret(ctx, prompt)
	if err == nil {
		t.Fatal("expected cancellation error, got nil")
	}
	if secret != "" {
		t.Fatalf("expected empty secret, got %q", secret)
	}
	if !restored {
		t.Fatal("expected terminal to be restored on context cancellation")
	}
	if !strings.HasPrefix(stdoutBuf.String(), prompt) {
		t.Fatalf("expected prompt in stdout, got %q", stdoutBuf.String())
	}
	if !strings.HasSuffix(stdoutBuf.String(), "\r\n") {
		t.Fatalf("expected CRLF newline at the end of output, got %q", stdoutBuf.String())
	}
}
