package terminal

import (
	"context"
	"io"
	"os"
	"sync"

	"golang.org/x/term"
)

// Prompter provides interruptible terminal input for lines and secrets.
type Prompter interface {
	ReadLine(ctx context.Context, prompt string) (string, error)
	ReadSecret(ctx context.Context, prompt string) (string, error)
}

// PromptInput wraps an interruptible input stream.
type PromptInput interface {
	io.ReadCloser
	Interrupt() error
}

// ClosablePromptInput wraps an io.ReadCloser into PromptInput.
type ClosablePromptInput struct {
	io.ReadCloser
	once sync.Once
	err  error
}

// Interrupt closes the underlying ReadCloser once.
func (i *ClosablePromptInput) Interrupt() error {
	i.once.Do(func() {
		i.err = i.ReadCloser.Close()
	})
	return i.err
}

// Close closes the underlying ReadCloser.
func (i *ClosablePromptInput) Close() error {
	return i.Interrupt()
}

// NewPrompter creates a Prompter backed by stdin and stdout.
func NewPrompter(stdin io.Reader, stdout io.Writer) Prompter {
	if stdin == nil {
		stdin = os.Stdin
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	return &stdPrompter{
		stdin:      stdin,
		stdout:     stdout,
		isTerminal: term.IsTerminal,
		makeRaw:    term.MakeRaw,
		restore:    term.Restore,
	}
}
