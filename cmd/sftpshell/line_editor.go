package sftpshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/chzyer/readline"
)

type lineEditor struct {
	instance   *readline.Instance
	input      promptInput
	inputOnce  sync.Once
	inputErr   error
	ready      chan struct{}
	promptMu   sync.Mutex
	promptDone chan struct{}
	closing    bool
	closeOnce  sync.Once
	closeErr   error
}

func newLineEditor(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, historyFile string, shell *Shell) (*lineEditor, error) {
	if ctx == nil {
		return nil, fmt.Errorf("line editor context is nil")
	}
	input, err := duplicatePromptInput(stdin)
	if err != nil {
		return nil, fmt.Errorf("duplicate prompt input failed: %w", err)
	}

	instance, err := readline.NewEx(&readline.Config{
		HistoryFile:            historyFile,
		DisableAutoSaveHistory: true,
		InterruptPrompt:        "^C",
		EOFPrompt:              "^D",
		Stdin:                  input,
		Stdout:                 stdout,
		Stderr:                 stderr,
		AutoComplete:           shellCompleter{shell: shell},
	})
	if err != nil {
		if closeErr := input.Close(); closeErr != nil {
			return nil, fmt.Errorf(
				"create line editor failed: %w; close prompt input after editor creation failed: %w",
				err,
				closeErr,
			)
		}
		return nil, fmt.Errorf("create line editor failed: %w", err)
	}
	editor := &lineEditor{instance: instance, input: input, ready: make(chan struct{})}
	go editor.waitForTerminalReader(ctx)
	return editor, nil
}

// waitForTerminalReader establishes that readline's internal terminal
// goroutine has registered itself before Close is allowed to call into it.
// readline v1.5.1 registers its WaitGroup inside that goroutine; closing any
// earlier races with Wait. The editor owns this short-lived goroutine; Close
// waits for ready before touching readline and cancellation interrupts its
// input so the goroutine has a bounded exit path.
func (e *lineEditor) waitForTerminalReader(ctx context.Context) {
	e.instance.Terminal.KickRead()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	ctxDone := ctx.Done()
	for !e.instance.Terminal.IsReading() {
		select {
		case <-ctxDone:
			// resetLineEditor observes cancellation and calls Close, which
			// interrupts the input. Keep waiting until readline has registered
			// its WaitGroup so that Close cannot race its internal Add call.
			ctxDone = nil
		case <-ticker.C:
		}
	}
	close(e.ready)
}

func (e *lineEditor) Prompt(ctx context.Context, prompt string) (result string, retErr error) {
	if ctx == nil {
		return "", fmt.Errorf("sftp line editor prompt context is nil")
	}
	done, err := e.beginPrompt()
	if err != nil {
		return "", err
	}
	defer e.endPrompt(done)
	interruptDone := make(chan error, 1)
	stopInterrupt := context.AfterFunc(ctx, func() {
		interruptDone <- e.Interrupt()
	})
	defer func() {
		if !stopInterrupt() {
			if interruptErr := <-interruptDone; interruptErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("interrupt SFTP line editor prompt failed: %w", interruptErr))
			}
		}
	}()
	e.instance.SetPrompt(prompt)
	result, err = e.instance.Readline()
	return result, errors.Join(retErr, err)
}

func (e *lineEditor) beginPrompt() (chan struct{}, error) {
	e.promptMu.Lock()
	defer e.promptMu.Unlock()
	if e.closing {
		return nil, fmt.Errorf("sftp line editor is closed")
	}
	if e.promptDone != nil {
		return nil, fmt.Errorf("sftp line editor already has an active prompt")
	}
	done := make(chan struct{})
	e.promptDone = done
	return done, nil
}

func (e *lineEditor) endPrompt(done chan struct{}) {
	e.promptMu.Lock()
	if e.promptDone == done {
		e.promptDone = nil
		close(done)
	}
	e.promptMu.Unlock()
}

func (e *lineEditor) AppendHistory(input string) error {
	return e.instance.SaveHistory(input)
}

// Interrupt 仅关闭 Shell 自己持有的 stdin 副本，用于唤醒正在阻塞的 Readline；
// 不会关闭进程级 os.Stdin，也不会影响其他终端使用者。
func (e *lineEditor) Interrupt() error {
	e.inputOnce.Do(func() {
		e.inputErr = e.input.Interrupt()
	})
	return e.inputErr
}

func (e *lineEditor) Close() error {
	e.closeOnce.Do(func() {
		<-e.ready
		e.promptMu.Lock()
		e.closing = true
		promptDone := e.promptDone
		e.promptMu.Unlock()
		inputErr := e.Interrupt()
		if promptDone != nil {
			<-promptDone
		}
		editorErr := e.instance.Close()
		closeInputErr := e.input.Close()
		switch {
		case inputErr != nil && editorErr != nil && closeInputErr != nil:
			e.closeErr = fmt.Errorf("interrupt prompt input failed: %w; close line editor failed: %w; close prompt input failed: %w", inputErr, editorErr, closeInputErr)
		case inputErr != nil && editorErr != nil:
			e.closeErr = fmt.Errorf("interrupt prompt input failed: %w; close line editor failed: %w", inputErr, editorErr)
		case inputErr != nil && closeInputErr != nil:
			e.closeErr = fmt.Errorf("interrupt prompt input failed: %w; close prompt input failed: %w", inputErr, closeInputErr)
		case editorErr != nil && closeInputErr != nil:
			e.closeErr = fmt.Errorf("close line editor failed: %w; close prompt input failed: %w", editorErr, closeInputErr)
		case inputErr != nil:
			e.closeErr = fmt.Errorf("interrupt prompt input failed: %w", inputErr)
		case editorErr != nil:
			e.closeErr = fmt.Errorf("close line editor failed: %w", editorErr)
		case closeInputErr != nil:
			e.closeErr = fmt.Errorf("close prompt input failed: %w", closeInputErr)
		}
	})
	return e.closeErr
}

type promptInput interface {
	io.ReadCloser
	Interrupt() error
}

type closablePromptInput struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (i *closablePromptInput) Interrupt() error {
	i.once.Do(func() {
		i.err = i.ReadCloser.Close()
	})
	return i.err
}

func (i *closablePromptInput) Close() error {
	return i.Interrupt()
}

type shellCompleter struct {
	shell *Shell
}

func (c shellCompleter) Do(line []rune, pos int) ([][]rune, int) {
	// readline invokes completion without a request context. Give this bounded
	// callback its own context instead of retaining Run's context in the editor.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	head, completions, _ := c.shell.wordCompleter(ctx, string(line), pos)
	typedRunes := line[len([]rune(head)):pos]
	candidates := make([][]rune, 0, len(completions))
	for _, completion := range completions {
		completionRunes := []rune(completion)
		if len(completionRunes) < len(typedRunes) || string(completionRunes[:len(typedRunes)]) != string(typedRunes) {
			continue
		}
		candidates = append(candidates, append([]rune(nil), completionRunes[len(typedRunes):]...))
	}
	return candidates, len(typedRunes)
}
