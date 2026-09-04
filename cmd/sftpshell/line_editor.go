package sftpshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"github.com/wentf9/xops-cli/internal/terminal"
)

type lineEditor struct {
	instance    *readline.Instance
	input       terminal.PromptInput
	inputOnce   sync.Once
	inputErr    error
	platform    *lineEditorPlatform
	promptMu    sync.Mutex
	promptDone  chan struct{}
	readStarted bool
	closing     bool
	closeOnce   sync.Once
	closeErr    error
}

func newLineEditor(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, historyFile string, shell *Shell) (*lineEditor, error) {
	if ctx == nil {
		return nil, fmt.Errorf("line editor context is nil")
	}
	input, err := terminal.DuplicatePromptInput(stdin)
	if err != nil {
		return nil, fmt.Errorf("duplicate prompt input failed: %w", err)
	}

	platform := newLineEditorPlatform(stdin)
	config := &readline.Config{
		HistoryFile:            historyFile,
		DisableAutoSaveHistory: true,
		InterruptPrompt:        "^C",
		EOFPrompt:              "^D",
		Stdin:                  input,
		Stdout:                 stdout,
		Stderr:                 stderr,
		AutoComplete:           shellCompleter{shell: shell},
	}
	platform.configure(config)
	instance, err := readline.NewEx(config)
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
	editor := &lineEditor{instance: instance, input: input, platform: platform}
	platform.start(ctx, instance)
	return editor, nil
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
	if err := e.platform.preparePrompt(); err != nil {
		return "", err
	}
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
	e.markPromptReadStarted()
	result, err = e.instance.Readline()
	return result, errors.Join(retErr, e.platform.finishPrompt(err))
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

func (e *lineEditor) markPromptReadStarted() {
	e.promptMu.Lock()
	e.readStarted = true
	e.promptMu.Unlock()
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
		e.platform.waitBeforeClose()
		e.promptMu.Lock()
		e.closing = true
		promptDone := e.promptDone
		e.promptMu.Unlock()
		inputErr := e.Interrupt()
		if promptDone != nil {
			<-promptDone
		}
		e.promptMu.Lock()
		readStarted := e.readStarted
		e.promptMu.Unlock()
		e.platform.prepareInstanceClose(e.instance, readStarted)
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
