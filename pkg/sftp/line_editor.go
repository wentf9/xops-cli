package sftp

import (
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/chzyer/readline"
)

type lineEditor struct {
	instance   *readline.Instance
	input      promptInput
	inputOnce  sync.Once
	inputErr   error
	promptUsed atomic.Bool
	closeOnce  sync.Once
	closeErr   error
}

func newLineEditor(stdin io.Reader, stdout, stderr io.Writer, historyFile string, shell *Shell) (*lineEditor, error) {
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
	return &lineEditor{instance: instance, input: input}, nil
}

func (e *lineEditor) Prompt(prompt string) (string, error) {
	e.promptUsed.Store(true)
	e.instance.SetPrompt(prompt)
	return e.instance.Readline()
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
		inputErr := e.Interrupt()
		// chzyer/readline 在 terminal goroutine 内登记 WaitGroup。若编辑器从未进入
		// Prompt，先 KickRead 并等待其完成登记，避免 Close 与 Add 并发。
		if !e.promptUsed.Load() {
			e.instance.Terminal.KickRead()
			for !e.instance.Terminal.IsReading() {
				runtime.Gosched()
			}
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
	head, completions, _ := c.shell.wordCompleter(string(line), pos)
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
