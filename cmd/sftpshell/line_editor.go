package sftpshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/term"
	"github.com/wentf9/xops-cli/pkg/logger"
)

var (
	// ErrLineEditorClosed indicates that the editor cannot start another prompt.
	ErrLineEditorClosed = errors.New("sftp line editor is closed")
	// ErrPromptInterrupted cancels an input line without ending the shell session.
	ErrPromptInterrupted = errors.New("sftp prompt interrupted")
)

// promptCleanupError takes precedence over EOF and keyboard interrupts.
// A terminal/output failure must not be treated as a normal shell exit.
type promptCleanupError struct{ error }

func (e *promptCleanupError) Unwrap() error { return e.error }

func joinPromptCleanup(result *error, cleanup error) {
	if cleanup != nil {
		*result = &promptCleanupError{errors.Join(*result, cleanup)}
	}
}

type promptOptions struct {
	text         string
	confirmation bool
}

type lineEditor struct {
	stdin    io.Reader
	stdout   io.Writer
	complete completionFunc
	history  *commandHistory
	session  *editorSession
	mu       sync.Mutex
	cancel   context.CancelFunc
	done     chan struct{}
	closed   bool
}

func newLineEditor(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, historyFile string, shell *Shell) (*lineEditor, error) {
	if ctx == nil {
		return nil, fmt.Errorf("line editor context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	session, err := shell.getEditorSession(historyFile, stderr)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &lineEditor{stdin: stdin, stdout: stdout, history: session.history, session: session, complete: shell.completeLine}, nil
}

func (e *lineEditor) Prompt(ctx context.Context, prompt string) (string, error) {
	return e.prompt(ctx, promptOptions{text: prompt})
}

func (e *lineEditor) prompt(ctx context.Context, options promptOptions) (line string, retErr error) {
	if ctx == nil {
		return "", fmt.Errorf("sftp line editor prompt context is nil")
	}
	if !e.session.prompt.TryLock() {
		return "", fmt.Errorf("SFTP session already has an active prompt")
	}
	releaseSession := sync.OnceFunc(e.session.prompt.Unlock)
	defer releaseSession()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return "", ErrLineEditorClosed
	}
	if e.done != nil {
		e.mu.Unlock()
		return "", fmt.Errorf("sftp line editor already has an active prompt")
	}
	done := make(chan struct{})
	e.done, e.cancel = done, cancel
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		var cleanup *promptCleanupError
		if e.closed && errors.Is(retErr, context.Canceled) && !errors.As(retErr, &cleanup) {
			retErr = ErrLineEditorClosed
		}
		e.done, e.cancel = nil, nil
		// Close must not return while a replacement editor is still excluded.
		releaseSession()
		close(done)
		e.mu.Unlock()
	}()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	input, err := newEditorInput(e.stdin)
	if err != nil {
		return "", err
	}
	defer func() { joinPromptCleanup(&retErr, input.Close()) }()
	restore, err := captureTerminalState(e.stdin, e.stdout)
	if err != nil {
		return "", err
	}
	defer func() { joinPromptCleanup(&retErr, restore()) }()
	if term.IsTerminal(input.Fd()) {
		if err := makeEditorRaw(input.Fd()); err != nil {
			return "", fmt.Errorf("enable SFTP terminal input failed: %w", err)
		}
	}
	output := &editorOutput{writer: e.stdout, cancel: cancel}
	defer func() { joinPromptCleanup(&retErr, output.Err()) }()
	worker := newCompletionWorker(ctx, e.complete)
	defer worker.Close()
	model := newEditorModel(options, e.history.Lines(), worker.Schedule)
	size := selectEditorTerminal(e.stdout, e.stdin)
	opts := []tea.ProgramOption{
		tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(output),
		tea.WithWindowSize(size.width, size.height),
		// The root context owns SIGINT/SIGTERM and joins prompt cleanup.
		tea.WithoutSignalHandler(),
	}
	if file, ok := e.stdout.(terminalFile); ok {
		opts = append(opts, tea.WithOutput(&editorFileOutput{editorOutput: output, file: file}))
	}
	if !logger.ColorEnabled() {
		opts = append(opts, tea.WithColorProfile(colorprofile.Ascii))
	}
	program := tea.NewProgram(model, opts...)
	worker.Start(program.Send)
	stopEvents := startEditorEvents(ctx, input, e.session, program.Send)
	stopResize := watchEditorSize(ctx, size, program.Send)
	interruptDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { input.Interrupt(); close(interruptDone) })
	defer func() {
		if !stop() {
			<-interruptDone
		}
	}()
	result, runErr := program.Run()
	// Stop and join the decoder, including events queued after submission.
	stopEvents()
	stopResize()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if runErr != nil {

		return "", fmt.Errorf("run SFTP prompt failed: %w", runErr)
	}
	final := result.(*editorModel)
	// Rendering has finished and cleared the edit area. Write once through the
	// checked output so even commands taller than the screen reach scrollback.
	if _, err := io.WriteString(output, final.transcript()); err != nil {
		return "", fmt.Errorf("write SFTP command echo failed: %w", err)
	}
	return final.input.Value(), final.err
}

func (e *lineEditor) isReading() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.done != nil
}

func (e *lineEditor) AppendHistory(input string) error { return e.history.Append(input) }

func (e *lineEditor) Interrupt() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
	}
	return nil
}

func (e *lineEditor) Close() error {
	e.mu.Lock()
	e.closed = true
	if e.cancel != nil {
		e.cancel()
	}
	done := e.done
	e.mu.Unlock()
	if done != nil {
		<-done
	}
	return nil
}
