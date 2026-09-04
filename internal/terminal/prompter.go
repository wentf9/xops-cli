package terminal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unicode/utf8"

	"golang.org/x/term"
)

type stdPrompter struct {
	stdin      io.Reader
	stdout     io.Writer
	isTerminal func(fd int) bool
	makeRaw    func(fd int) (*term.State, error)
	restore    func(fd int, state *term.State) error
}

func (p *stdPrompter) ReadLine(ctx context.Context, prompt string) (lineResult string, retErr error) {
	if ctx == nil {
		return "", fmt.Errorf("context is nil")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if prompt != "" && p.stdout != nil {
		if _, err := fmt.Fprint(p.stdout, prompt); err != nil {
			return "", fmt.Errorf("write prompt failed: %w", err)
		}
	}

	defer func() {
		if retErr != nil {
			lineResult = ""
		}
	}()

	input, cleanup, err := setupPromptInput(ctx, p.stdin)
	if err != nil {
		return "", err
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()

	lineResult, retErr = p.readLineLoop(ctx, input)
	return lineResult, retErr
}

func (p *stdPrompter) readLineLoop(ctx context.Context, input PromptInput) (string, error) {
	var line bytes.Buffer
	buf := make([]byte, 1)
	for {
		n, readErr := input.Read(buf)
		if n > 0 {
			switch processReadLineByte(buf[0], &line) {
			case secretActionDone:
				return line.String(), nil
			case secretActionCanceled:
				return "", context.Canceled
			case secretActionEOF:
				return "", io.EOF
			case secretActionContinue:
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if err := ctx.Err(); err != nil {
					return "", err
				}
				if line.Len() > 0 {
					return line.String(), nil
				}
				return "", io.EOF
			}
			if err := ctx.Err(); err != nil {
				return "", err
			}
			return "", fmt.Errorf("read line failed: %w", readErr)
		}
	}
}

func (p *stdPrompter) ReadSecret(ctx context.Context, prompt string) (secretResult string, retErr error) {
	if ctx == nil {
		return "", fmt.Errorf("context is nil")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	promptPrinted := false
	if prompt != "" && p.stdout != nil {
		if _, err := fmt.Fprint(p.stdout, prompt); err != nil {
			return "", fmt.Errorf("write secret prompt failed: %w", err)
		}
		promptPrinted = true
	}

	defer func() {
		if retErr != nil {
			secretResult = ""
		}
	}()

	restoreCleanup, isTerminal, rawErr := p.enterRawMode(p.stdin)
	if rawErr != nil {
		return "", rawErr
	}
	if restoreCleanup != nil {
		defer func() {
			if restoreErr := restoreCleanup(); restoreErr != nil {
				retErr = errors.Join(retErr, restoreErr)
			}
			if promptPrinted && isTerminal && p.stdout != nil {
				if _, printErr := fmt.Fprint(p.stdout, "\r\n"); printErr != nil {
					retErr = errors.Join(retErr, fmt.Errorf("write newline failed: %w", printErr))
				}
			}
		}()
	}

	input, cleanup, err := setupPromptInput(ctx, p.stdin)
	if err != nil {
		return "", err
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()

	secret, _, loopErr := p.readSecretLoop(ctx, input, isTerminal)
	if loopErr != nil {
		retErr = loopErr
		return "", retErr
	}
	secretResult = secret
	return secretResult, retErr
}

func (p *stdPrompter) readSecretLoop(ctx context.Context, input PromptInput, isTerminal bool) (string, bool, error) {
	var secret []byte
	buf := make([]byte, 1)
	for {
		n, readErr := input.Read(buf)
		if n > 0 {
			b := buf[0]
			if isTerminal {
				switch processTerminalSecretByte(b, &secret) {
				case secretActionDone:
					return string(secret), true, nil
				case secretActionCanceled:
					return "", false, context.Canceled
				case secretActionEOF:
					return "", false, io.EOF
				case secretActionContinue:
				}
			} else {
				if b == '\n' {
					return string(secret), false, nil
				}
				if b != '\r' {
					secret = append(secret, b)
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if err := ctx.Err(); err != nil {
					return "", false, err
				}
				if len(secret) > 0 {
					return string(secret), false, nil
				}
				return "", false, io.EOF
			}
			if err := ctx.Err(); err != nil {
				return "", false, err
			}
			return "", false, fmt.Errorf("read secret failed: %w", readErr)
		}
	}
}

type secretByteAction int

const (
	secretActionContinue secretByteAction = iota
	secretActionDone
	secretActionCanceled
	secretActionEOF
)

func processReadLineByte(b byte, line *bytes.Buffer) secretByteAction {
	switch b {
	case '\n':
		return secretActionDone
	case '\r':
		return secretActionContinue
	case 3: // Ctrl+C
		return secretActionCanceled
	case 4: // Ctrl+D
		if line.Len() == 0 {
			return secretActionEOF
		}
		return secretActionDone
	case 127, 8: // Backspace / DEL
		if line.Len() > 0 {
			bs := line.Bytes()
			_, size := utf8.DecodeLastRune(bs)
			line.Truncate(len(bs) - size)
		}
		return secretActionContinue
	default:
		line.WriteByte(b)
		return secretActionContinue
	}
}

func processTerminalSecretByte(b byte, secret *[]byte) secretByteAction {
	switch b {
	case '\r', '\n':
		return secretActionDone
	case 3: // Ctrl+C
		return secretActionCanceled
	case 4: // Ctrl+D
		if len(*secret) == 0 {
			return secretActionEOF
		}
		return secretActionDone
	case 127, 8: // Backspace / DEL
		if len(*secret) > 0 {
			_, size := utf8.DecodeLastRune(*secret)
			*secret = (*secret)[:len(*secret)-size]
		}
		return secretActionContinue
	default:
		*secret = append(*secret, b)
		return secretActionContinue
	}
}

func (p *stdPrompter) enterRawMode(stdin io.Reader) (func() error, bool, error) {
	file, isFile := stdin.(*os.File)
	isTerminalFn := p.isTerminal
	if isTerminalFn == nil {
		isTerminalFn = term.IsTerminal
	}
	if !isFile || !isTerminalFn(int(file.Fd())) {
		return nil, false, nil
	}

	makeRawFn := p.makeRaw
	if makeRawFn == nil {
		makeRawFn = term.MakeRaw
	}
	restoreFn := p.restore
	if restoreFn == nil {
		restoreFn = term.Restore
	}

	oldState, stateErr := makeRawFn(int(file.Fd()))
	if stateErr != nil {
		return nil, false, fmt.Errorf("set terminal to raw mode failed: %w", stateErr)
	}

	sigChan := make(chan os.Signal, 1)
	sigDone := make(chan struct{})
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var restoreOnce sync.Once
	var restoreErr error

	restoreCleanup := func() error {
		restoreOnce.Do(func() {
			signal.Stop(sigChan)
			close(sigDone)
			if err := restoreFn(int(file.Fd()), oldState); err != nil {
				restoreErr = fmt.Errorf("restore terminal mode failed: %w", err)
			}
		})
		return restoreErr
	}

	go func() {
		select {
		case <-sigChan:
			_ = restoreCleanup()
			os.Exit(130)
		case <-sigDone:
		}
	}()

	return restoreCleanup, true, nil
}

func setupPromptInput(ctx context.Context, r io.Reader) (PromptInput, func() error, error) {
	input, err := DuplicatePromptInput(r)
	if err != nil {
		return nil, nil, fmt.Errorf("duplicate prompt input failed: %w", err)
	}

	interruptDone := make(chan error, 1)
	stopInterrupt := context.AfterFunc(ctx, func() {
		interruptDone <- input.Interrupt()
	})

	cleanup := func() error {
		var errs error
		if !stopInterrupt() {
			if interruptErr := <-interruptDone; interruptErr != nil && !errors.Is(interruptErr, os.ErrClosed) {
				errs = errors.Join(errs, fmt.Errorf("interrupt prompt input failed: %w", interruptErr))
			}
		}
		if closeErr := input.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			errs = errors.Join(errs, fmt.Errorf("close prompt input failed: %w", closeErr))
		}
		return errs
	}
	return input, cleanup, nil
}
