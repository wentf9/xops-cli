//go:build windows

package sftp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

type windowsPromptInput struct {
	file *os.File
	once sync.Once
	err  error
}

func duplicatePromptInput(input io.Reader) (promptInput, error) {
	file, ok := input.(*os.File)
	if !ok {
		if closer, hasCloser := input.(io.ReadCloser); hasCloser {
			return &closablePromptInput{ReadCloser: closer}, nil
		}
		return nil, fmt.Errorf("prompt input must be an *os.File or io.ReadCloser")
	}
	process := windows.CurrentProcess()
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(
		process,
		windows.Handle(file.Fd()),
		process,
		&duplicate,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return nil, err
	}
	return &windowsPromptInput{file: os.NewFile(uintptr(duplicate), file.Name())}, nil
}

func (i *windowsPromptInput) Read(buffer []byte) (int, error) {
	return i.file.Read(buffer)
}

func (i *windowsPromptInput) Interrupt() error {
	i.once.Do(func() {
		handle := windows.Handle(i.file.Fd())
		cancelErr := windows.CancelIoEx(handle, nil)
		if errors.Is(cancelErr, windows.ERROR_NOT_FOUND) || errors.Is(cancelErr, windows.ERROR_INVALID_HANDLE) {
			cancelErr = nil
		}
		closeErr := i.file.Close()
		switch {
		case cancelErr != nil && closeErr != nil:
			i.err = fmt.Errorf("cancel prompt input failed: %w; close prompt input failed: %w", cancelErr, closeErr)
		case cancelErr != nil:
			i.err = fmt.Errorf("cancel prompt input failed: %w", cancelErr)
		case closeErr != nil:
			i.err = fmt.Errorf("close prompt input failed: %w", closeErr)
		}
	})
	return i.err
}

func (i *windowsPromptInput) Close() error {
	return i.Interrupt()
}
