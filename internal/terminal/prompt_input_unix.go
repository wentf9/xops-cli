//go:build !windows

package terminal

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type pollPromptInput struct {
	file          *os.File
	cancelReader  *os.File
	cancelWriter  *os.File
	interruptOnce sync.Once
	interruptErr  error
	closeOnce     sync.Once
	closeErr      error
}

const promptPollTimeoutMilliseconds = 1000

// DuplicatePromptInput duplicates an input stream and equips it with an interrupt pipe.
func DuplicatePromptInput(input io.Reader) (PromptInput, error) {
	file, ok := input.(*os.File)
	if !ok {
		if closer, hasCloser := input.(io.ReadCloser); hasCloser {
			return &ClosablePromptInput{ReadCloser: closer}, nil
		}
		return nil, fmt.Errorf("prompt input must be an *os.File or io.ReadCloser")
	}
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	duplicate := os.NewFile(uintptr(fd), file.Name())
	cancelReader, cancelWriter, err := os.Pipe()
	if err != nil {
		if closeErr := duplicate.Close(); closeErr != nil {
			return nil, fmt.Errorf("create prompt cancellation pipe failed: %w; close duplicated prompt input failed: %w", err, closeErr)
		}
		return nil, fmt.Errorf("create prompt cancellation pipe failed: %w", err)
	}
	return &pollPromptInput{
		file:         duplicate,
		cancelReader: cancelReader,
		cancelWriter: cancelWriter,
	}, nil
}

func (i *pollPromptInput) Read(buffer []byte) (int, error) {
	pollFDs := []unix.PollFd{
		{Fd: int32(i.file.Fd()), Events: unix.POLLIN},
		{Fd: int32(i.cancelReader.Fd()), Events: unix.POLLIN},
	}
	for {
		ready, err := unix.Poll(pollFDs, promptPollTimeoutMilliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("poll prompt input failed: %w", err)
		}
		if ready == 0 {
			continue
		}
		if pollFDs[1].Revents != 0 {
			return 0, io.EOF
		}
		if pollFDs[0].Revents != 0 {
			return i.file.Read(buffer)
		}
	}
}

func (i *pollPromptInput) Interrupt() error {
	i.interruptOnce.Do(func() {
		i.interruptErr = i.cancelWriter.Close()
	})
	return i.interruptErr
}

func (i *pollPromptInput) Close() error {
	i.closeOnce.Do(func() {
		interruptErr := i.Interrupt()
		fileErr := i.file.Close()
		cancelReaderErr := i.cancelReader.Close()
		switch {
		case interruptErr != nil && fileErr != nil && cancelReaderErr != nil:
			i.closeErr = fmt.Errorf("interrupt prompt input failed: %w; close prompt file failed: %w; close prompt cancellation reader failed: %w", interruptErr, fileErr, cancelReaderErr)
		case interruptErr != nil && fileErr != nil:
			i.closeErr = fmt.Errorf("interrupt prompt input failed: %w; close prompt file failed: %w", interruptErr, fileErr)
		case interruptErr != nil && cancelReaderErr != nil:
			i.closeErr = fmt.Errorf("interrupt prompt input failed: %w; close prompt cancellation reader failed: %w", interruptErr, cancelReaderErr)
		case fileErr != nil && cancelReaderErr != nil:
			i.closeErr = fmt.Errorf("close prompt file failed: %w; close prompt cancellation reader failed: %w", fileErr, cancelReaderErr)
		case interruptErr != nil:
			i.closeErr = fmt.Errorf("interrupt prompt input failed: %w", interruptErr)
		case fileErr != nil:
			i.closeErr = fmt.Errorf("close prompt file failed: %w", fileErr)
		case cancelReaderErr != nil:
			i.closeErr = fmt.Errorf("close prompt cancellation reader failed: %w", cancelReaderErr)
		}
	})
	return i.closeErr
}
