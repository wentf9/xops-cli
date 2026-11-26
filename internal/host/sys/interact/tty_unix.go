//go:build unix

package interact

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/unix"
)

func probeFileTTYOS(in, out *os.File) (bool, error) {
	if in == nil || out == nil {
		return false, nil
	}
	_, inErr := unix.IoctlGetTermios(int(in.Fd()), ioctlReadTermios)
	runtime.KeepAlive(in)
	if inErr != nil {
		return false, nil
	}
	_, outErr := unix.IoctlGetTermios(int(out.Fd()), ioctlReadTermios)
	runtime.KeepAlive(out)
	return outErr == nil, nil
}

func probeControllingTTYOS() (bool, error) {
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, nil
	}
	defer func() { _ = unix.Close(fd) }()
	_, tErr := unix.IoctlGetTermios(fd, ioctlReadTermios)
	return tErr == nil, nil
}

func promptTTYLineOS(ctx context.Context, in, out *os.File, allowDevTTY bool, prompt string, noEcho bool) ([]byte, error) {
	if isTTY, _ := probeFileTTYOS(in, out); isTTY {
		defer runtime.KeepAlive(in)
		defer runtime.KeepAlive(out)
		return readPromptFromUnixFDs(ctx, int(in.Fd()), int(out.Fd()), prompt, noEcho)
	}
	if !allowDevTTY {
		return nil, ports.ErrInteractionUnavailable
	}
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ports.ErrInteractionUnavailable
	}
	defer func() { _ = unix.Close(fd) }()
	if _, tErr := unix.IoctlGetTermios(fd, ioctlReadTermios); tErr != nil {
		return nil, ports.ErrInteractionUnavailable
	}
	return readPromptFromUnixFDs(ctx, fd, fd, prompt, noEcho)
}

func readPromptFromUnixFDs(ctx context.Context, inFD, outFD int, prompt string, noEcho bool) ([]byte, error) {
	if err := writeAllUnixFD(outFD, []byte(prompt)); err != nil {
		return nil, err
	}
	if noEcho {
		restore, err := disableEchoUnixFD(inFD)
		if err != nil {
			return nil, err
		}
		defer func() {
			_ = restore()
			_ = writeAllUnixFD(outFD, []byte("\n"))
		}()
	}
	return readCancelableLineUnixFD(ctx, inFD)
}

func disableEchoUnixFD(fd int) (func() error, error) {
	orig, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, fmt.Errorf("读取 Unix 终端 termios 失败: %w", err)
	}
	saved := *orig
	muted := *orig
	muted.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &muted); err != nil {
		return nil, fmt.Errorf("禁用 Unix 终端回显失败: %w", err)
	}
	return func() error {
		return unix.IoctlSetTermios(fd, ioctlWriteTermios, &saved)
	}, nil
}

func readCancelableLineUnixFD(ctx context.Context, inFD int) ([]byte, error) {
	wakeR, wakeW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("创建终端唤醒管道失败: %w", err)
	}
	defer func() {
		_ = wakeW.Close()
		_ = wakeR.Close()
	}()
	stop := context.AfterFunc(ctx, func() { _ = wakeW.Close() })
	defer stop()

	fds := []unix.PollFd{
		{Fd: int32(inFD), Events: unix.POLLIN},
		{Fd: int32(wakeR.Fd()), Events: unix.POLLIN},
	}
	var out []byte
	var one [1]byte
	for len(out) < maxPromptLineBytes {
		if err := pollNextByteUnix(ctx, fds, wakeR); err != nil {
			clear(out)
			return nil, err
		}
		n, rErr := readByteUnixFD(inFD, one[:])
		if rErr != nil {
			clear(out)
			return nil, rErr
		}
		if n == 0 {
			if len(out) > 0 {
				return out, nil
			}
			return nil, ports.ErrInteractionCanceled
		}
		if one[0] == '\n' {
			return out, nil
		}
		out = append(out, one[0])
	}
	return out, nil
}

func pollNextByteUnix(ctx context.Context, fds []unix.PollFd, wakeR *os.File) error {
	for {
		_, err := unix.Poll(fds, -1)
		runtime.KeepAlive(wakeR)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if fds[1].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLNVAL) != 0 {
			if cErr := ctx.Err(); cErr != nil {
				return cErr
			}
			return ports.ErrInteractionCanceled
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return nil
		}
	}
}

func readByteUnixFD(fd int, buf []byte) (int, error) {
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return n, err
	}
}

func writeAllUnixFD(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
