//go:build linux

package testpty

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenPreservesPTYPairDuringStackRelocation(t *testing.T) {
	// Occupy the first available PTY so an incorrectly zeroed slave number
	// cannot accidentally identify the new master on an otherwise idle host.
	master, slave, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := errors.Join(slave.Close(), master.Close()); err != nil {
			t.Errorf("close reserved PTY pair: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	gcDone := make(chan struct{})
	go func() {
		defer close(gcDone)
		for ctx.Err() == nil {
			runtime.GC()
		}
	}()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait(); <-gcDone }()
	for i := range 4096 {
		done := make(chan error, 1)
		workers.Go(func() {
			growPTYStack(32)
			if err := ctx.Err(); err != nil {
				done <- err
				return
			}
			done <- checkPTYAtDepth(i % 100)
		})
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("PTY pair %d: %v", i, err)
			}
		case <-ctx.Done():
			t.Fatal("PTY allocation did not finish within its deadline")
		}
	}
}

// Grow before allocation so GC can shrink the stack during an ioctl.
//
//go:noinline
func growPTYStack(depth int) {
	var padding [1024]byte
	if depth > 0 {
		growPTYStack(depth - 1)
	}
	runtime.KeepAlive(padding)
}

//go:noinline
func checkPTYAtDepth(depth int) error {
	var padding [127]byte
	padding[0] = byte(depth)
	var err error
	if depth > 0 {
		err = checkPTYAtDepth(depth - 1)
	} else {
		err = checkPTYPair()
	}
	runtime.KeepAlive(padding)
	return err
}

func checkPTYPair() (retErr error) {
	master, slave, err := Open()
	if err != nil {
		return err
	}
	defer func() {
		if err := errors.Join(slave.Close(), master.Close()); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close PTY pair: %w", err))
		}
	}()
	number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		return fmt.Errorf("read master PTY number: %w", err)
	}
	want, err := os.Stat("/dev/pts/" + strconv.Itoa(number))
	if err != nil {
		return fmt.Errorf("stat master slave path: %w", err)
	}
	got, err := slave.Stat()
	if err != nil {
		return fmt.Errorf("stat opened slave: %w", err)
	}
	if !os.SameFile(got, want) {
		return fmt.Errorf("opened %s instead of master's slave /dev/pts/%d", slave.Name(), number)
	}
	if err := Setsize(master, &Winsize{Rows: 31, Cols: 79, X: 632, Y: 496}); err != nil {
		return err
	}
	size, err := unix.IoctlGetWinsize(int(slave.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return fmt.Errorf("read slave window size: %w", err)
	}
	if size.Row != 31 || size.Col != 79 || size.Xpixel != 632 || size.Ypixel != 496 {
		return fmt.Errorf("window size corrupted during ioctl: %+v", size)
	}
	return nil
}
