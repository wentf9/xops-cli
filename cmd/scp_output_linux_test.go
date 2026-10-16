//go:build linux

package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/internal/testpty"
	"golang.org/x/sys/unix"
)

func TestSCPProgressPausedTerminalCancellation(t *testing.T) {
	master, slave, err := testpty.Open()
	if err != nil {
		t.Fatal(err)
	}
	// The fixture owns the PTY pair. Process streams remain borrowed.
	defer closeSCPTestResource(t, master)
	defer closeSCPTestResource(t, slave)
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = slave, slave
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	if err := unix.IoctlSetInt(int(slave.Fd()), unix.TCXONC, unix.TCOOFF); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.IoctlSetInt(int(slave.Fd()), unix.TCXONC, unix.TCOON) }()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	progress, finish := (&ScpOptions{}).createTransferProgress(ctx, 64*1024, "paused", 0)
	if progress == nil {
		t.Fatal("Linux terminal progress disabled")
	}
	// Gate only the fixture callback after the real progress callback returns.
	// Cancellation must then join the transfer while terminal output stays paused.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	done := make(chan error, 1)
	go func() {
		client := &sftp.Client{}
		done <- client.StreamTransfer(ctx, client, strings.NewReader(strings.Repeat("x", 64*1024)), io.Discard, 64*1024, func(n int64) {
			progress(n)
			close(entered)
			<-release
		})
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		// Unpause before joining on a failing old implementation.
		_ = unix.IoctlSetInt(int(slave.Fd()), unix.TCXONC, unix.TCOON)
		cancel()
		once.Do(func() { close(release) })
		<-done
		_ = finish()
		t.Fatal("progress callback blocked on paused terminal")
	}
	cancel()
	once.Do(func() { close(release) })
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		_ = unix.IoctlSetInt(int(slave.Fd()), unix.TCXONC, unix.TCOON)
		<-done
		_ = finish()
		t.Fatal("paused terminal blocked transfer cancellation")
	}
	err = finish()
	var outputErr *SCPOutputError
	if !errors.As(err, &outputErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("output cancellation lost: %v", err)
	}
	if _, err := slave.Stat(); err != nil {
		t.Fatalf("borrowed stderr closed: %v", err)
	}
}

// Exercise both actual selector status branches against a full native pipe.
// The fixture owns the pipe and joins the transfer before restoring stdio.
func TestSCPSelectorStatusBlockedPipe(t *testing.T) {
	for _, mode := range []string{"skip", "success"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newSCPTransferFixture(t)
			options := NewScpOptions()
			options.Host, options.Dest = "scp-test", "status-target.txt"
			options.Source = filepath.Join(t.TempDir(), "payload.txt")
			writeSCPTestFile(t, options.Source, "uploaded payload")
			want := "uploaded payload"
			stream := "stdout"
			if mode == "skip" {
				want, stream = "existing payload", "stderr"
				writeSCPTestFile(t, filepath.Join(fixture.home, options.Dest), want)
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer closeSCPTestResource(t, writer)
			// Closing reader is also the failure-path interrupt for old raw writes.
			var closeReader sync.Once
			releaseReader := func() { closeReader.Do(func() { closeSCPTestResource(t, reader) }) }
			defer releaseReader()
			capacity, err := unix.FcntlInt(writer.Fd(), unix.F_GETPIPE_SZ, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(make([]byte, capacity)); err != nil {
				t.Fatal(err)
			}
			stdout, stderr := os.Stdout, os.Stderr
			if mode == "skip" {
				os.Stderr = writer
			} else {
				os.Stdout = writer
			}
			defer func() { os.Stdout, os.Stderr = stdout, stderr }()
			done := make(chan error, 1)
			go func() { done <- options.runTransfer(fixture.ctx, fixture.repo, fixture.connector) }()
			select {
			case err := <-done:
				var outputErr *SCPOutputError
				if !errors.As(err, &outputErr) || outputErr.Stream != stream {
					t.Fatalf("status output failure lost: %v", err)
				}
			case <-time.After(3 * time.Second):
				releaseReader()
				<-done
				t.Fatal("status output blocked transfer shutdown")
			}
			assertSCPTestFile(t, filepath.Join(fixture.home, options.Dest), want)
			if _, err := writer.Stat(); err != nil {
				t.Fatalf("borrowed status stream closed: %v", err)
			}
		})
	}
}
