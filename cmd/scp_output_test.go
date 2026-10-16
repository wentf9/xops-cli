package cmd

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/internal/testpty"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func TestSCPOutputFlags(t *testing.T) {
	for _, tc := range []struct {
		args           []string
		quiet, verbose bool
	}{
		{nil, false, false},
		{[]string{"-q"}, true, false},
		{[]string{"--quiet"}, true, false},
		{[]string{"-v"}, false, true},
		{[]string{"--verbose"}, false, true},
		{[]string{"-qv"}, true, true},
	} {
		cmd := NewCmdScp()
		if err := cmd.ParseFlags(tc.args); err != nil {
			t.Fatal(err)
		}
		quiet, err := cmd.Flags().GetBool("quiet")
		if err != nil {
			t.Fatal(err)
		}
		verbose, err := cmd.Flags().GetBool("verbose")
		if err != nil {
			t.Fatal(err)
		}
		if quiet != tc.quiet || verbose != tc.verbose {
			t.Fatalf("flags %v: quiet=%v verbose=%v", tc.args, quiet, verbose)
		}
	}
}

func TestSCPVerboseLogLevel(t *testing.T) {
	t.Setenv("XOPS_CONFIG_DIR", t.TempDir())
	previous := logger.LogLevel.Level()
	t.Cleanup(func() { logger.LogLevel.Set(previous) })
	for _, tc := range []struct {
		args  []string
		level slog.Level
	}{
		{[]string{"-v"}, slog.Level(100)},
		{[]string{"-qv"}, slog.Level(100)},
		{[]string{"--log-level=error", "-v"}, slog.LevelError},
		{[]string{"--log-level=error", "-q"}, slog.LevelError},
		{[]string{"--log-level=debug"}, slog.LevelDebug},
		{[]string{"--debug", "--verbose=false"}, slog.LevelDebug},
		{nil, slog.Level(100)},
	} {
		root := newRootCmd()
		initRootFlags(root)
		scp := NewCmdScp()
		called := false
		scp.RunE = func(*cobra.Command, []string) error {
			called = true
			if got := logger.LogLevel.Level(); got != tc.level {
				t.Fatalf("flags %v: log level=%v, want %v", tc.args, got, tc.level)
			}
			return nil
		}
		root.AddCommand(scp)
		root.SetArgs(append([]string{"scp"}, tc.args...))
		if err := root.ExecuteContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("SCP command was not dispatched")
		}
	}
}

// captureSCPOutput owns the PTY pair and reader goroutine. It restores borrowed
// process streams, closes its files, and joins the reader on completion/timeout.
func captureSCPOutput(t *testing.T, terminal bool, run func()) string {
	t.Helper()
	if !terminal {
		file, err := os.CreateTemp(t.TempDir(), "scp-output-")
		if err != nil {
			t.Fatal(err)
		}
		defer closeSCPTestResource(t, file)
		stdout, stderr := os.Stdout, os.Stderr
		os.Stdout, os.Stderr = file, file
		defer func() { os.Stdout, os.Stderr = stdout, stderr }()
		run()
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if runtime.GOOS == "windows" {
		t.Skip("Unix PTY output test; Windows console behavior is left to native CI")
	}
	master, slave, err := testpty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer closeSCPTestResource(t, slave)
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = slave, slave
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	type result struct {
		data string
		err  error
	}
	done := make(chan result, 1)
	joined := false
	defer func() {
		closeSCPTestResource(t, master)
		if !joined {
			<-done
		}
	}()
	go func() {
		data, err := bufio.NewReader(master).ReadString(0)
		done <- result{strings.TrimSuffix(data, "\x00"), err}
	}()
	// Even if run calls Fatal, deferred cleanup closes master and unblocks the reader.
	run()
	if _, err := fmt.Fprint(slave, "\x00"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		joined = true
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.data
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading SCP terminal output")
		return ""
	}
}

func TestSCPProgressOutput(t *testing.T) {
	for _, mode := range []string{"upload", "download", "relay", "selector", "directory upload", "directory download"} {
		for _, output := range []string{"terminal", "quiet", "redirected"} {
			t.Run(mode+"/"+output, func(t *testing.T) {
				fixture := newSCPTransferFixture(t)
				local := filepath.Join(t.TempDir(), "payload.txt")
				writeSCPTestFile(t, local, "progress payload")
				writeSCPTestFile(t, filepath.Join(fixture.home, "payload.txt"), "progress payload")
				options := NewScpOptions()
				options.Quiet = output == "quiet"
				options.Source, options.Dest = local, "scp-test:uploaded.txt"
				description := "Uploading"
				switch mode {
				case "download":
					options.Source, options.Dest = "scp-test:payload.txt", filepath.Join(t.TempDir(), "downloaded.txt")
					description = "Downloading"
				case "relay":
					options.Source, options.Dest = "scp-test:payload.txt", "scp-test:relayed.txt"
					description = "Relaying"
				case "selector":
					options.Host, options.Dest = "scp-test", "selected.txt"
				case "directory upload":
					options.Recursive = true
					options.Source, options.Dest = filepath.Dir(local), "scp-test:uploaded-directory"
				case "directory download":
					remoteDirectory := filepath.Join(fixture.home, "directory")
					if err := os.Mkdir(remoteDirectory, 0o700); err != nil {
						t.Fatal(err)
					}
					writeSCPTestFile(t, filepath.Join(remoteDirectory, "payload.txt"), "directory payload")
					options.Recursive = true
					options.Source, options.Dest = "scp-test:directory", filepath.Join(t.TempDir(), "downloaded-directory")
					description = "Downloading"
				}
				var transferErr error
				captured := captureSCPOutput(t, output != "redirected", func() {
					transferErr = options.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
				})
				if transferErr != nil {
					t.Fatal(transferErr)
				}
				// Native console bindings outside Linux are deliberately disabled
				// until they can guarantee cancelable output; transfers still run.
				wantProgress := output == "terminal" && runtime.GOOS == "linux"
				if got, want := strings.Contains(captured, description), wantProgress; got != want {
					t.Fatalf("progress present=%v, want %v; output=%q", got, want, captured)
				}
				if output == "quiet" && captured != "" {
					t.Fatalf("quiet transfer emitted output: %q", captured)
				}
				if wantProgress && !strings.HasSuffix(captured, "\n") {
					t.Fatalf("progress did not finish its terminal line: %q", captured)
				}
			})
		}
	}
}
