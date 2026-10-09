package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBindOutputCapabilities(t *testing.T) {
	var noContext context.Context
	if _, _, _, err := BindOutput(noContext, io.Discard); err == nil {
		t.Fatal("nil context accepted")
	}
	var typedNil *bytes.Buffer
	if _, _, _, err := BindOutput(t.Context(), typedNil); err == nil {
		t.Fatal("typed nil output accepted")
	}
	writer, closeFn, cancelable, err := BindOutput(t.Context(), nil)
	if err != nil || writer != nil || cancelable {
		t.Fatalf("nil output changed: %v %v %v", writer, cancelable, err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}

	unknown := &unknownTerminalWriter{}
	writer, closeFn, cancelable, err = BindOutput(t.Context(), unknown)
	if err != nil || cancelable || writer != io.Writer(unknown) {
		t.Fatalf("unknown writer was not returned unchanged: %v %v", cancelable, err)
	}
	if err := closeFn(); err != nil || unknown.calls.Load() != 0 {
		t.Fatal("unknown writer invoked by binding")
	}

	var memory bytes.Buffer
	for _, target := range []io.Writer{&memory, io.Discard, cancelableTerminalWriter{}} {
		writer, closeFn, cancelable, err = BindOutput(t.Context(), target)
		if err != nil || !cancelable || writer == nil {
			t.Fatalf("%T not bound: %v %v", target, cancelable, err)
		}
		if err := closeFn(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBindOutputRegularFileAndNullDevice(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "out.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	writer, closeFn, cancelable, err := BindOutput(ctx, file)
	if err != nil || !cancelable {
		t.Fatalf("regular file rejected: %v %v", cancelable, err)
	}
	if _, err := writer.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	cancel()
	if n, err := writer.Write([]byte("after")); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled write reached file: %d %v", n, err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	// The borrowed file stays open and contains only pre-cancellation output.
	if _, err := file.Write([]byte("!")); err != nil {
		t.Fatalf("borrowed file was closed: %v", err)
	}
	if data, err := os.ReadFile(file.Name()); err != nil || string(data) != "before!" {
		t.Fatalf("file content %q, %v", data, err)
	}

	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("null device unavailable: %v", err)
	}
	defer func() {
		if err := null.Close(); err != nil {
			t.Error(err)
		}
	}()
	writer, closeFn, cancelable, err = BindOutput(t.Context(), null)
	if err != nil || !cancelable {
		t.Fatalf("null device rejected: %v %v", cancelable, err)
	}
	if _, err := writer.Write([]byte("discarded")); err != nil {
		t.Fatal(err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
}

func TestBindRunOutputModes(t *testing.T) {
	client := &Client{}
	var stream bytes.Buffer
	config, closeFn, err := client.bindRunOutput(t.Context(), &RunConfig{OutMode: OutputModeStream, StreamWriter: &stream, StreamPrefix: "[h] "})
	if err != nil {
		t.Fatal(err)
	}
	writer := newOutputWriter(config)
	if _, err := writer.Write([]byte("a\nb")); err != nil {
		t.Fatal(err)
	}
	if err := closeFn(); err != nil || stream.String() != "[h] a\n[h] b" {
		t.Fatalf("prefixed stream %q, %v", stream.String(), err)
	}

	file, err := os.CreateTemp(t.TempDir(), "run-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	config, closeFn, err = client.bindRunOutput(t.Context(), &RunConfig{OutMode: OutputModeFile, OutFile: file})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newOutputWriter(config).Write([]byte("file output")); err != nil {
		t.Fatal(err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(file.Name()); err != nil || string(data) != "file output" {
		t.Fatalf("file output %q, %v", data, err)
	}

	var typedNil *os.File
	if _, _, err := client.bindRunOutput(t.Context(), &RunConfig{OutMode: OutputModeFile, OutFile: typedNil}); err != nil {
		t.Fatalf("unset legacy file must stay an output-time error: %v", err)
	}
	if _, err := newOutputWriter(&RunConfig{OutMode: OutputModeFile}).Write([]byte("x")); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil file output accepted: %v", err)
	}
}

func TestLegacyBashPayloadMatchesHistoricalQuoting(t *testing.T) {
	historical := func(command string, login bool) string {
		flag := ""
		if login {
			flag = "-l "
		}
		return fmt.Sprintf("bash %s-c '%s'", flag, strings.ReplaceAll(command, "'", "'\\''"))
	}
	for _, command := range []string{"", "id -u", "echo 'quoted'", "a\nb", "$HOME `date` \"x\"", "unicode 世界", "''", "\\'"} {
		for _, login := range []bool{false, true} {
			if got, want := bashCommandPayload(command, login), historical(command, login); got != want {
				t.Fatalf("payload for %q login=%v: %q, want %q", command, login, got, want)
			}
		}
	}
	if bashScriptPayload(true) != "bash -l -s" || bashScriptPayload(false) != "bash -s" {
		t.Fatal("script payload changed")
	}
	plan, err := PlanCommand("echo 'quoted'", CommandOptions{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX, Login: LoginEnabled})
	if err != nil || plan.Payload() != historical("echo 'quoted'", true) {
		t.Fatalf("plan and legacy builders diverged: %q, %v", plan.Payload(), err)
	}
	if legacyBashPayload("") != "bash" || legacyBashPayload("x") != historical("x", false) {
		t.Fatal("legacy empty-command payload changed")
	}
}

func TestLegacyStreamingEntryPointPayloads(t *testing.T) {
	for _, test := range []struct {
		name, command, payload, input string
		run                           func(*Client) error
	}{
		{"command", "echo 'x'", "bash -c 'echo '\\''x'\\'''", "in", func(c *Client) error {
			return c.RunCommandWithIO(t.Context(), "echo 'x'", false, strings.NewReader("in"), io.Discard, io.Discard)
		}},
		{"empty command reads stdin", "", "bash", "script", func(c *Client) error {
			return c.RunCommandWithIO(t.Context(), "", false, strings.NewReader("script"), io.Discard, io.Discard)
		}},
		{"stream", "tail -f x", "bash -c 'tail -f x'", "", func(c *Client) error {
			stream, err := c.RunStream(t.Context(), "tail -f x")
			if err != nil {
				return err
			}
			_, readErr := io.ReadAll(stream)
			return errors.Join(readErr, stream.Close())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			scenario := &commandFixture{commands: make(chan string, 1), inputs: make(chan string, 1), output: "output"}
			client := commandTestClient(t, scenario)
			if err := test.run(client); err != nil {
				t.Fatal(err)
			}
			if got := <-scenario.commands; got != test.payload {
				t.Fatalf("payload %q, want %q", got, test.payload)
			}
			if test.name != "stream" {
				if got := <-scenario.inputs; got != test.input {
					t.Fatalf("stdin %q, want %q", got, test.input)
				}
			}
		})
	}
}

func TestLegacyFileOutputsReceiveCommandOutput(t *testing.T) {
	scenario := &commandFixture{output: "remote output"}
	client := commandTestClient(t, scenario)
	file, err := os.CreateTemp(t.TempDir(), "legacy-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := client.Run(t.Context(), "command", WithOutFile(file)); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(file.Name()); err != nil || !strings.Contains(string(data), "remote output") {
		t.Fatalf("legacy file output %q, %v", data, err)
	}
	var stdout, stderr bytes.Buffer
	if err := client.RunCommandWithIO(t.Context(), "command", false, nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "remote output" || stderr.String() != "stderr" {
		t.Fatalf("legacy command output %q / %q", stdout.String(), stderr.String())
	}
	if scenario.attempts.Load() != 2 {
		t.Fatal("unexpected command replay")
	}
}

func TestBindOutputStandardFileHandles(t *testing.T) {
	if runtime.GOOS != "linux" {
		for _, target := range []*os.File{os.Stdout, os.Stderr} {
			_, closeFn, cancelable, err := BindOutput(t.Context(), target)
			if err != nil {
				t.Fatalf("bind %s on %s: unexpected error %v", target.Name(), runtime.GOOS, err)
			}
			if cancelable {
				t.Fatalf("%s unexpectedly reported cancelable on %s", target.Name(), runtime.GOOS)
			}
			if err := closeFn(); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for _, target := range []*os.File{os.Stdout, os.Stderr} {
		writer, closeFn, cancelable, err := BindOutput(t.Context(), target)
		if err != nil {
			t.Fatalf("bind %s: %v", target.Name(), err)
		}
		if !cancelable {
			t.Fatalf("%s not cancelable", target.Name())
		}
		if writer == nil {
			t.Fatalf("%s writer is nil", target.Name())
		}
		if err := closeFn(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNonLinuxCompilation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-compilation check in short mode")
	}
	platforms := []struct {
		goos   string
		goarch string
	}{
		{"darwin", "arm64"},
		{"darwin", "amd64"},
		{"windows", "amd64"},
		{"windows", "arm64"},
	}
	for _, p := range platforms {
		t.Run(p.goos+"_"+p.goarch, func(t *testing.T) {
			cmd := exec.Command("go", "build", ".")
			cmd.Env = append(os.Environ(), "GOOS="+p.goos, "GOARCH="+p.goarch, "CGO_ENABLED=0")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("cross-compilation for %s/%s failed: %v\n%s", p.goos, p.goarch, err, string(out))
			}
		})
	}
}
