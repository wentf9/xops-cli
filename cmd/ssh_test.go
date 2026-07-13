package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestParseForwardArg(t *testing.T) {
	tests := []struct {
		name     string
		arg      string
		wantBind string
		wantDest string
		wantErr  bool
	}{
		{
			name:     "port:host:hostport",
			arg:      "8080:localhost:80",
			wantBind: "127.0.0.1:8080",
			wantDest: "localhost:80",
			wantErr:  false,
		},
		{
			name:     "bind_address:port:host:hostport",
			arg:      "0.0.0.0:8080:localhost:80",
			wantBind: "0.0.0.0:8080",
			wantDest: "localhost:80",
			wantErr:  false,
		},
		{
			name:     "invalid format",
			arg:      "8080",
			wantBind: "",
			wantDest: "",
			wantErr:  true,
		},
		{
			name:     "invalid format with one colon",
			arg:      "localhost:80",
			wantBind: "",
			wantDest: "",
			wantErr:  true,
		},
		{
			name:     "too many colons (ipv6 with brackets without port)",
			arg:      "127.0.0.1:8080:[::1]:80",
			wantBind: "127.0.0.1:8080",
			wantDest: "[::1]:80",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBind, gotDest, err := parseForwardArg(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseForwardArg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotBind != tt.wantBind {
				t.Errorf("parseForwardArg() gotBind = %v, want %v", gotBind, tt.wantBind)
			}
			if gotDest != tt.wantDest {
				t.Errorf("parseForwardArg() gotDest = %v, want %v", gotDest, tt.wantDest)
			}
		})
	}
}

func TestSshBackgroundValidation(t *testing.T) {
	tests := []struct {
		name    string
		options *SshOptions
		wantErr bool
	}{
		{
			name: "BgRun without NoCmd",
			options: &SshOptions{
				BgRun: true,
				NoCmd: false,
				Host:  "127.0.0.1",
				User:  "test",
				Port:  22,
			},
			wantErr: true,
		},
		{
			name: "BgRun with NoCmd",
			options: &SshOptions{
				BgRun: true,
				NoCmd: true,
				Host:  "127.0.0.1",
				User:  "test",
				Port:  22,
			},
			wantErr: false,
		},
		{
			name: "Normal command without BgRun",
			options: &SshOptions{
				BgRun: false,
				NoCmd: false,
				Host:  "127.0.0.1",
				User:  "test",
				Port:  22,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPromptPressEnterIfTUI(t *testing.T) {
	// Backup original env var
	origEnv, exists := os.LookupEnv("XOPS_CLI_SSH_FROM_TUI")
	defer func() {
		if exists {
			_ = os.Setenv("XOPS_CLI_SSH_FROM_TUI", origEnv)
		} else {
			_ = os.Unsetenv("XOPS_CLI_SSH_FROM_TUI")
		}
	}()

	tests := []struct {
		name          string
		envVal        string
		hasEnv        bool
		stdinVal      string
		wantOutput    bool
		wantReadCount int
	}{
		{
			name:          "From TUI: prints prompt and reads stdin",
			envVal:        "true",
			hasEnv:        true,
			stdinVal:      "\n",
			wantOutput:    true,
			wantReadCount: 1,
		},
		{
			name:          "Not from TUI: env not set, no prompt, no read",
			hasEnv:        false,
			wantOutput:    false,
			wantReadCount: 0,
		},
		{
			name:          "Not from TUI: env is false, no prompt, no read",
			envVal:        "false",
			hasEnv:        true,
			wantOutput:    false,
			wantReadCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.hasEnv {
				_ = os.Setenv("XOPS_CLI_SSH_FROM_TUI", tt.envVal)
			} else {
				_ = os.Unsetenv("XOPS_CLI_SSH_FROM_TUI")
			}

			stdin := strings.NewReader(tt.stdinVal)
			var stdout bytes.Buffer

			promptPressEnterIfTUI(stdin, &stdout)

			hasPrompt := stdout.Len() > 0
			if hasPrompt != tt.wantOutput {
				t.Errorf("expected output to be %v, got %v (output: %q)", tt.wantOutput, hasPrompt, stdout.String())
			}

			unreadLen := stdin.Len()
			readCount := len(tt.stdinVal) - unreadLen
			if readCount != tt.wantReadCount {
				t.Errorf("expected to read %d bytes, read %d", tt.wantReadCount, readCount)
			}
		})
	}
}

func TestSshArgsCommandParsing(t *testing.T) {
	o := NewSshOptions()
	o.args = []string{"test-host", "echo", "hello", "world"}

	err := o.Validate()
	if err != nil {
		t.Fatalf("expected Validate to succeed, got error: %v", err)
	}

	if o.Host != "test-host" {
		t.Errorf("expected Host to be 'test-host', got %q", o.Host)
	}

	expectedCmd := "echo hello world"
	if o.Command != expectedCmd {
		t.Errorf("expected Command to be %q, got %q", expectedCmd, o.Command)
	}
}

func TestSshStdinScriptDetection(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer func() { _ = w.Close() }()
	defer func() { _ = r.Close() }()

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	os.Stdin = r

	// 1. 正常管道输入
	o1 := NewSshOptions()
	o1.Complete(nil, []string{"test-host"})
	if !o1.stdinScript {
		t.Error("expected stdinScript to be true when stdin is a pipe")
	}

	// 2. 带有 StdinRedirect (-n) 时，即使 stdin 是管道，也应当忽略它作为 script
	o2 := NewSshOptions()
	o2.StdinRedirect = true
	o2.Complete(nil, []string{"test-host"})
	if o2.stdinScript {
		t.Error("expected stdinScript to be false when StdinRedirect (-n) is enabled")
	}
}

func TestSshCommandWithFlagsNotParsedAsXopsFlags(t *testing.T) {
	c := NewCmdSsh()
	args := []string{"host-01", "ss", "-tlpn"}
	err := c.Flags().Parse(args)
	if err != nil {
		t.Fatalf("expected Parse to succeed with interspersed false, got error: %v", err)
	}

	parsedArgs := c.Flags().Args()
	expected := []string{"host-01", "ss", "-tlpn"}
	if len(parsedArgs) != len(expected) {
		t.Fatalf("expected %d arguments, got %d (%v)", len(expected), len(parsedArgs), parsedArgs)
	}
	for i, v := range expected {
		if parsedArgs[i] != v {
			t.Errorf("at index %d: expected %q, got %q", i, v, parsedArgs[i])
		}
	}
}
