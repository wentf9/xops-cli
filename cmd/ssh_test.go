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
