package ssh

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestGetSudoParams(t *testing.T) {
	tests := []struct {
		name        string
		mode        SudoMode
		password    string
		suPwd       string
		expectedCmd string
		expectedPwd string
	}{
		{"sudo mode", SudoModeSudo, "mypass", "", "sudo -i", "mypass"},
		{"sudoer mode", SudoModeSudoer, "mypass", "", "sudo -i", ""},
		{"su mode", SudoModeSu, "", "rootpass", "su -", "rootpass"},
		{"root mode", SudoModeRoot, "", "", "", ""},
		{"invalid mode", SudoMode("unknown"), "", "", "", ""},
		{"empty mode", SudoModeNone, "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				cfg: &ClientConfig{
					SudoMode: tt.mode,
					SuPwd:    tt.suPwd,
					Password: tt.password,
				},
			}

			cmd, pwd := c.getSudoParams()
			if cmd != tt.expectedCmd {
				t.Errorf("expected cmd %q, got %q", tt.expectedCmd, cmd)
			}
			if pwd != tt.expectedPwd {
				t.Errorf("expected pwd %q, got %q", tt.expectedPwd, pwd)
			}
		})
	}
}

func TestProcessSuOutputForPassword(t *testing.T) {
	stdout := bytes.NewBufferString("some output\nPassword: ")
	outputBuf := &bytes.Buffer{}
	foundCh := make(chan bool, 1)

	go processSuOutputForPassword(stdout, foundCh, outputBuf)

	select {
	case found := <-foundCh:
		if !found {
			t.Errorf("expected true, got false")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for password prompt")
	}

	if !strings.Contains(outputBuf.String(), "Password:") {
		t.Errorf("expected output buffer to contain 'Password:', got %q", outputBuf.String())
	}
}

func TestHandlePasswordHandshake(t *testing.T) {
	stdout := bytes.NewBufferString("some output\n[sudo] password for user: ")
	stdin := &bytes.Buffer{}

	handlePasswordHandshake(stdout, stdin, "mypassword")

	if stdin.String() != "mypassword\n" {
		t.Errorf("expected 'mypassword\\n', got %q", stdin.String())
	}
}
