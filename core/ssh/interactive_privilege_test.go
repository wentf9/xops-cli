package ssh

import (
	"bytes"
	"io"
	"regexp"
	"testing"
	"time"
)

func TestInteractivePrivilegeCommand(t *testing.T) {
	for _, tt := range []struct {
		name string
		mode SudoMode
		want string
	}{
		{"sudo", SudoModeSudo, "sudo -i -- bash -c 'ls /root'"},
		{"sudoer", SudoModeSudoer, "sudo -i -- bash -c 'ls /root'"},
		{"su", SudoModeSu, "su - root -c 'exec bash -c '\\''ls /root'\\'''"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := interactivePrivilegeCommand(tt.mode, "ls /root")
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	if _, err := interactivePrivilegeCommand(SudoModeNone, "ls"); err == nil {
		t.Fatal("unsupported privilege mode accepted")
	}
}

func TestExpectAuthenticationHandoffPreservesCommandOutput(t *testing.T) {
	var replies, output bytes.Buffer
	prompt := regexp.MustCompile(`Password: `)
	e := NewExpect(&replies, ExpectRule{Pattern: prompt, Respond: StaticRespond("test-password")})
	e.SetAccumulate(true)
	// Authentication and command output can arrive together, even without newline.
	if _, err := io.WriteString(e, "[sudo] Password: first\nPassword: command data\n"); err != nil {
		t.Fatal(err)
	}
	if err := e.Wait(t.Context(), time.Second); err != nil {
		t.Fatal(err)
	}
	if err := e.streamAfterAuthentication(&output); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(e, "last\n"); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "first\nPassword: command data\nlast\n" {
		t.Fatalf("command output lost or filtered: %q", got)
	}
	if replies.String() != "test-password\n" {
		t.Fatalf("unexpected authentication response")
	}
}
