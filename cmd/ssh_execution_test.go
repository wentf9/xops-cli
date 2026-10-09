package cmd

import (
	"strings"
	"testing"
)

func TestSSHEmptyCommandDoesNotBecomeShellOrStdinScript(t *testing.T) {
	for _, test := range []struct {
		host    string
		args    []string
		wantErr bool
	}{
		{"", []string{"node", ""}, true},
		{"node", []string{""}, true},
		{"", []string{"node"}, false},
		{"node", nil, false},
		{"node", []string{"echo", ""}, false},
	} {
		o := NewSshOptions()
		command := newCmdSshWithOptions(o)
		o.Host = test.host
		if err := o.Complete(command, test.args); err != nil {
			t.Fatal(err)
		}
		err := o.Validate()
		if test.wantErr {
			if err == nil || !strings.Contains(err.Error(), "must not be empty") {
				t.Fatalf("empty command routed to shell/script: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestExecPTYRejectsIgnoredLegacyOptions(t *testing.T) {
	for _, configure := range []func(*ExecOptions){
		func(o *ExecOptions) { o.Stream = true },
		func(o *ExecOptions) { o.OutDir = "logs" },
		func(o *ExecOptions) { o.stdinScript = true },
		func(o *ExecOptions) { o.Sudo = true; o.NoLoginShell = true },
	} {
		o := NewExecOptions()
		o.Command = "command"
		o.Host = "node"
		o.Interactive = true
		configure(o)
		if err := o.Validate(); err == nil {
			t.Fatal("ignored PTY option accepted")
		}
	}
}

func TestExecPTYMissingCommandDoesNotReadStdin(t *testing.T) {
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	if err := command.Flags().Parse([]string{"--host", "node", "-x"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, nil); err == nil {
		t.Fatal("missing PTY command became stdin script")
	}
	if o.stdinScript {
		t.Fatal("PTY startup consumed a script")
	}
}
