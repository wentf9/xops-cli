package cmd

import (
	"runtime"
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

func TestSSHExplicitExecutionOptions(t *testing.T) {
	for _, test := range []struct {
		name    string
		flags   []string
		args    []string
		payload string
		wantErr string
	}{
		{
			name:    "server with command",
			flags:   []string{"--interpreter", "server"},
			args:    []string{"node", "echo", "$HOME"},
			payload: "echo $HOME",
		},
		{
			name:    "bash posix login default",
			flags:   []string{"--launch-dialect", "posix"},
			args:    []string{"node", "echo", "$HOME"},
			payload: "bash -l -c 'echo $HOME'",
		},
		{
			name:    "bash explicit dialect and login",
			flags:   []string{"--interpreter", "bash", "--launch-dialect", "posix", "--login-shell"},
			args:    []string{"node", "printf", "%s", "test"},
			payload: "bash -l -c 'printf %s test'",
		},
		{
			name:    "bash explicit disabled login",
			flags:   []string{"--interpreter", "bash", "--launch-dialect", "posix", "--login-shell=false"},
			args:    []string{"node", "printf", "%s", "test"},
			payload: "bash -c 'printf %s test'",
		},
		{
			name:    "bash no-login",
			flags:   []string{"--interpreter", "bash", "--launch-dialect", "posix", "--no-login"},
			args:    []string{"node", "uptime"},
			payload: "bash -c 'uptime'",
		},
		{
			name:    "server interactive terminal shell allowed",
			flags:   []string{"--interpreter", "server"},
			args:    []string{"node"},
			payload: "",
		},
		{
			name:    "bash interactive terminal shell rejected",
			flags:   []string{"--interpreter", "bash", "--launch-dialect", "posix"},
			args:    []string{"node"},
			wantErr: "terminal shell session does not support explicit interpreter",
		},
		{
			name:    "login-shell interactive terminal shell rejected",
			flags:   []string{"--login-shell"},
			args:    []string{"node"},
			wantErr: "terminal shell session does not support explicit interpreter",
		},
		{
			name:    "sudo rejected with explicit execution",
			flags:   []string{"--interpreter", "server", "--sudo"},
			args:    []string{"node", "uptime"},
			wantErr: "without sudo",
		},
		{
			name:    "no-cmd rejected with explicit execution",
			flags:   []string{"--interpreter", "server", "-N"},
			args:    []string{"node"},
			wantErr: "cannot be combined with -N",
		},
		{
			name:    "server login mode rejected",
			flags:   []string{"--interpreter", "server", "--login-shell"},
			args:    []string{"node", "uptime"},
			wantErr: "inherited login mode",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := NewSshOptions()
			cmd := newCmdSshWithOptions(o)
			allArgs := append(test.flags, test.args...)
			if err := cmd.Flags().Parse(allArgs); err != nil {
				t.Fatal(err)
			}
			if err := o.Complete(cmd, cmd.Flags().Args()); err != nil {
				t.Fatal(err)
			}
			err := o.Validate()
			if runtime.GOOS != "linux" && (o.execution.enabled() || o.execution.noLoginSet) {
				if err == nil || !strings.Contains(err.Error(), "cancelable native output is only available on Linux") {
					t.Fatalf("error %v, want platform guard error on %s", err, runtime.GOOS)
				}
				return
			}
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected validate error: %v", err)
			}
			if test.payload != "" {
				if o.commandPlan == nil {
					t.Fatal("expected command plan, got nil")
				}
				if o.commandPlan.Payload() != test.payload {
					t.Fatalf("payload %q, want %q", o.commandPlan.Payload(), test.payload)
				}
			} else {
				if o.commandPlan != nil {
					t.Fatalf("unexpected command plan: %+v", o.commandPlan)
				}
			}
		})
	}
}

func TestSSHExplicitPipedStdinRouting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("explicit execution is currently available on Linux only")
	}
	// Server mode with piped stdin -> accepted, no plan (handled by RunShellWithoutPTY)
	o := NewSshOptions()
	cmd := newCmdSshWithOptions(o)
	if err := cmd.Flags().Parse([]string{"--interpreter", "server", "node"}); err != nil {
		t.Fatal(err)
	}
	o.stdinScript = true // simulate piped stdin
	if err := o.Complete(cmd, cmd.Flags().Args()); err != nil {
		t.Fatal(err)
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("server mode with piped stdin should be accepted: %v", err)
	}

	// Piped stdin with any non-server or default-Bash explicit options -> rejected in P1
	for _, flags := range [][]string{
		{"--interpreter", "bash"},
		{"--launch-dialect", "posix"},
		{"--login-shell"},
		{"--no-login"},
	} {
		oReject := NewSshOptions()
		cmdReject := newCmdSshWithOptions(oReject)
		if err := cmdReject.Flags().Parse(append(flags, "node")); err != nil {
			t.Fatal(err)
		}
		oReject.stdinScript = true // simulate piped stdin
		if err := oReject.Complete(cmdReject, cmdReject.Flags().Args()); err != nil {
			t.Fatal(err)
		}
		err := oReject.Validate()
		if err == nil || !strings.Contains(err.Error(), "explicit script execution is not supported yet") {
			t.Fatalf("flags %v with piped stdin should be rejected: %v", flags, err)
		}
	}

	// Empty explicit values must be rejected
	for _, flags := range [][]string{
		{"--interpreter", ""},
		{"--launch-dialect", ""},
	} {
		for _, piped := range []bool{true, false} {
			oEmpty := NewSshOptions()
			cmdEmpty := newCmdSshWithOptions(oEmpty)
			if err := cmdEmpty.Flags().Parse(append(flags, "node")); err != nil {
				t.Fatal(err)
			}
			oEmpty.stdinScript = piped
			if err := oEmpty.Complete(cmdEmpty, cmdEmpty.Flags().Args()); err != nil {
				t.Fatal(err)
			}
			err := oEmpty.Validate()
			if err == nil || !strings.Contains(err.Error(), "must not be empty") {
				t.Fatalf("empty explicit option %v (piped=%v) accepted: %v", flags, piped, err)
			}
		}
	}
}
