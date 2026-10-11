package ssh

import (
	"errors"
	"testing"
)

func TestConfiguredCommandDefaultsP3(t *testing.T) {
	yes := true
	for _, test := range []struct {
		name    string
		cfg     *ExecutionConfig
		payload string
	}{
		{"absent", nil, "uptime"},
		{"empty", &ExecutionConfig{}, "uptime"},
		{"explicit server", &ExecutionConfig{Interpreter: InterpreterServer}, "uptime"},
		{"explicit bash default", &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX}, "bash -c 'uptime'"},
		{"explicit bash login", &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX, Login: &yes}, "bash -l -c 'uptime'"},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := PlanCommand("uptime", test.cfg.CommandOptions())
			if err != nil || plan.Payload() != test.payload {
				t.Fatalf("wrong stage default: %q, %v", plan.Payload(), err)
			}
		})
	}
}

func TestConfiguredSudoValidatesAndPinsLogin(t *testing.T) {
	yes, no := true, false
	for _, test := range []struct {
		cfg   *ExecutionConfig
		login bool
	}{
		{nil, true},
		{&ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX, Login: &yes}, true},
		{&ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX, Login: &no}, false},
		{&ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX}, false},
	} {
		opts, err := test.cfg.SudoRunOptions("uptime")
		if err != nil {
			t.Fatal(err)
		}
		config := DefaultRunConfig()
		for _, option := range opts {
			option(config)
		}
		if config.LoginShell != test.login {
			t.Fatalf("sudo login=%t, want %t", config.LoginShell, test.login)
		}
	}
	for _, cfg := range []*ExecutionConfig{
		{Interpreter: InterpreterServer},
		{Interpreter: InterpreterBash, LaunchDialect: LaunchCmd},
		{Interpreter: InterpreterBash, LaunchDialect: LaunchUnknown},
	} {
		_, err := (*Client)(nil).RunWithSudoExecution(t.Context(), "must-not-start", cfg)
		if !errors.Is(err, ErrExecutionValidation) {
			t.Fatalf("unsupported sudo config reached execution: %v", err)
		}
	}
}

func TestScriptRevalidatesDerivedInterpreterAndLaunchDialect(t *testing.T) {
	for _, dialect := range []LaunchDialect{LaunchCmd, LaunchPowerShell, LaunchUnknown, ""} {
		for _, script := range []string{"#!/bin/bash\necho script", "echo fallback"} {
			node := &ExecutionConfig{Interpreter: InterpreterServer, LaunchDialect: dialect}
			var global *ExecutionConfig
			if script == "echo fallback" {
				global = &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: dialect}
			}
			_, err := ResolveScriptExecution(nil, nil, node, global, []byte(script))
			if !errors.Is(err, ErrExecutionValidation) {
				t.Fatalf("script accepted incompatible/unknown launch dialect %q: %v", dialect, err)
			}
		}
	}
	res, err := ResolveScriptExecution(nil, nil, &ExecutionConfig{Interpreter: InterpreterServer, LaunchDialect: LaunchPOSIX}, nil, []byte("#!/bin/bash\necho script"))
	if err != nil || res.Login == nil || *res.Login {
		t.Fatalf("resolved Bash login not frozen to adapter default: %+v, %v", res, err)
	}
}

func TestResolveCommandIOInterpreter(t *testing.T) {
	client := &Client{}

	// 1. Unconfigured non-sudo: defaults to Server, empty command rejected
	_, err := client.resolveCommandIOInterpreter(false, "")
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation for unconfigured non-sudo empty command, got: %v", err)
	}

	interp, err := client.resolveCommandIOInterpreter(false, "uptime")
	if err != nil || interp != InterpreterServer {
		t.Fatalf("unconfigured non-sudo command: interp=%q, err=%v", interp, err)
	}

	// 2. Unconfigured sudo: defaults to Bash, allows empty command
	interp, err = client.resolveCommandIOInterpreter(true, "")
	if err != nil || interp != InterpreterBash {
		t.Fatalf("unconfigured sudo empty command: interp=%q, err=%v", interp, err)
	}

	// 3. Server interpreter with sudo: rejected
	serverClient := NewTestClient(ConnectionConfig{Execution: &ExecutionConfig{Interpreter: InterpreterServer}})
	_, err = serverClient.resolveCommandIOInterpreter(true, "uptime")
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation for server sudo, got: %v", err)
	}
}

func TestRunScriptOptionOrdering(t *testing.T) {
	no := false
	exec := &ExecutionConfig{
		Interpreter:   InterpreterBash,
		LaunchDialect: LaunchPOSIX,
		Login:         &no,
	}

	extraOpts := []RunOption{WithLoginShell(true), WithInterpreter(InterpreterSh)}
	opts := make([]RunOption, len(extraOpts))
	copy(opts, extraOpts)
	if exec.Interpreter != "" {
		opts = append(opts, WithInterpreter(exec.Interpreter))
	}
	if exec.Login != nil {
		opts = append(opts, WithLoginShell(*exec.Login))
	}

	config := DefaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}
	if config.LoginShell != false {
		t.Fatalf("expected LoginShell=false, got %t", config.LoginShell)
	}
	if config.Interpreter != InterpreterBash {
		t.Fatalf("expected Interpreter=bash, got %s", config.Interpreter)
	}
}
