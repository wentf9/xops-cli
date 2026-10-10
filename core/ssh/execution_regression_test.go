package ssh

import (
	"errors"
	"testing"
)

func TestConfiguredCommandDefaultsStayLegacyUntilP3(t *testing.T) {
	no := false
	for _, test := range []struct {
		name    string
		cfg     *ExecutionConfig
		payload string
	}{
		{"absent", nil, "bash -l -c 'uptime'"},
		{"empty", &ExecutionConfig{}, "bash -l -c 'uptime'"},
		{"login only", &ExecutionConfig{Login: &no}, "bash -c 'uptime'"},
		{"explicit server", &ExecutionConfig{Interpreter: InterpreterServer}, "uptime"},
		{"explicit bash default", &ExecutionConfig{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX}, "bash -c 'uptime'"},
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
