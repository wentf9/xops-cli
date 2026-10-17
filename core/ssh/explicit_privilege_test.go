package ssh

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSudoExecutionOutputOptionsCannotReplaceExecution(t *testing.T) {
	scenario := &commandFixture{output: "chosen-output", commands: make(chan string, 1)}
	client := commandTestClient(t, scenario)
	client.connCfg.SudoMode = SudoModeRoot
	var output bytes.Buffer
	selected := &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX}
	result, err := client.RunWithSudoExecution(t.Context(), "chosen", selected,
		WithInterpreter(InterpreterCmd), WithLaunchDialect(LaunchCmd), WithLoginShell(true), WithStream(&output, ""))
	if err != nil {
		t.Fatal(err)
	}
	if result != "" || strings.Count(output.String(), "chosen-output") != 1 || strings.Count(output.String(), "stderr") != 1 {
		t.Fatalf("output options ignored: %q / %q", result, output.String())
	}
	if got := <-scenario.commands; got != "sh -c 'chosen'" {
		t.Fatalf("validated execution replaced: %q", got)
	}
	if client.Execution() != nil {
		t.Fatal("per-operation execution mutated client defaults")
	}
}

func TestScriptExecutionCarriesLaunchDialect(t *testing.T) {
	scenario := &commandFixture{commands: make(chan string, 1)}
	client := commandTestClient(t, scenario)
	client.connCfg.Execution = &ExecutionConfig{Interpreter: InterpreterPwsh, LaunchDialect: LaunchCmd}
	var actual *RunConfig
	_, err := client.RunScriptWithExecution(t.Context(), "echo chosen", &ExecutionConfig{
		Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX,
	}, func(config *RunConfig) { actual = config })
	if err != nil {
		t.Fatal(err)
	}
	if actual == nil || actual.LaunchDialect != LaunchPOSIX || actual.Interpreter != InterpreterSh {
		t.Fatalf("script did not receive selected execution: %+v", actual)
	}
}

func TestExplicitPrivilegeTerminalUsesSeparateControlShell(t *testing.T) {
	for _, interpreter := range []Interpreter{InterpreterBash, InterpreterSh} {
		t.Run(string(interpreter), func(t *testing.T) {
			exchange := newPrivilegeExchange(nil, SudoModeSudoer, false, interpreter)
			exchange.launchDialect = LaunchPOSIX
			exchange.terminal = &privilegeTerminal{portableControl: true}
			command := exchange.command(string(interpreter) + " -c 'chosen'")
			if !strings.HasPrefix(command, "sudo -n -S -p ") || !strings.Contains(command, " -- /bin/sh -c ") || strings.Contains(command, "sudo -i") {
				t.Fatalf("explicit non-login command entered a legacy login shell: %q", command)
			}
		})
	}
}

func TestInteractiveSudoExecutionRejectsUnsupportedBeforeAccessingClient(t *testing.T) {
	for _, interpreter := range []Interpreter{InterpreterServer, InterpreterPowerShell, InterpreterCmd} {
		err := (*Client)(nil).RunInteractiveWithSudoExecution(t.Context(), "must-not-start", &ExecutionConfig{Interpreter: interpreter})
		if !errors.Is(err, ErrExecutionValidation) {
			t.Fatalf("unsupported %s reached execution: %v", interpreter, err)
		}
	}
}
