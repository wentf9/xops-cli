package ssh

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestFormatScriptPayload(t *testing.T) {
	for _, tc := range []struct {
		name        string
		interp      Interpreter
		login       bool
		dialect     LaunchDialect
		args        []string
		wantPayload string
		wantErr     bool
	}{
		// Bash
		{"bash no args no login", InterpreterBash, false, LaunchPOSIX, nil, "bash -s", false},
		{"bash no args login", InterpreterBash, true, LaunchPOSIX, nil, "bash -l -s", false},
		{"bash default empty interp", "", false, LaunchPOSIX, nil, "bash -s", false},
		{"bash with args no login", InterpreterBash, false, LaunchPOSIX, []string{"arg1", "arg 2", "--flag"}, "bash -s -- 'arg1' 'arg 2' '--flag'", false},
		{"bash with args login", InterpreterBash, true, LaunchPOSIX, []string{"arg1", "arg 2"}, "bash -l -s -- 'arg1' 'arg 2'", false},
		{"bash with single quote in arg", InterpreterBash, false, LaunchPOSIX, []string{"don't"}, "bash -s -- 'don'\\''t'", false},

		// Sh
		{"sh no args", InterpreterSh, false, LaunchPOSIX, nil, "sh -s", false},
		{"sh with args", InterpreterSh, false, LaunchPOSIX, []string{"arg1", "arg 2"}, "sh -s -- 'arg1' 'arg 2'", false},

		// Zsh
		{"zsh no args no login", InterpreterZsh, false, LaunchPOSIX, nil, "zsh -s", false},
		{"zsh no args login", InterpreterZsh, true, LaunchPOSIX, nil, "zsh -l -s", false},
		{"zsh with args no login", InterpreterZsh, false, LaunchPOSIX, []string{"arg1", "arg 2"}, "zsh -s -- 'arg1' 'arg 2'", false},
		{"zsh with args login", InterpreterZsh, true, LaunchPOSIX, []string{"arg1", "arg 2"}, "zsh -l -s -- 'arg1' 'arg 2'", false},

		// Fish
		{"fish no args no login", InterpreterFish, false, LaunchPOSIX, nil, "fish", false},
		{"fish no args login", InterpreterFish, true, LaunchPOSIX, nil, "fish -l", false},
		{"fish with args posix outer", InterpreterFish, false, LaunchPOSIX, []string{"arg1", "arg 2"}, "fish -c 'source - '\\''arg1'\\'' '\\''arg 2'\\'''", false},
		{"fish with args fish outer", InterpreterFish, false, LaunchFish, []string{"arg1", "arg 2"}, "fish -c 'source - \\'arg1\\' \\'arg 2\\''", false},
		{"fish with args login", InterpreterFish, true, LaunchPOSIX, []string{"arg1"}, "fish -l -c 'source - '\\''arg1'\\'''", false},

		// Csh & Tcsh
		{"csh no args", InterpreterCsh, false, LaunchPOSIX, nil, "csh -s", false},
		{"csh with args", InterpreterCsh, false, LaunchPOSIX, []string{"arg1", "arg 2"}, "csh -s -b 'arg1' 'arg 2'", false},
		{"tcsh no args", InterpreterTcsh, false, LaunchPOSIX, nil, "tcsh -s", false},
		{"tcsh with args", InterpreterTcsh, false, LaunchPOSIX, []string{"arg1", "arg 2"}, "tcsh -s -b 'arg1' 'arg 2'", false},

		// Empty string args and empty slices
		{"bash with empty string arg", InterpreterBash, false, LaunchPOSIX, []string{""}, "bash -s -- ''", false},
		{"bash with empty slice", InterpreterBash, false, LaunchPOSIX, []string{}, "bash -s", false},
		{"fish with empty string arg", InterpreterFish, false, LaunchPOSIX, []string{""}, "fish -c 'source - '\\'''\\'''", false},
		{"csh with bang and special chars", InterpreterCsh, false, LaunchCsh, []string{"hello!world", "don't"}, "csh -s -b 'hello\\!world' 'don'\\''t'", false},

		// Unsupported interpreters
		{"unsupported server", InterpreterServer, false, LaunchPOSIX, nil, "", true},
		{"unsupported powershell", InterpreterPowerShell, false, LaunchPOSIX, nil, "", true},
		{"unsupported cmd", InterpreterCmd, false, LaunchPOSIX, nil, "", true},

		// NUL byte in args
		{"nul byte rejection", InterpreterBash, false, LaunchPOSIX, []string{"bad\x00arg"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FormatScriptPayload(tc.interp, tc.login, tc.dialect, tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (payload: %q)", got)
				}
				if !errors.Is(err, ErrExecutionValidation) {
					t.Fatalf("expected ErrExecutionValidation, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantPayload {
				t.Fatalf("got payload %q, want %q", got, tc.wantPayload)
			}
		})
	}
}

func TestFormatScriptPayloadMaxBytes(t *testing.T) {
	// Construct arguments that exceed MaxCommandBytes (64 KiB)
	largeArg := strings.Repeat("a", MaxCommandBytes)
	_, err := FormatScriptPayload(InterpreterBash, false, LaunchPOSIX, []string{largeArg})
	if err == nil {
		t.Fatal("expected error for payload exceeding MaxCommandBytes, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}
}

func TestRunScriptWithSudoPayloadLimit(t *testing.T) {
	client := &Client{connCfg: ConnectionConfig{SudoMode: SudoModeSu}}
	ctx := context.Background()

	t.Run("script with args exceeds MaxCommandBytes", func(t *testing.T) {
		// Script content base64 encoded + args that together exceed MaxCommandBytes,
		// while args alone do not exceed MaxCommandBytes so formatScriptPayload passes.
		scriptContent := strings.Repeat("echo 'test'\n", 3000) // ~36 KB, base64 ~48 KB
		arg := strings.Repeat("x", 20000)                      // 20 KB (< 64 KB)

		_, err := client.RunScriptWithSudo(ctx, scriptContent, WithInterpreter(InterpreterBash), WithScriptArgs(arg))
		if err == nil {
			t.Fatal("expected payload limit error in RunScriptWithSudo, got nil")
		}
		if !errors.Is(err, ErrExecutionValidation) {
			t.Fatalf("expected ErrExecutionValidation, got: %v", err)
		}
		if !strings.Contains(err.Error(), "generated exec payload exceeds") {
			t.Fatalf("expected 'generated exec payload exceeds' in error, got: %v", err)
		}
	})

	t.Run("script alone in su mode exceeds MaxCommandBytes", func(t *testing.T) {
		largeScript := strings.Repeat("echo 'test'\n", 5000) // ~60 KB, base64 ~80 KB > 64 KB

		_, err := client.RunScriptWithSudo(ctx, largeScript, WithInterpreter(InterpreterBash))
		if err == nil {
			t.Fatal("expected payload limit error in RunScriptWithSudo, got nil")
		}
		if !errors.Is(err, ErrExecutionValidation) {
			t.Fatalf("expected ErrExecutionValidation, got: %v", err)
		}
		if !strings.Contains(err.Error(), "generated exec payload exceeds") {
			t.Fatalf("expected 'generated exec payload exceeds' in error, got: %v", err)
		}
	})

	t.Run("sh script alone in su mode exceeds MaxCommandBytes", func(t *testing.T) {
		largeScript := strings.Repeat("echo 'test'\n", 5000)

		_, err := client.RunScriptWithSudo(ctx, largeScript, WithInterpreter(InterpreterSh))
		if err == nil {
			t.Fatal("expected payload limit error in RunScriptWithSudo, got nil")
		}
		if !errors.Is(err, ErrExecutionValidation) {
			t.Fatalf("expected ErrExecutionValidation, got: %v", err)
		}
		if !strings.Contains(err.Error(), "generated exec payload exceeds") {
			t.Fatalf("expected 'generated exec payload exceeds' in error, got: %v", err)
		}
	})

	t.Run("large script with args under sudo mode does not fail payload limit", func(t *testing.T) {
		sudoClient := &Client{connCfg: ConnectionConfig{SudoMode: SudoModeSudo}}
		largeScript := strings.Repeat("echo 'test'\n", 5000) // ~60 KB, base64 ~80 KB > 64 KB
		_, err := sudoClient.RunScriptWithSudo(ctx, largeScript, WithInterpreter(InterpreterBash), WithScriptArgs("arg1"))
		if errors.Is(err, ErrExecutionValidation) {
			t.Fatalf("SudoModeSudo should not fail with ErrExecutionValidation for large script with args: %v", err)
		}
	})
}

func TestNativeScriptArgsExecution(t *testing.T) {
	testCases := []struct {
		interp     Interpreter
		dialect    LaunchDialect
		shellCmd   string
		scriptBody string
	}{
		{
			interp:     InterpreterBash,
			dialect:    LaunchPOSIX,
			shellCmd:   "bash",
			scriptBody: "echo argc=$#\necho 1=$1\necho 2=$2\necho 3=$3\necho 4=\"[$4]\"\n",
		},
		{
			interp:     InterpreterSh,
			dialect:    LaunchPOSIX,
			shellCmd:   "sh",
			scriptBody: "echo argc=$#\necho 1=$1\necho 2=$2\necho 3=$3\necho 4=\"[$4]\"\n",
		},
		{
			interp:     InterpreterZsh,
			dialect:    LaunchPOSIX,
			shellCmd:   "zsh",
			scriptBody: "echo argc=$#\necho 1=$1\necho 2=$2\necho 3=$3\necho 4=\"[$4]\"\n",
		},
		{
			interp:     InterpreterFish,
			dialect:    LaunchPOSIX,
			shellCmd:   "fish",
			scriptBody: "echo argc=(count $argv)\necho 1=$argv[1]\necho 2=$argv[2]\necho 3=$argv[3]\necho 4=\"[$argv[4]]\"\n",
		},
	}

	for _, tc := range testCases {
		t.Run(string(tc.interp), func(t *testing.T) {
			outerPath, err := exec.LookPath("sh")
			if err != nil {
				t.Skip("sh not available")
			}
			if _, err := exec.LookPath(tc.shellCmd); err != nil {
				t.Skipf("%s not available", tc.shellCmd)
			}

			scriptArgs := []string{"first arg", "second'quote", "--flag-opt", ""}
			payload, err := FormatScriptPayload(tc.interp, false, tc.dialect, scriptArgs)
			if err != nil {
				t.Fatalf("FormatScriptPayload: %v", err)
			}

			// Run outer shell passing payload with stdin script
			ctx := context.Background()
			cmd := exec.CommandContext(ctx, outerPath, "-c", payload)
			cmd.Stdin = strings.NewReader(tc.scriptBody)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("command failed: %v, output: %s", err, string(out))
			}

			output := string(out)
			if !strings.Contains(output, "argc=4") {
				t.Errorf("expected argc=4, got output:\n%s", output)
			}
			if !strings.Contains(output, "1=first arg") {
				t.Errorf("expected 1=first arg, got output:\n%s", output)
			}
			if !strings.Contains(output, "2=second'quote") {
				t.Errorf("expected 2=second'quote, got output:\n%s", output)
			}
			if !strings.Contains(output, "3=--flag-opt") {
				t.Errorf("expected 3=--flag-opt, got output:\n%s", output)
			}
			if !strings.Contains(output, "4=[]") {
				t.Errorf("expected 4=[], got output:\n%s", output)
			}
		})
	}
}
