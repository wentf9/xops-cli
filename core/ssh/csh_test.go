package ssh

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestCshQuoteAndPlanCommand(t *testing.T) {
	if got := cshQuote("quote' bang! line1\nline2 \\slash $HOME"); got != `'quote'\'' bang\! line1\`+"\n"+`line2 \slash $HOME'` {
		t.Fatalf("unexpected cshQuote output: %q", got)
	}
	for _, interp := range []Interpreter{InterpreterCsh, InterpreterTcsh} {
		for _, dialect := range []LaunchDialect{LaunchCsh, LaunchPOSIX, LaunchFish} {
			cfg := &ExecutionConfig{Interpreter: interp, LaunchDialect: dialect}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("validate %s/%s: %v", interp, dialect, err)
			}
			plan, err := PlanCommand("echo ok! && true\necho second", cfg.CommandOptions())
			if err != nil {
				t.Fatalf("plan %s/%s: %v", interp, dialect, err)
			}
			if plan.LoginMode() != LoginDisabled {
				t.Fatalf("expected LoginDisabled for %s, got %s", interp, plan.LoginMode())
			}
			if dialect == LaunchCsh && !strings.Contains(plan.Payload(), `\!`) {
				t.Fatalf("expected csh history-expansion escaping in payload %q", plan.Payload())
			}
		}
		loginTrue := true
		cfgLogin := &ExecutionConfig{Interpreter: interp, LaunchDialect: LaunchCsh, Login: &loginTrue}
		if !errors.Is(cfgLogin.Validate(), ErrExecutionValidation) {
			t.Fatalf("expected login=true to be rejected for %s", interp)
		}
		if _, err := PlanCommand("echo ok", CommandOptions{Interpreter: interp, LaunchDialect: LaunchCsh, Login: LoginEnabled}); err == nil {
			t.Fatalf("expected PlanCommand with LoginEnabled to fail for %s", interp)
		}
	}
}

func TestCshWorkingDirAndShebang(t *testing.T) {
	for _, interp := range []Interpreter{InterpreterCsh, InterpreterTcsh} {
		cfg := &ExecutionConfig{Interpreter: interp, LaunchDialect: LaunchCsh}
		cmd, err := FormatWorkingDirCommand("/var/tmp/dir'bang!", "pwd", cfg)
		if err != nil {
			t.Fatalf("FormatWorkingDirCommand(%s): %v", interp, err)
		}
		want := "cd -- '/var/tmp/dir'\\''bang\\!' || exit $status\npwd"
		if cmd != want {
			t.Fatalf("FormatWorkingDirCommand(%s) = %q, want %q", interp, cmd, want)
		}
	}
	for _, tc := range []struct {
		shebang string
		interp  Interpreter
	}{
		{"#!/bin/csh\necho hi\n", InterpreterCsh},
		{"#!/usr/bin/env csh\necho hi\n", InterpreterCsh},
		{"#!/bin/tcsh\necho hi\n", InterpreterTcsh},
		{"#!/usr/bin/env tcsh\necho hi\n", InterpreterTcsh},
	} {
		info := ParseShebang([]byte(tc.shebang))
		if !info.Supported || info.Interpreter != tc.interp || info.Dialect != LaunchCsh {
			t.Fatalf("ParseShebang(%q) = %+v", tc.shebang, info)
		}
		resolved, err := ResolveScriptExecution(nil, nil, &ExecutionConfig{LaunchDialect: LaunchCsh}, nil, []byte(tc.shebang))
		if err != nil || resolved.Interpreter != tc.interp || resolved.LaunchDialect != LaunchCsh {
			t.Fatalf("ResolveScriptExecution(%q) = %+v, err = %v", tc.shebang, resolved, err)
		}
	}
}

func TestCshPrivilegeWrapping(t *testing.T) {
	for _, interp := range []Interpreter{InterpreterCsh, InterpreterTcsh, InterpreterSh} {
		for _, dialect := range []LaunchDialect{LaunchCsh, LaunchPOSIX} {
			cfg := &ExecutionConfig{Interpreter: interp, LaunchDialect: dialect}
			if _, err := cfg.SudoRunOptions("id"); err != nil {
				t.Fatalf("SudoRunOptions(%s/%s): %v", interp, dialect, err)
			}
			client := NewTestClient(ConnectionConfig{Execution: cfg})
			exchangeSudo := newPrivilegeExchange(client, SudoModeSudo, false, interp)
			exchangeSudo.launchDialect = dialect
			_ = exchangeSudo.command("id")
			wantSudo := "sudo -S -p '<password-prompt>' -- /bin/sh -c '<privileged payload>'"
			if interp == InterpreterSh && dialect == LaunchPOSIX {
				wantSudo = "sudo -S -p '<password-prompt>' -- sh -c '<privileged payload>'"
			}
			if exchangeSudo.commandPreview != wantSudo {
				t.Fatalf("unexpected sudo preview for %s/%s: %q, want %q", interp, dialect, exchangeSudo.commandPreview, wantSudo)
			}
			exchangeSu := newPrivilegeExchange(client, SudoModeSu, false, interp)
			exchangeSu.launchDialect = dialect
			_ = exchangeSu.command("id")
			wantSu := "env LC_ALL=C su - root -c 'exec sh -c '\\''<privileged payload>'\\'''"
			if dialect == LaunchPOSIX {
				wantSu = "export LC_ALL=C; su - root -c 'exec sh -c '\\''<privileged payload>'\\'''"
			}
			if exchangeSu.commandPreview != wantSu {
				t.Fatalf("unexpected %s/%s su preview: %q, want %q", interp, dialect, exchangeSu.commandPreview, wantSu)
			}
		}
	}
}

func TestCshPrivilegeBangEscaping(t *testing.T) {
	client := NewTestClient(ConnectionConfig{})
	bangCommands := []string{
		"echo hello!",
		"echo !test",
		"echo !! && echo !$",
		"echo !?find? && echo a!=b",
		"echo !123",
	}
	for _, interp := range []Interpreter{InterpreterCsh, InterpreterTcsh, InterpreterSh} {
		for _, dialect := range []LaunchDialect{LaunchCsh, LaunchPOSIX} {
			exchangeSu := newPrivilegeExchange(client, SudoModeSu, false, interp)
			exchangeSu.launchDialect = dialect
			for _, cmd := range bangCommands {
				wrapped := exchangeSu.wrapPortableBody(cmd, "prompt")
				if strings.Contains(wrapped, "-s /bin/sh") {
					t.Fatalf("unexpected GNU -s /bin/sh for %s/%s on %q: %s", interp, dialect, cmd, wrapped)
				}
				if !strings.Contains(wrapped, "\\!") {
					t.Fatalf("expected bang protection in wrapped body for %s/%s on %q, got: %s", interp, dialect, cmd, wrapped)
				}
			}
		}
	}
}

func TestCshLoginShellFlag(t *testing.T) {
	for _, tc := range []struct {
		interp Interpreter
		login  bool
		want   string
	}{
		{InterpreterCsh, true, "exec csh"},
		{InterpreterCsh, false, "exec csh"},
		{InterpreterTcsh, true, "exec tcsh"},
		{InterpreterTcsh, false, "exec tcsh"},
		{InterpreterSh, true, "exec sh"},
		{InterpreterSh, false, "exec sh"},
		{InterpreterBash, true, "exec bash -l"},
		{InterpreterBash, false, "exec bash"},
		{InterpreterZsh, true, "exec zsh -l"},
		{InterpreterFish, true, "exec fish -l"},
	} {
		got := portableUserCommand("", &RunConfig{Interpreter: tc.interp, LoginShell: tc.login}, LaunchPOSIX)
		if got != tc.want {
			t.Errorf("portableUserCommand(%s, login=%v) = %q, want %q", tc.interp, tc.login, got, tc.want)
		}
	}

	for _, interp := range []Interpreter{InterpreterCsh, InterpreterTcsh} {
		client := NewTestClient(ConnectionConfig{Execution: &ExecutionConfig{Interpreter: interp, LaunchDialect: LaunchCsh}})
		exchange := newPrivilegeExchange(client, SudoModeSudo, false, interp)
		exchange.launchDialect = LaunchCsh
		cmd := exchange.portableCommand("")
		if strings.Contains(cmd, "-l") {
			t.Fatalf("portableCommand(\"\") for %s unexpectedly included -l: %q", interp, cmd)
		}
		if !strings.Contains(cmd, "exec "+string(interp)) {
			t.Fatalf("portableCommand(\"\") for %s expected exec %s, got: %q", interp, interp, cmd)
		}
	}
}

func TestRunPortableWithSudoScriptLoginShellFlag(t *testing.T) {
	for _, tc := range []struct {
		interp Interpreter
		login  bool
		want   string
	}{
		{InterpreterBash, true, "bash -l -s"},
		{InterpreterBash, false, "bash -s"},
		{InterpreterZsh, true, "zsh -l -s"},
		{InterpreterZsh, false, "zsh -s"},
		{InterpreterFish, true, "fish -l"},
		{InterpreterFish, false, "fish"},
		{InterpreterCsh, true, "csh -s"},
		{InterpreterCsh, false, "csh -s"},
		{InterpreterTcsh, true, "tcsh -s"},
		{InterpreterTcsh, false, "tcsh -s"},
		{InterpreterSh, true, "sh -s"},
		{InterpreterSh, false, "sh -s"},
	} {
		config := &RunConfig{Interpreter: tc.interp, LoginShell: tc.login}
		inner := strings.TrimPrefix(portableUserCommand("", config, LaunchPOSIX), "exec ")
		if tc.interp != InterpreterFish {
			inner += " -s"
		}
		if inner != tc.want {
			t.Errorf("portable script inner command for %s (login=%v) = %q, want %q", tc.interp, tc.login, inner, tc.want)
		}
	}
}

func unquoteSingleQuote(s string) (string, error) {
	if len(s) < 2 || !strings.HasPrefix(s, "'") || !strings.HasSuffix(s, "'") {
		return "", fmt.Errorf("string is not single-quoted: %s", s)
	}
	content := s[1 : len(s)-1]
	return strings.ReplaceAll(content, `'\''`, `'`), nil
}

func cshUnquote(s string) (string, error) {
	if len(s) < 2 || !strings.HasPrefix(s, "'") || !strings.HasSuffix(s, "'") {
		return "", fmt.Errorf("string is not single-quoted: %s", s)
	}
	content := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(content); i++ {
		if strings.HasPrefix(content[i:], `'\''`) {
			b.WriteByte('\'')
			i += 3
			continue
		}
		if strings.HasPrefix(content[i:], `\!`) {
			b.WriteByte('!')
			i++
			continue
		}
		if strings.HasPrefix(content[i:], "\\\n") {
			b.WriteByte('\n')
			i++
			continue
		}
		b.WriteByte(content[i])
	}
	return b.String(), nil
}

func parseShellArgv(s string) ([]string, error) {
	var words []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && (ch == ' ' || ch == '\t') {
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			continue
		}
		if !inQuote && ch == '\\' && i+1 < len(s) {
			current.WriteByte(s[i+1])
			i++
			continue
		}
		current.WriteByte(ch)
	}
	if inQuote {
		return nil, errors.New("unmatched quote")
	}
	if current.Len() > 0 {
		words = append(words, current.String())
	}
	return words, nil
}

func verifyMultilineSuQuoting(t *testing.T, exchangeSu *privilegeExchange, interp Interpreter, dialect LaunchDialect, cmd string) {
	t.Helper()
	wrapped := exchangeSu.wrapPortableBody(cmd, "prompt")
	if strings.Contains(wrapped, "\n") {
		t.Fatalf("expected no literal newlines in wrapped su command for %s/%s on %q, got:\n%s", interp, dialect, cmd, wrapped)
	}
	if strings.Contains(wrapped, "\\\n") {
		t.Fatalf("expected no line continuation backslash before newline in wrapped su command for %s/%s on %q", interp, dialect, cmd)
	}
	if strings.Contains(wrapped, "\r") {
		t.Fatalf("unexpected carriage return in wrapped su command for %s/%s on %q", interp, dialect, cmd)
	}
	if !strings.Contains(wrapped, "eval \"$(printf") {
		t.Fatalf("expected eval printf reassembly in wrapped su command for %s/%s on %q: %s", interp, dialect, cmd, wrapped)
	}
	if strings.Contains(cmd, "!") && !strings.Contains(wrapped, "\\!") {
		t.Fatalf("expected bang protection in wrapped su command for %s/%s on %q: %s", interp, dialect, cmd, wrapped)
	}

	prefix := "export LC_ALL=C; su - root -c "
	if dialect == LaunchCsh {
		prefix = "env LC_ALL=C su - root -c "
	}
	if !strings.HasPrefix(wrapped, prefix) {
		t.Fatalf("expected prefix %q in wrapped command: %s", prefix, wrapped)
	}
	quotedBody := strings.TrimPrefix(wrapped, prefix)
	var suBody string
	var err error
	if dialect == LaunchCsh {
		suBody, err = cshUnquote(quotedBody)
	} else {
		suBody, err = unquoteSingleQuote(quotedBody)
	}
	if err != nil {
		t.Fatalf("failed to unquote suBody for %s/%s on %q: %v", interp, dialect, cmd, err)
	}
	if strings.Contains(suBody, "\n") {
		t.Fatalf("suBody contains literal newline for %s/%s on %q", interp, dialect, cmd)
	}
}

func verifySuBodyExecution(t *testing.T, suBody, wantOut string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "sh", "-c", suBody)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("exec sh -c suBody failed: %v, output: %s", err, string(out))
	}
	if string(out) != wantOut {
		t.Fatalf("posix root execution output mismatch: got %q, want %q", string(out), wantOut)
	}

	words, err := parseShellArgv(suBody)
	if err != nil {
		t.Fatalf("parseShellArgv failed: %v", err)
	}
	if len(words) < 4 {
		t.Fatalf("expected at least 4 words, got %d: %+v", len(words), words)
	}
	if words[0] != "exec" || words[1] != "sh" || words[2] != "-c" {
		t.Fatalf("unexpected command structure in parsed argv: %+v", words)
	}
	if len(words) >= 5 {
		if words[4] != "sh" {
			t.Fatalf("unexpected command structure in parsed argv: %+v", words[:5])
		}
		if words[3] != "eval \"$(printf '%s\\n' \"$@\")\"" {
			t.Fatalf("unexpected eval printf script in argv[3]: %q", words[3])
		}
	}

	innerCmd := exec.CommandContext(t.Context(), words[1], words[2:]...)
	innerOut, err := innerCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("simulated csh exec %s failed: %v, output: %s", words[1], err, string(innerOut))
	}
	if string(innerOut) != wantOut {
		t.Fatalf("simulated csh exec output mismatch: got %q, want %q", string(innerOut), wantOut)
	}

	for _, cshName := range []string{"csh", "tcsh"} {
		if cshBin, err := exec.LookPath(cshName); err == nil {
			cshCmd := exec.CommandContext(t.Context(), cshBin, "-c", suBody)
			cshOut, err := cshCmd.CombinedOutput()
			if err != nil {
				t.Fatalf("exec %s -c suBody failed: %v, output: %s", cshName, err, string(cshOut))
			}
			if string(cshOut) != wantOut {
				t.Fatalf("%s root execution output mismatch: got %q, want %q", cshName, string(cshOut), wantOut)
			}
		}
	}
}

func TestCshPrivilegeMultilineSu(t *testing.T) {
	client := NewTestClient(ConnectionConfig{})
	multilineCommands := []string{
		"echo first\necho second",
		"echo first\r\necho second\r\n",
		"cd -- '/var/tmp' || exit $status\npwd",
		"cd -- '/var/tmp' || exit $status\r\npwd",
		"echo line1!\necho line2\necho line3!",
		"echo line1!\r\necho line2\r\necho line3!\r\n",
	}
	for _, interp := range []Interpreter{InterpreterCsh, InterpreterTcsh, InterpreterSh} {
		for _, dialect := range []LaunchDialect{LaunchCsh, LaunchPOSIX} {
			exchangeSu := newPrivilegeExchange(client, SudoModeSu, false, interp)
			exchangeSu.launchDialect = dialect
			for _, cmd := range multilineCommands {
				verifyMultilineSuQuoting(t, exchangeSu, interp, dialect, cmd)
			}
		}
	}

	execCases := []struct {
		name    string
		cmd     string
		wantOut string
	}{
		{"single_line", "echo first", "first\n"},
		{"single_line_bang", "echo first!", "first!\n"},
		{"single_line_crlf", "echo first\r\n", "first\n"},
		{"single_line_quotes", "echo 'hello' \"world\"", "hello world\n"},
		{"two_lines", "echo first\necho second", "first\nsecond\n"},
		{"two_lines_crlf", "echo first\r\necho second\r\n", "first\nsecond\n"},
		{"bang_multiline", "echo line1!\necho line2\necho line3!", "line1!\nline2\nline3!\n"},
		{"bang_multiline_crlf", "echo line1!\r\necho line2\r\necho line3!\r\n", "line1!\nline2\nline3!\n"},
		{"variables", "VAR='hello world'\necho $VAR\necho done", "hello world\ndone\n"},
		{"quotes_and_slashes", "echo 'single quoted'\necho \"double quoted\"\necho 'path\\to\\file'", "single quoted\ndouble quoted\npath\\to\\file\n"},
		{"multiline_empty_line", "echo first\n\necho second", "first\nsecond\n"},
		{"multiline_comment", "echo first\n# a comment\necho second", "first\nsecond\n"},
		{"multiline_heredoc", "cat << 'EOF'\nheredoc test\nEOF", "heredoc test\n"},
	}

	for _, dialect := range []LaunchDialect{LaunchPOSIX, LaunchCsh} {
		for _, interp := range []Interpreter{InterpreterSh, InterpreterCsh} {
			for _, tc := range execCases {
				testName := fmt.Sprintf("%s_%s_%s", dialect, interp, tc.name)
				t.Run(testName, func(t *testing.T) {
					exchangeSu := newPrivilegeExchange(client, SudoModeSu, false, interp)
					exchangeSu.launchDialect = dialect
					wrapped := exchangeSu.wrapPortableBody(tc.cmd, "prompt")
					prefix := "export LC_ALL=C; su - root -c "
					if dialect == LaunchCsh {
						prefix = "env LC_ALL=C su - root -c "
					}
					quotedBody := strings.TrimPrefix(wrapped, prefix)
					var suBody string
					var err error
					if dialect == LaunchCsh {
						suBody, err = cshUnquote(quotedBody)
					} else {
						suBody, err = unquoteSingleQuote(quotedBody)
					}
					if err != nil {
						t.Fatalf("unquote suBody: %v", err)
					}
					verifySuBodyExecution(t, suBody, tc.wantOut)
				})
			}
		}
	}

	cfg := &ExecutionConfig{Interpreter: InterpreterCsh, LaunchDialect: LaunchCsh}
	formatted, err := FormatWorkingDirCommand("/var/tmp/dir'bang!", "pwd", cfg)
	if err != nil {
		t.Fatal(err)
	}
	exchangeSu := newPrivilegeExchange(client, SudoModeSu, false, InterpreterCsh)
	exchangeSu.launchDialect = LaunchCsh
	wrapped := exchangeSu.wrapPortableBody(formatted, "prompt")
	if strings.Contains(wrapped, "\n") {
		t.Fatalf("expected no literal newlines in wrapped cwd command, got:\n%s", wrapped)
	}
	if strings.Contains(wrapped, "\\\n") {
		t.Fatalf("expected no line continuation backslash in wrapped cwd command, got:\n%s", wrapped)
	}
}
