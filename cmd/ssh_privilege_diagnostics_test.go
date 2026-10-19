package cmd

import (
	"bytes"
	"strings"
	"testing"

	corelog "github.com/wentf9/xops-cli/core/log"
)

func TestSSHPrivilegeDiagnosticDetailsEscapeUntrustedText(t *testing.T) {
	for _, phase := range []string{"command_prepared", "password_prompt_matched", "password_prompt_pattern", "password_prompt_fallback_pattern"} {
		value := "text\n\x1b[31m" + strings.Repeat("x", 1000)
		text := formatSSHDiagnostic(corelog.Diagnostic{Kind: corelog.PrivilegeLifecycle, Outcome: phase, PrivilegeCommand: value, PrivilegePrompt: value, PrivilegePromptPattern: value})
		if strings.ContainsAny(text, "\n\x1b") || !strings.Contains(text, `\n\x1b`) || len(text) > 500 {
			t.Fatalf("unsafe or unbounded %s: %q", phase, text)
		}
	}
}

func TestSSHPrivilegeDiagnosticLevels(t *testing.T) {
	for level := 1; level <= 3; level++ {
		var output bytes.Buffer
		diagnostics, err := newSSHDiagnostics(t.Context(), &output, level)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range []corelog.Diagnostic{
			{Kind: corelog.PrivilegeLifecycle, Operation: "sudo", Outcome: "attempt_started", Attempt: 1},
			{Kind: corelog.PrivilegeLifecycle, Operation: "sudo", Outcome: "password_prompt", Level: 2, Attempt: 2},
			{Kind: corelog.PrivilegeLifecycle, Operation: "sudo", Outcome: "terminal_restored", Level: 3},
			{Kind: corelog.PrivilegeLifecycle, Operation: "sudo", Outcome: "command_prepared", PrivilegeCommand: "sudo -S -p '<password-prompt>' -- bash -c '<privileged payload>'"},
			{Kind: corelog.PrivilegeLifecycle, Operation: "sudo", Outcome: "password_prompt_pattern", PrivilegePromptPattern: "<password-prompt>", Level: 2},
			{Kind: corelog.PrivilegeLifecycle, Operation: "sudo", Outcome: "password_prompt_fallback_pattern", PrivilegePromptPattern: "Password:", Level: 2},
			{Kind: corelog.PrivilegeLifecycle, Operation: "sudo", Outcome: "password_prompt_matched", PrivilegePrompt: "[sudo: <password-prompt>] Password:", Level: 2},
		} {
			event.NodeID = "fixture"
			diagnostics.ObserveDiagnostic(event)
		}
		if err := diagnostics.finish(); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		if !strings.Contains(text, `Privilege escalation via "sudo" for "fixture": "attempt started" (attempt 1)`) {
			t.Fatalf("privilege phase/mode/counter missing: %s", text)
		}
		if !strings.Contains(text, "sudo -S -p '<password-prompt>' -- bash -c '<privileged payload>'") {
			t.Fatalf("privilege invocation missing: %s", text)
		}
		if strings.Contains(text, "password prompt fallback pattern") != (level >= 2) {
			t.Fatalf("fallback pattern level incorrect: %s", text)
		}
		if strings.Contains(text, "[sudo: <password-prompt>] Password:") != (level >= 2) {
			t.Fatalf("matched prompt level incorrect: %s", text)
		}
		if strings.Contains(text, "password prompt") != (level >= 2) || strings.Contains(text, "terminal restored") != (level >= 3) {
			t.Fatalf("privilege levels not enforced: %s", text)
		}
	}
}
