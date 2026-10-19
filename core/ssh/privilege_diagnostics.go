package ssh

import (
	"context"
	"errors"
	"regexp"
	"strings"

	corelog "github.com/wentf9/xops-cli/core/log"
)

// Privilege diagnostics reuse the caller-owned observer. Invocation previews
// redact user payloads; prompt metadata never reads credential response buffers.
func (c *Client) observePrivilege(mode SudoMode, phase string, level, attempt int) {
	// Other secret kinds are not privilege operations.
	if mode == "" {
		return
	}
	c.observeDiagnostic(corelog.Diagnostic{Kind: corelog.PrivilegeLifecycle, Level: level, Operation: string(mode), Outcome: phase, Attempt: attempt})
}

func (c *Client) observePrivilegeExchange(exchange *privilegeExchange, pattern *regexp.Regexp) {
	if c == nil || !corelog.DiagnosticEnabled(c.diagnostics, 1) {
		return
	}
	c.observePrivilegeCommand(exchange.mode, exchange.commandPreview)
	if exchange.mode == SudoModeSudoer {
		return // Keep the invocation, but omit password rules for noninteractive sudo -n.
	}
	c.observePrivilegePromptPattern(exchange.mode, pattern.String(), exchange.promptToken, false)
	if exchange.mode == SudoModeSudo && c.sudoPromptFallback != nil {
		c.observePrivilegePromptPattern(exchange.mode, c.sudoPromptFallback.String(), exchange.promptToken, true)
	}
}

func (w *privilegeFrameWriter) observePrompt(match []int) {
	if w.fallbackMatched {
		w.exchange.client.observePrivilege(w.exchange.mode, "password_prompt_fallback", 2, 0)
	}
	w.exchange.client.observePrivilegePrompt(w.exchange.mode, string(w.pending[match[0]:match[1]]), w.exchange.promptToken)
}

func (c *Client) observePrivilegeCommand(mode SudoMode, preview string) {
	c.observeDiagnostic(corelog.Diagnostic{Kind: corelog.PrivilegeLifecycle, Level: 1, Operation: string(mode), Outcome: "command_prepared", PrivilegeCommand: preview})
}

func (c *Client) observePrivilegePrompt(mode SudoMode, prompt, marker string) {
	if c == nil || !corelog.DiagnosticEnabled(c.diagnostics, 2) {
		return
	}
	c.observeDiagnostic(corelog.Diagnostic{Kind: corelog.PrivilegeLifecycle, Level: 2, Operation: string(mode), Outcome: "password_prompt_matched", PrivilegePrompt: privilegePromptText(prompt, marker)})
}

func (c *Client) observePrivilegePromptPattern(mode SudoMode, pattern, marker string, fallback bool) {
	if c == nil || !corelog.DiagnosticEnabled(c.diagnostics, 2) {
		return
	}
	phase := "password_prompt_pattern"
	if fallback {
		phase = "password_prompt_fallback_pattern"
	}
	c.observeDiagnostic(corelog.Diagnostic{Kind: corelog.PrivilegeLifecycle, Level: 2, Operation: string(mode), Outcome: phase, PrivilegePromptPattern: privilegePromptText(pattern, marker)})
}

func privilegePromptText(text, marker string) string {
	if marker != "" {
		text = strings.ReplaceAll(text, regexp.QuoteMeta(marker), "<password-prompt>")
		text = strings.ReplaceAll(text, marker, "<password-prompt>")
	}
	const limit = 1024
	if len(text) > limit {
		text = text[:limit-3] + "..."
	}
	return text
}

func (c *Client) observePrivilegeSelection(ctx context.Context, err error) {
	if c == nil || c.diagnostics == nil {
		return
	}
	mode := c.ConnectionConfig().SudoMode
	if err != nil {
		c.observePrivilegeResult(ctx, mode, err)
		return
	}
	if mode == "" || mode == SudoModeAuto {
		return
	}
	c.observePrivilege(mode, "mode_selected", 1, 0)
	if mode == SudoModeRoot {
		c.observePrivilege(mode, "escalation_not_required", 1, 0)
	}
}

func (c *Client) observePrivilegeResult(ctx context.Context, mode SudoMode, err error) {
	if c == nil || c.diagnostics == nil {
		return
	}
	phase := "operation_completed"
	if err != nil {
		phase = "operation_failed"
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			phase = "operation_timed_out"
		case errors.Is(err, context.Canceled):
			phase = "operation_canceled"
		case ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
			phase = "operation_timed_out"
		case ctx != nil && ctx.Err() != nil:
			phase = "operation_canceled"
		}
	}
	c.observePrivilege(mode, phase, 1, 0)
}
