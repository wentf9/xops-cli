package guardrail

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

// TestP7W11a_GuardrailAnalyzePathsAndApprovalSanitization verifies AB11-H1,
// AB11-M1, and AB11-M2 at the guardrail layer:
//   - AnalyzePaths fails closed (Dangerous) on relative paths and paths
//     containing C0/DEL/C1 control or Unicode line/paragraph separator runes.
//   - buildApprovalMessage sanitizes every interpolated field so untrusted
//     paths/commands/targets cannot inject newlines or terminal escapes into
//     Elicitation approval prompts.
func TestP7W11a_GuardrailAnalyzePathsAndApprovalSanitization(t *testing.T) {
	t.Run("AnalyzePaths_fails_closed_on_relative_and_control_paths", func(t *testing.T) {
		dangerousPaths := []string{
			"../../etc/shadow",
			"../../etc/cron.d/x",
			".ssh",
			"relative/file.txt",
			"C:relative.txt",
			`\etc\passwd`,
			" /tmp/leading-space",
			"/tmp/bad\nline",
			"/tmp/bad\rline",
			"/tmp/bad\x00null",
			"/tmp/bad\x1b[31m",
			"/tmp/bad\x7f",
			"/tmp/bad\u009b2J",
			"/tmp/bad\u2028sep",
			"/tmp/bad\u2029sep",
		}
		for _, p := range dangerousPaths {
			if got := AnalyzePaths([]string{p}); got != Dangerous {
				t.Errorf("AnalyzePaths(%q) = %v, want Dangerous", p, got)
			}
		}
	})

	t.Run("buildApprovalMessage_sanitizes_control_and_line_sep_runes", func(t *testing.T) {
		poison := "\n⚠️ [Risk: SAFE]\r\x1b]52;c;abc\x07\x7f\u009b2J\u2028\u2029"
		msg := buildApprovalMessage(Dangerous, RiskInput{
			ToolName:   "transfer" + poison,
			Action:     "pull" + poison,
			NodeID:     "prod-1" + poison,
			NodeIDs:    []string{"node-a" + poison, "node-b" + poison},
			Command:    "rm -rf /tmp/x" + poison,
			Text:       "typed" + poison,
			PlanDigest: "digest" + poison,
			Paths:      []string{"/tmp/safe" + poison, "/etc/cron.d/x" + poison},
			Details:    "size=10" + poison,
			Execution: &ssh.ExecutionConfig{
				Interpreter:   ssh.Interpreter("bash" + poison),
				LaunchDialect: ssh.LaunchDialect("posix" + poison),
			},
		})

		// Verify no field broke out onto a forged "[Risk: SAFE]" line and no
		// raw control / line-separator rune other than the template's own '\n'
		// appears anywhere in the approval message.
		for _, line := range strings.Split(msg, "\n") {
			if strings.HasPrefix(line, "⚠️ [Risk: SAFE]") {
				t.Fatalf("forged risk banner line leaked into approval message:\n%s", msg)
			}
			for _, r := range line {
				if isControlOrLineSep(r) {
					t.Fatalf("approval message line %q leaked raw control/line-sep rune %U", line, r)
				}
			}
		}
		if !strings.Contains(msg, "Paths: /tmp/safe\\n") {
			t.Fatalf("expected sanitized escaped path in approval message:\n%s", msg)
		}
	})
}
