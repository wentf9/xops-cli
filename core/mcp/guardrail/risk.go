package guardrail

import (
	"net/netip"

	"github.com/wentf9/xops-cli/core/ssh"
)

// RiskLevel represents the danger level of a tool invocation.
type RiskLevel int

const (
	Safe      RiskLevel = iota // read-only, no side effects
	Moderate                   // creates or modifies data, recoverable
	Dangerous                  // destructive or arbitrary execution
)

func (r RiskLevel) String() string {
	switch r {
	case Safe:
		return "safe"
	case Moderate:
		return "moderate"
	case Dangerous:
		return "dangerous"
	default:
		return "unknown"
	}
}

// ParseRiskLevel converts a string to RiskLevel, defaulting to Dangerous.
func ParseRiskLevel(s string) RiskLevel {
	switch s {
	case "safe":
		return Safe
	case "moderate":
		return Moderate
	case "dangerous":
		return Dangerous
	default:
		return Dangerous
	}
}

// RiskInput carries contextual information about a single tool invocation
// for risk assessment.
type RiskInput struct {
	ToolName   string
	Action     string // polymorphic sub-action (e.g. read/write/patch/stat, push/pull, create/list/status/stop)
	NodeID     string
	NodeIDs    []string // additional canonical nodes covered by a batch operation
	Command    string   // populated for terminal command execution
	Text       string   // keystrokes typed into a remote GUI session (gui type)
	Paths      []string // file/directory paths involved
	Sudo       bool     // whether sudo is requested
	Details    string   // deferred-operation size, digest and overwrite information
	TunnelMode string   // local, remote, or dynamic SSH forwarding
	ListenHost string   // normalized IP literal, never resolved through DNS
	Execution  *ssh.ExecutionConfig
	Dialect    string
	PlanDigest string
}

// Classify returns the effective risk level for a tool invocation.
func Classify(input RiskInput) RiskLevel {
	base := classifyBase(input)

	pathRisk := AnalyzePaths(input.Paths)
	if pathRisk > base {
		return pathRisk
	}
	return base
}

func classifyBase(input RiskInput) RiskLevel {
	switch input.ToolName {
	case "nodes":
		return Safe
	case "terminal":
		return classifyTerminal(input)
	case "file":
		return classifyFile(input.Action)
	case "gui":
		return classifyGUI(input)
	case "transfer":
		return classifyTransfer(input.Action)
	case "tunnel":
		return classifyTunnel(input)
	default:
		return Dangerous
	}
}

func classifyTerminal(input RiskInput) RiskLevel {
	if input.Command == "" && input.Action == "poll" {
		return Safe
	}
	isPersistentRun := input.Action != "" && input.Action != "once" && input.Action != "poll"
	base := Dangerous
	if input.Command == "" && isPersistentRun {
		base = Moderate
	}
	if input.Command != "" {
		dialect := input.Dialect
		if dialect == "" && input.Execution != nil {
			dialect = string(input.Execution.CommandOptions().LaunchDialect)
			if dialect == "" {
				dialect = string(ssh.LaunchUnknown)
			}
		}
		base = AnalyzeCommandWithDialect(input.Command, dialect)
	}
	if (input.Sudo || isPersistentRun) && base < Moderate {
		base = Moderate
	}
	return base
}

func classifyFile(action string) RiskLevel {
	switch action {
	case "read", "stat":
		return Safe
	case "write", "patch":
		return Moderate
	default:
		return Dangerous
	}
}

// classifyGUI rates keyboard input (type and key) and any unknown action as
// Dangerous because keystrokes can be split across multiple calls and
// submitted with Return into a remote terminal window, bypassing single-call
// command analysis.
func classifyGUI(input RiskInput) RiskLevel {
	switch input.Action {
	case "shot", "move":
		return Safe
	case "click", "double_click", "right_click", "scroll", "drag":
		return Moderate
	default:
		return Dangerous
	}
}

func classifyTransfer(action string) RiskLevel {
	switch action {
	case "pull", "prepare_pull", "status", "cancel":
		return Safe
	case "push", "prepare_push":
		return Moderate
	default:
		return Dangerous
	}
}

func classifyTunnel(input RiskInput) RiskLevel {
	switch input.Action {
	case "list", "status":
		return Safe
	case "stop":
		return Moderate
	case "create":
		if input.TunnelMode == "local" {
			if addr, err := netip.ParseAddr(input.ListenHost); err == nil && addr.Unmap().IsLoopback() {
				return Moderate
			}
		}
		return Dangerous
	default:
		return Dangerous
	}
}
