package guardrail

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
	ToolName string
	NodeID   string
	Command  string   // populated only for ssh_run
	Paths    []string // file/directory paths involved
	Sudo     bool     // whether sudo is requested
	Details  string   // deferred-operation size, digest and overwrite information
}

// toolBaseRisk maps tool names to their static (baseline) risk level.
var toolBaseRisk = map[string]RiskLevel{
	"xops_list_nodes":       Safe,
	"xops_read_file":        Safe,
	"xops_fs_ls":            Safe,
	"xops_download":         Safe,
	"xops_prepare_download": Safe,
	"xops_transfer_status":  Safe,
	"xops_transfer_cancel":  Safe,

	"xops_write_file":     Moderate,
	"xops_upload":         Moderate,
	"xops_prepare_upload": Moderate,
	"xops_fs_mkdir":       Moderate,
	"xops_fs_touch":       Moderate,
	"xops_fs_mv":          Moderate,
	"xops_fs_cp":          Moderate,

	"xops_fs_rm":   Dangerous,
	"xops_ssh_run": Dangerous,
}

// Classify returns the effective risk level for a tool invocation.
// For ssh_run, it refines the level based on command analysis.
func Classify(input RiskInput) RiskLevel {
	base, ok := toolBaseRisk[input.ToolName]
	if !ok {
		return Dangerous // unknown tools default to highest risk
	}

	if input.ToolName == "xops_ssh_run" {
		if input.Command != "" {
			base = AnalyzeCommand(input.Command)
		}
		if input.Sudo && base < Moderate {
			base = Moderate
		}
	}

	pathRisk := AnalyzePaths(input.Paths)
	if pathRisk > base {
		return pathRisk
	}
	return base
}
