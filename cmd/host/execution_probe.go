package host

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func registerEnrollmentProbeFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("probe", true, i18n.T("flag_host_probe"))
	cmd.Flags().Bool("no-probe", false, i18n.T("flag_host_no_probe"))
	cmd.Flags().String("interpreter", "", i18n.T("flag_host_interpreter"))
	cmd.Flags().String("launch-dialect", "", i18n.T("flag_host_launch_dialect"))
	cmd.MarkFlagsMutuallyExclusive("probe", "no-probe")
}

func enrollmentProbeOptions(cmd *cobra.Command) (bool, *ssh.ExecutionConfig, error) {
	probe, err := cmd.Flags().GetBool("probe")
	if err != nil {
		return false, nil, fmt.Errorf("read probe option: %w", err)
	}
	noProbe, err := cmd.Flags().GetBool("no-probe")
	if err != nil {
		return false, nil, fmt.Errorf("read no-probe option: %w", err)
	}
	var execution *ssh.ExecutionConfig
	for _, flag := range []string{"interpreter", "launch-dialect"} {
		if !cmd.Flags().Changed(flag) {
			continue
		}
		value, err := cmd.Flags().GetString(flag)
		if err != nil {
			return false, nil, fmt.Errorf("read %s option: %w", flag, err)
		}
		if value == "" {
			return false, nil, fmt.Errorf("explicit %s must not be empty", flag)
		}
		if execution == nil {
			execution = &ssh.ExecutionConfig{}
		}
		if flag == "interpreter" {
			execution.Interpreter = ssh.Interpreter(value)
		} else {
			execution.LaunchDialect = ssh.LaunchDialect(value)
		}
	}
	return probe && !noProbe, execution, execution.Validate()
}

// enrollmentExecution never overwrites explicit fields or persists a partial
// probe result. An incompatible recommendation leaves only the explicit config.
func enrollmentExecution(explicit *ssh.ExecutionConfig, check *inventoryVerification) (*ssh.ExecutionConfig, error) {
	if !check.Probe || check.ProbeErr != nil || check.Result == nil {
		return explicit.Clone(), check.ProbeErr
	}
	if explicit != nil && explicit.LaunchDialect != "" && explicit.LaunchDialect != check.Result.DetectedDialect {
		return explicit.Clone(), fmt.Errorf("explicit launch dialect %q differs from detected %q", explicit.LaunchDialect, check.Result.DetectedDialect)
	}
	resolved, err := ssh.ResolveExecution(explicit, &check.Result.SuggestedConfig)
	if err != nil {
		return explicit.Clone(), fmt.Errorf("merge probe recommendation with explicit execution: %w", err)
	}
	return resolved, nil
}

func probeWarning(nodeID string, err error) string {
	return i18n.Tf("inventory_probe_warning", map[string]any{"Node": nodeID, "Error": err})
}
