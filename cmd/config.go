package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// NewCmdConfig creates the `xops config` parent command.
func NewCmdConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "config",
		Aliases: []string{"cfg"},
		Short:   i18n.T("config_short"),
		Long:    i18n.T("config_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newCmdConfigDoctor())
	return cmd
}

func newCmdConfigDoctor() *cobra.Command {
	var fix bool
	cmd := &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"doc", "check"},
		Short:   i18n.T("config_doctor_short"),
		Long:    i18n.T("config_doctor_long"),
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigDoctor(cmd, fix)
		},
	}
	cmd.Flags().BoolVar(&fix, "fix", false, i18n.T("flag_config_doctor_fix"))
	return cmd
}

func runConfigDoctor(cmd *cobra.Command, fix bool) error {
	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		return err
	}

	var report *config.DoctorReport
	var runErr error
	if fix {
		report, runErr = config.FixConfigFile(cmd.Context(), cfgPath, keyPath)
	} else {
		report, runErr = config.DiagnoseConfigFile(cfgPath)
	}
	if report == nil {
		return runErr
	}
	if err := renderConfigDoctorReport(cmd, report, fix); err != nil {
		return err
	}
	if runErr != nil {
		return runErr
	}
	if report.HasErrors() {
		return fmt.Errorf("%s", i18n.Tf("config_doctor_issues_found", map[string]any{"Count": len(report.Issues)}))
	}
	return nil
}

func renderConfigDoctorReport(cmd *cobra.Command, report *config.DoctorReport, fix bool) error {
	out := cmd.OutOrStdout()
	if !report.Exists {
		_, err := fmt.Fprintln(out, i18n.Tf("config_doctor_not_found", map[string]any{"Path": report.Path}))
		return err
	}
	if len(report.Fixes) > 0 || len(report.Issues) > 0 {
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		if _, err := fmt.Fprintln(w, "STATUS\tCODE\tENTITY\tDETAILS"); err != nil {
			return fmt.Errorf("write config doctor header failed: %w", err)
		}
		for _, applied := range report.Fixes {
			if _, err := fmt.Fprintf(w, "FIXED\t%s\t%s\t%s\n", applied.Code, applied.Entity, applied.Summary); err != nil {
				return fmt.Errorf("write config doctor fix row failed: %w", err)
			}
		}
		for _, issue := range report.Issues {
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", issue.Severity, issue.Code, issue.Entity, issue.Message); err != nil {
				return fmt.Errorf("write config doctor issue row failed: %w", err)
			}
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("flush config doctor report failed: %w", err)
		}
	}
	if report.Healthy() {
		if fix && len(report.Fixes) > 0 {
			_, err := fmt.Fprintln(out, i18n.Tf("config_doctor_fixed", map[string]any{"Count": len(report.Fixes)}))
			return err
		}
		_, err := fmt.Fprintln(out, i18n.T("config_doctor_healthy"))
		return err
	}
	if !fix && report.HasFixableIssues() {
		_, err := fmt.Fprintln(out, i18n.T("config_doctor_fix_hint"))
		return err
	}
	if fix && report.HasErrors() {
		_, err := fmt.Fprintln(out, i18n.T("config_doctor_unfixable"))
		return err
	}
	return nil
}
