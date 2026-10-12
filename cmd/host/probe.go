package host

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func NewCmdInventoryProbe() *cobra.Command {
	return newCmdInventoryProbe(verifyInventoryNode)
}

func newCmdInventoryProbe(verify inventoryVerifier) *cobra.Command {
	var save bool
	cmd := &cobra.Command{
		Use: "probe <node-id>", Short: i18n.T("inventory_probe_short"), Long: i18n.T("inventory_probe_long"),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, repo, _, err := utils.GetConfigStore()
			if err != nil {
				return fmt.Errorf("load probe configuration: %w", err)
			}
			view := repo.View()
			provider := config.NewProviderWithoutOpenSSH(view.Configuration)
			nodeID, err := provider.ResolveSelector(args[0])
			if err != nil {
				return fmt.Errorf("resolve probe node: %w", err)
			}
			ref, exists := view.NodeRefs[nodeID]
			if !exists {
				return fmt.Errorf("probe target %q is not a saved node", args[0])
			}
			bundle, err := provider.ResolveConnection(nodeID)
			if err != nil {
				return fmt.Errorf("resolve probe connection: %w", err)
			}
			check := inventoryVerification{ConnectionSnapshot: bundle, Probe: true}
			if err := verify(cmd.Context(), repo, nodeID, &check); err != nil {
				return fmt.Errorf("verify probe connection: %w", err)
			}
			if check.Result != nil {
				if err := writeProbeResult(cmd.OutOrStdout(), nodeID, check.Result); err != nil {
					return errors.Join(check.ProbeErr, err)
				}
			}
			if check.ProbeErr != nil {
				return fmt.Errorf("probe node %q: %w", nodeID, check.ProbeErr)
			}
			if check.Result == nil {
				return fmt.Errorf("probe node %q returned no result", nodeID)
			}
			if save {
				if err := repo.UpdateNodeExecutionAtRefContext(cmd.Context(), ref, &check.Result.SuggestedConfig); err != nil {
					return fmt.Errorf("save node probe recommendation: %w", err)
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), i18n.T("inventory_probe_saved")); err != nil {
					return fmt.Errorf("report saved probe recommendation: %w", err)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&save, "save", false, i18n.T("flag_host_probe_save"))
	return cmd
}

func writeProbeResult(out io.Writer, nodeID string, result *ssh.ProbeResult) error {
	interpreters := make([]string, len(result.AvailableInterpreters))
	for index, interpreter := range result.AvailableInterpreters {
		interpreters[index] = string(interpreter)
	}
	rows := []struct{ label, value string }{
		{"inventory_probe_node", nodeID},
		{"inventory_probe_os", result.RemoteOS},
		{"inventory_probe_shell", result.RemoteShellPath},
		{"inventory_probe_banner", result.ServerVersion},
		{"inventory_probe_dialect", string(result.DetectedDialect)},
		{"inventory_probe_available", strings.Join(interpreters, ", ")},
		{"inventory_probe_recommended", string(result.SuggestedConfig.Interpreter)},
		{"inventory_probe_login", string(result.SuggestedConfig.LoginMode())},
		{"inventory_probe_duration", result.Duration.String()},
	}
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	for _, row := range rows {
		value := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return ' '
			}
			return r
		}, row.value)
		if value == "" {
			value = "-"
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\n", i18n.T(row.label), value); err != nil {
			return fmt.Errorf("write probe result: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush probe result: %w", err)
	}
	return nil
}
