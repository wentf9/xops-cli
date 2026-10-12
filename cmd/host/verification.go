package host

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/terminal"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

type inventoryVerification struct {
	config.ConnectionSnapshot
	Probe    bool
	Result   *ssh.ProbeResult
	ProbeErr error
}

type inventoryVerifier func(context.Context, *config.Repository, string, *inventoryVerification) error

func verifyInventoryNode(ctx context.Context, repo *config.Repository, nodeID string, bundle *inventoryVerification) error {
	preview, err := repo.PreviewConnection(nodeID, bundle.Node, bundle.Host, bundle.Identity)
	if err != nil {
		return err
	}
	registry, err := utils.GetCredentialRegistry(repo.Snapshot())
	if err != nil {
		return fmt.Errorf("initialize verification credentials: %w", err)
	}
	if !bundle.Probe {
		return adapter.VerifyConnection(ctx, preview, nodeID, registry)
	}
	result, err := adapter.VerifyConnectionWithProbe(ctx, preview, nodeID, registry)
	bundle.Result, bundle.ProbeErr = result.Probe, result.ProbeErr
	return err
}

func confirmFailedVerification(cmd *cobra.Command, nodeID string, verifyErr error) error {
	message := i18n.Tf("inventory_verify_not_saved", map[string]any{"Node": nodeID, "Error": verifyErr})
	if _, err := fmt.Fprintln(cmd.ErrOrStderr(), message); err != nil {
		return errors.Join(verifyErr, fmt.Errorf("report verification failure: %w", err))
	}
	if err := cmd.Context().Err(); err != nil {
		return errors.Join(verifyErr, err)
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
	defer cancel()
	prompt := i18n.T("inventory_confirm_save_unverified") + " [y/N]: "
	answer, err := terminal.NewPrompter(cmd.InOrStdin(), cmd.ErrOrStderr()).ReadLine(ctx, prompt)
	if err != nil {
		return errors.Join(verifyErr, fmt.Errorf("confirm saving unverified node (use --skip-verify for unattended addition): %w", err))
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return fmt.Errorf("%s: %w", i18n.T("inventory_save_declined"), verifyErr)
	}
	return nil
}

func verifyAndConfirmAddedNode(cmd *cobra.Command, repo *config.Repository, nodeID string, bundle *inventoryVerification, auth utils.HostInfo, verify inventoryVerifier) error {
	draft := importDraft{bundle: bundle.ConnectionSnapshot, addr: auth}
	bundle.ConnectionSnapshot = draft.verificationBundle()
	if err := verify(cmd.Context(), repo, nodeID, bundle); err != nil {
		bundle.Result = nil
		return confirmFailedVerification(cmd, nodeID, err)
	}
	return nil
}

func verifyAndProbeAddedNode(cmd *cobra.Command, repo *config.Repository, nodeID string, bundle *inventoryVerification, auth utils.HostInfo, verify inventoryVerifier) (*ssh.ExecutionConfig, error) {
	explicit := bundle.Node.Execution.Clone()
	if err := verifyAndConfirmAddedNode(cmd, repo, nodeID, bundle, auth, verify); err != nil {
		return nil, err
	}
	execution, warning := enrollmentExecution(explicit, bundle)
	if warning != nil {
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), probeWarning(nodeID, warning)); err != nil {
			return nil, fmt.Errorf("report execution probe warning: %w", err)
		}
	}
	return execution, nil
}
