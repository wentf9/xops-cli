package adapter

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/ssh"
)

// WithEnrollmentProbing enables read-only probing before a new authenticated
// node is saved. It still requires interactive credential remembering to be
// enabled for that node. The optional reporter belongs to the CLI layer.
func WithEnrollmentProbing(report func(string, error)) Option {
	return func(a *SSHAdapter) {
		a.enrollmentProbe = true
		a.enrollmentProbeWarning = report
	}
}

// WithEnrollmentProbeExclusions skips enrollment probing for nodes with explicit
// session execution choices. Other nodes, including jumps, retain their policy.
func WithEnrollmentProbeExclusions(nodeIDs ...string) Option {
	nodeIDs = append([]string(nil), nodeIDs...)
	return func(a *SSHAdapter) {
		if a.enrollmentProbeExcluded == nil {
			a.enrollmentProbeExcluded = make(map[string]struct{}, len(nodeIDs))
		}
		for _, nodeID := range nodeIDs {
			a.enrollmentProbeExcluded[nodeID] = struct{}{}
		}
	}
}

type enrollmentProbeRepository interface {
	PendingNodeExecution(string) (*ssh.ExecutionConfig, bool)
	ConfirmNodeWithExecutionContext(context.Context, string, *ssh.ExecutionConfig) error
}

// ConfirmAuthenticatedConnection probes only pending, remembered connections.
// A failed probe preserves authentication success and normal node enrollment.
func (a *SSHAdapter) ConfirmAuthenticatedConnection(ctx context.Context, nodeID string, client *ssh.Client) (*ssh.ExecutionConfig, error) {
	repo, ok := a.cfgProvider.(enrollmentProbeRepository)
	auth, remembering := a.getSessionOverride(nodeID)
	_, excluded := a.enrollmentProbeExcluded[nodeID]
	if !ok || !a.enrollmentProbe || excluded || a.nonInteractive || !a.credentialRecording || !remembering || !auth.Remember {
		return nil, a.ConfirmConnection(ctx, nodeID)
	}
	nodeExecution, pending := repo.PendingNodeExecution(nodeID)
	if !pending {
		return nil, a.ConfirmConnection(ctx, nodeID)
	}
	effective, err := ssh.EffectiveExecution(nodeExecution, a.cfgProvider.Snapshot().Execution)
	if err != nil {
		return nil, fmt.Errorf("resolve enrollment execution: %w", err)
	}
	if !ssh.NeedsExecutionProbe(effective) {
		return nil, a.ConfirmConnection(ctx, nodeID)
	}
	result, probeErr := client.ProbeExecutionConfig(ctx)
	if probeErr != nil {
		if a.enrollmentProbeWarning != nil {
			a.enrollmentProbeWarning(nodeID, probeErr)
		}
		return nil, a.ConfirmConnection(ctx, nodeID)
	}
	if err := repo.ConfirmNodeWithExecutionContext(ctx, nodeID, &result.SuggestedConfig); err != nil {
		return nil, err
	}
	// Another connection may have confirmed the pending node while this probe
	// was running. Adopt only settings actually published by the repository.
	confirmed, _ := a.cfgProvider.GetNode(nodeID)
	return confirmed.Execution.Clone(), nil
}
