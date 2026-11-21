package adapter

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
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

func (a *SSHAdapter) isPendingNode(nodeID string) bool {
	if a == nil || a.cfgProvider == nil || nodeID == "" {
		return false
	}
	checker, ok := a.cfgProvider.(interface{ IsPendingNode(string) bool })
	return ok && checker.IsPendingNode(nodeID)
}

func (a *SSHAdapter) stageDeferredAuth(nodeID, authUpdateToken, password, keyPath, passphrase string) {
	if a == nil || nodeID == "" {
		return
	}
	entry := &deferredAuthUpdate{
		authUpdateToken: authUpdateToken,
		keyPath:         keyPath,
	}
	if password != "" {
		entry.password = []byte(password)
	}
	if passphrase != "" {
		entry.passphrase = []byte(passphrase)
	}
	a.deferredAuthMu.Lock()
	if a.deferredAuth == nil {
		a.deferredAuth = make(map[string]*deferredAuthUpdate)
	}
	if old := a.deferredAuth[nodeID]; old != nil {
		old.zero()
	}
	a.deferredAuth[nodeID] = entry
	a.deferredAuthMu.Unlock()
}

func (a *SSHAdapter) takeDeferredAuth(nodeID string) *deferredAuthUpdate {
	if a == nil || nodeID == "" {
		return nil
	}
	a.deferredAuthMu.Lock()
	entry := a.deferredAuth[nodeID]
	delete(a.deferredAuth, nodeID)
	a.deferredAuthMu.Unlock()
	return entry
}

// ClearDeferredAuth wipes and drops any buffered handshake credentials for
// nodeID. Callers invoke this on cleanup if FinalizePendingConnection is not run.
func (a *SSHAdapter) ClearDeferredAuth(nodeID string) {
	if entry := a.takeDeferredAuth(nodeID); entry != nil {
		entry.zero()
	}
}

// FinalizePendingConnection confirms a scoped PendingLease after Connect
// succeeds (across fresh handshakes, cached pool hits, and ControlMaster
// attachment), runs optional read-only enrollment probing for brand-new
// remembered nodes, and flushes any handshake credentials buffered while the
// node was pending.
func (a *SSHAdapter) FinalizePendingConnection(ctx context.Context, lease config.PendingLease, client *ssh.Client) error {
	if a == nil || lease == nil {
		return nil
	}
	nodeID := lease.NodeID()
	defer a.ClearDeferredAuth(nodeID)

	auth, hasOverride := a.getSessionOverride(nodeID)
	if a.suppressNodeConfirmation || (hasOverride && auth.SuppressNodeConfirmation) {
		return nil
	}
	if nodeID != "" && a.cfgProvider != nil {
		_, _ = a.Resolve(ctx, ResolveRequest{
			NodeID:          nodeID,
			AllowBatchLatch: true,
		})
	}

	confirmed, err := a.confirmWithOptionalProbe(ctx, lease, nodeID, auth, hasOverride, client)
	if err != nil {
		return err
	}
	if !confirmed {
		if err := lease.Confirm(ctx); err != nil {
			return err
		}
	}
	return a.flushDeferredAuth(ctx, nodeID, client)
}

func (a *SSHAdapter) needsEnrollmentProbe(nodeID string, auth SessionAuth, hasOverride bool, client *ssh.Client) (bool, error) {
	if client == nil || !a.enrollmentProbe || !a.credentialRecording || !hasOverride || !auth.Remember || a.isNonInteractiveForNode(nodeID) {
		return false, nil
	}
	if _, excluded := a.enrollmentProbeExcluded[nodeID]; excluded {
		return false, nil
	}
	probeRepo, ok := a.cfgProvider.(interface {
		PendingNodeExecution(string) (*ssh.ExecutionConfig, bool)
	})
	if !ok {
		return false, nil
	}
	nodeExecution, pending := probeRepo.PendingNodeExecution(nodeID)
	if !pending {
		return false, nil
	}
	effective, err := ssh.EffectiveExecution(nodeExecution, a.cfgProvider.Snapshot().Execution)
	if err != nil {
		return false, fmt.Errorf("resolve enrollment execution: %w", err)
	}
	return ssh.NeedsExecutionProbe(effective), nil
}

func (a *SSHAdapter) confirmWithOptionalProbe(
	ctx context.Context,
	lease config.PendingLease,
	nodeID string,
	auth SessionAuth,
	hasOverride bool,
	client *ssh.Client,
) (bool, error) {
	needsProbe, err := a.needsEnrollmentProbe(nodeID, auth, hasOverride, client)
	if err != nil || !needsProbe {
		return false, err
	}
	result, probeErr := client.ProbeExecutionConfig(ctx)
	if probeErr != nil {
		if a.enrollmentProbeWarning != nil {
			a.enrollmentProbeWarning(nodeID, probeErr)
		}
		if err := lease.Confirm(ctx); err != nil {
			return false, err
		}
		if tErr := client.TransportError(); tErr != nil {
			return true, transportInitConnectionError(nodeID, client, tErr)
		}
		return true, nil
	}
	if err := confirmLeaseWithExecution(ctx, lease, &result.SuggestedConfig); err != nil {
		return false, err
	}
	if tErr := client.TransportError(); tErr != nil {
		return true, transportInitConnectionError(nodeID, client, tErr)
	}
	// Another connection may have confirmed the pending node while this probe
	// was running. Adopt only settings actually published by the repository.
	if confirmedNode, exists := a.cfgProvider.GetNode(nodeID); exists && confirmedNode.Execution != nil {
		effectiveExec := confirmedNode.Execution
		if resolved, err := ssh.ResolveExecution(confirmedNode.Execution, a.cfgProvider.Snapshot().Execution); err == nil {
			effectiveExec = resolved
		}
		client.SetExecution(effectiveExec)
	}
	return true, nil
}

func confirmLeaseWithExecution(ctx context.Context, lease config.PendingLease, execCfg *ssh.ExecutionConfig) error {
	if execLease, ok := lease.(config.PendingExecutionLease); ok {
		return execLease.ConfirmWithExecution(ctx, execCfg)
	}
	return lease.Confirm(ctx)
}

func (a *SSHAdapter) flushDeferredAuth(ctx context.Context, nodeID string, client *ssh.Client) error {
	deferred := a.takeDeferredAuth(nodeID)
	if deferred == nil {
		return nil
	}
	defer deferred.zero()

	if client != nil {
		if tErr := client.TransportError(); tErr != nil {
			return transportInitConnectionError(nodeID, client, tErr)
		}
	}
	committedToken, err := a.UpdateAuth(
		ctx,
		nodeID,
		deferred.authUpdateToken,
		string(deferred.password),
		deferred.keyPath,
		string(deferred.passphrase),
	)
	if err != nil {
		return fmt.Errorf("failed to update authentication for node %q: %w", nodeID, err)
	}
	if client != nil && committedToken != "" {
		var keyPath string
		var keyPaths []string
		if newCfg, cfgErr := a.GetConfig(nodeID); cfgErr == nil && newCfg != nil {
			keyPath = newCfg.KeyPath
			keyPaths = newCfg.KeyPaths
		}
		client.ApplyRecordedAuth(committedToken, keyPath, keyPaths)
	}
	return nil
}

func transportInitConnectionError(nodeID string, client *ssh.Client, transportErr error) error {
	var connCfg ssh.ConnectionConfig
	if client != nil {
		connCfg = client.ConnectionConfig()
	}
	return &ssh.ConnectionError{
		NodeID:   nodeID,
		Address:  connCfg.Address,
		Port:     connCfg.Port,
		AuthType: connCfg.AuthType,
		Err:      fmt.Errorf("SSH transport closed during initialization: %w", transportErr),
	}
}
