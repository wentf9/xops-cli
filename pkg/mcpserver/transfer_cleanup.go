package mcpserver

import "github.com/wentf9/xops-cli/pkg/mcpserver/transfer"

// Recovery only cleans known precommit leftovers (or explicitly resolved
// outcomes). A single cancellable worker bounds reconnect work at startup.
func (r *Runtime) startRecoveryCleanup() {
	done := make(chan struct{})
	r.recoveryDone = done
	var pending []string
	for _, record := range r.transfers.Records() {
		if record.CleanupPending && (record.State != transfer.Unknown || record.Resolved) {
			pending = append(pending, record.ID)
		}
	}
	if len(pending) == 0 {
		close(done)
		return
	}
	go func() {
		defer close(done)
		for _, id := range pending {
			if r.ctx.Err() != nil {
				return
			}
			if err := r.cleanupTransferContext(r.ctx, id); err != nil {
				r.logger.Debugf("recover owned transfer temporary file failed: %v", err)
				if r.ctx.Err() != nil {
					return
				}
				if err := r.transfers.Warn(id, "recovery cleanup remains pending; use mcp recover while stopped"); err != nil {
					r.logger.Debugf("persist recovery cleanup warning failed: %v", err)
				}
			}
		}
	}()
}
