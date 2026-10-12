package config

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/ssh"
)

// UpdateNodeExecutionAtRefContext updates only execution settings. The selected
// node bundle must still match ref, including its host and identity; a probe of
// an old endpoint must never overwrite a concurrently edited node.
func (r *Repository) UpdateNodeExecutionAtRefContext(ctx context.Context, ref NodeRef, execution *ssh.ExecutionConfig) error {
	execution = execution.Clone()
	if err := execution.Validate(); err != nil {
		return fmt.Errorf("validate node execution update: %w", err)
	}
	return r.commitContext(ctx, anyRevision, func(cfg *Configuration) error {
		if err := ensureNodeRefs(cfg, []NodeRef{ref}); err != nil {
			return err
		}
		node, _ := cfg.Nodes.Get(ref.ID)
		node.Execution = execution.Clone()
		cfg.Nodes.Set(ref.ID, node)
		return nil
	})
}
