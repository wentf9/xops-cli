// Package tunnel preserves the legacy import path for the shared state machine.
package tunnel

import (
	"context"
	core "github.com/wentf9/xops-cli/core/mcp/tunnel"
)

type Manager = core.Manager
type Observer = core.Observer
type Runner = core.Runner
type Spec = core.Spec
type Status = core.Status

const ConnectionLimit = core.ConnectionLimit
const DefaultTTL = core.DefaultTTL
const MaxActive = core.MaxActive
const MaxRecords = core.MaxRecords
const MaxTTL = core.MaxTTL
const Retention = core.Retention

func Normalize(spec Spec) (Spec, error) { return core.Normalize(spec) }
func New(ctx context.Context, run Runner, observe Observer) *Manager {
	return core.New(ctx, run, observe)
}
