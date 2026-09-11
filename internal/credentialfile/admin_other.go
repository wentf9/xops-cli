//go:build (!linux && !darwin && !windows) || (!amd64 && !arm64)

package credentialfile

import (
	"context"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// Init refuses unsupported platforms without creating files.
func (*Runtime) Init(context.Context, string, string, Wrapping) (MaintenanceResult, error) {
	return MaintenanceResult{}, ErrUnsupported
}

// Rewrap refuses unsupported platforms.
func (*Store) Rewrap(context.Context, Wrapping) (MaintenanceResult, error) {
	return MaintenanceResult{}, ErrUnsupported
}

// Reencrypt refuses unsupported platforms.
func (*Store) Reencrypt(context.Context, Wrapping) (MaintenanceResult, error) {
	return MaintenanceResult{}, ErrUnsupported
}

// Resume refuses unsupported platforms.
func (*Store) Resume(context.Context, Wrapping, Wrapping) (MaintenanceResult, error) {
	return MaintenanceResult{}, ErrUnsupported
}

// ResumeFrom refuses unsupported platforms.
func (*Store) ResumeFrom(context.Context, *Store, Wrapping, Wrapping) (MaintenanceResult, error) {
	return MaintenanceResult{}, ErrUnsupported
}

// Clone refuses unsupported platforms.
func (*Store) Clone(context.Context, string, string, Wrapping) (MaintenanceResult, error) {
	return MaintenanceResult{}, ErrUnsupported
}

// Restore refuses unsupported platforms.
func (*Store) Restore(context.Context, string, Wrapping, []credential.Ref) (MaintenanceResult, error) {
	return MaintenanceResult{}, ErrUnsupported
}

// Prune refuses unsupported platforms.
func (*Store) Prune(context.Context, bool) (PruneResult, error) { return PruneResult{}, ErrUnsupported }
