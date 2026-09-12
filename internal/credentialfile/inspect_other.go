//go:build (!linux && !darwin && !windows) || (!amd64 && !arm64)

package credentialfile

import "context"

// Inspect fails closed on unsupported platforms.
func (*Store) Inspect(context.Context, bool) (Inspection, error) { return Inspection{}, ErrUnsupported }

// RecoveryNeedsSource fails closed on unsupported platforms.
func (*Store) RecoveryNeedsSource(context.Context) (bool, error) { return false, ErrUnsupported }
