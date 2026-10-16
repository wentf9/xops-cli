//go:build !windows

package sshenv

import "context"

// OutputContext leaves native non-Windows output adapters unchanged.
func OutputContext(ctx context.Context) (context.Context, func() error, error) {
	return ctx, func() error { return nil }, nil
}

func platformServeConsoleOutputRelay(string) int { return 2 }
