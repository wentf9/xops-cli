//go:build darwin && (amd64 || arm64)

package kdfhelper

import (
	"context"
	"os"
	"strconv"
	"time"
)

// Darwin has no Linux Pdeathsig. The private worker checks its designated
// parent independently of pipe I/O and the KDF computation.
func startParentGuard() (func(), error) {
	expected, err := strconv.Atoi(os.Getenv("XOPS_INTERNAL_KDF_PARENT"))
	if err != nil || expected <= 1 || os.Getppid() != expected {
		return nil, ErrProcess
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if os.Getppid() != expected {
					os.Exit(1)
				}
			}
		}
	}()
	return func() { cancel(); <-done }, nil
}
