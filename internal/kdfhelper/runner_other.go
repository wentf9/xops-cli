//go:build (!linux && !darwin && !windows) || (!amd64 && !arm64)

package kdfhelper

import (
	"context"
	"os"
)

// Derive fails closed until native process lifecycle validation is available.
func (Runner) Derive(context.Context, Request) ([]byte, error) { return nil, ErrUnsupported }

// ServeFiles never performs KDF work on unsupported platforms.
func ServeFiles(*os.File, *os.File) int { return 1 }

func memorySnapshot() (uint64, bool) { return 0, false }
