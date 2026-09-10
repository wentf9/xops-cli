package kdfhelper

import (
	"context"
	"errors"
	"time"
)

// PrivateArgument selects a single-use worker before normal CLI initialization.
const PrivateArgument = "__xops_kdf_v1"

var (
	// ErrProcess hides untrusted process output while preserving exit failures.
	ErrProcess = errors.New("private KDF process failed")
	// ErrUnsupported fails closed on platforms not natively validated.
	ErrUnsupported = errors.New("private KDF process is unsupported")
	// ErrResource indicates insufficient observable memory or an enforced limit failure.
	ErrResource = errors.New("private KDF resource unavailable")
)

// Runner launches the current binary, with a bounded process lifetime. An explicit
// delegated cgroup directory can enforce the provisional 128 MiB limit on Linux.
// Empty CgroupParent never elevates privileges and reports a soft-only capability.
type Runner struct {
	Timeout      time.Duration
	CgroupParent string
}

// Capabilities distinguishes Go's soft target from a kernel-enforced memory limit.
type Capabilities struct {
	HardMemoryLimit      bool
	MemoryObserved       bool
	AvailableMemoryBytes uint64
}

// Capabilities reports requested enforcement; Derive fails if it cannot establish it.
func (r Runner) Capabilities() Capabilities {
	available, observed := memorySnapshot()
	return Capabilities{HardMemoryLimit: r.CgroupParent != "", MemoryObserved: observed, AvailableMemoryBytes: available}
}

// Deriver permits deterministic session tests without doing KDF work in the host.
// Implementations honor ctx and transfer exclusive ownership of returned bytes,
// including on error; the caller may clear them immediately.
type Deriver interface {
	Derive(context.Context, Request) ([]byte, error)
}
