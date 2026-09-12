// Package credentialfile implements offline encrypted vaults, sessions and maintenance.
// Composition roots inject prompting and explicitly own Runtime cleanup.
package credentialfile

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrUnsupported indicates an unimplemented platform, unavailable filesystem
	// operation or a directory crossing the vault's device/mount boundary.
	ErrUnsupported = errors.New("offline vault platform or required filesystem operation is unsupported")
	// ErrConflict indicates an immutable item already exists with a different value.
	ErrConflict = errors.New("offline credential item conflict")
	// ErrRevisionChanged indicates publication changed while unlocking.
	ErrRevisionChanged = errors.New("offline vault publication changed")
	// ErrMaintenanceRequired indicates unresolved maintenance or temporary state.
	ErrMaintenanceRequired = errors.New("offline vault requires maintenance recovery")
	// ErrKeyUsageExhausted prevents encryption after its durable reservation budget.
	ErrKeyUsageExhausted = errors.New("offline vault key usage exhausted")
	// ErrClosed indicates the file store has been closed.
	ErrClosed = errors.New("offline vault is closed")
	// ErrResourceBusy rejects admission beyond one running and eight queued KDF tasks.
	ErrResourceBusy = errors.New("offline KDF queue is full")
)

// KeySource must authenticate the complete metadata (including its wrapping tag)
// before returning an independently owned 32-byte DEK. The store clears that copy.
// Unlock is called without any vault lock and must honor cancellation/deadlines.
// Nil is fail-closed. Stage C supplies the process-owned session implementation.
type KeySource interface {
	Unlock(ctx context.Context, metadata []byte) ([]byte, error)
}

// PromptProvider owns presentation; returned password bytes transfer to Runtime.
// Implementations must honor cancellation and never log supplied material.
type PromptProvider interface {
	Password(context.Context, string) ([]byte, error)
}

// SessionOptions fixes the policy shared by all handles of one physical vault.
type SessionOptions struct {
	Mode           string
	KeyFile        string
	IdleTTL        time.Duration
	CacheTTL       time.Duration
	PromptTimeout  time.Duration
	UnlockTimeout  time.Duration
	NonInteractive bool
}

// Options configures file operations without introducing terminal interaction.
type Options struct {
	Keys          KeySource
	ReadOnly      bool
	Timeout       time.Duration
	UnlockTimeout time.Duration
}

// DurabilityError preserves publication outcome for the named file operation.
// In particular Op="budget" describes a reservation, not a saved secret.
type DurabilityError struct {
	Op      string
	Applied bool
	Durable bool
	Cause   error
}

func (e *DurabilityError) Error() string {
	return fmt.Sprintf("offline vault %s failed (applied=%t durable=%t): %v", e.Op, e.Applied, e.Durable, e.Cause)
}

// Unwrap preserves cancellation and underlying I/O classifications.
func (e *DurabilityError) Unwrap() error { return e.Cause }
