// Package auth defines storage-independent authentication failures.
package auth

import "errors"

var (
	// ErrCredentialNotFound identifies the corresponding authentication-source failure.
	ErrCredentialNotFound = errors.New("credential not found")
	// ErrCredentialStoreLocked identifies the corresponding authentication-source failure.
	ErrCredentialStoreLocked = errors.New("credential store is locked")
	// ErrCredentialStoreUnavailable identifies the corresponding authentication-source failure.
	ErrCredentialStoreUnavailable = errors.New("credential store is unavailable")
	// ErrCredentialAccessDenied identifies the corresponding authentication-source failure.
	ErrCredentialAccessDenied = errors.New("credential access denied")
	// ErrConfigConflict identifies the corresponding authentication-source failure.
	ErrConfigConflict = errors.New("configuration conflict")
	// ErrInvalidRef identifies the corresponding authentication-source failure.
	ErrInvalidRef = errors.New("invalid credential reference")
	// ErrStoreNotFound identifies the corresponding authentication-source failure.
	ErrStoreNotFound = errors.New("credential store not found")

	// ErrProxyCycle identifies a cycle in a resolved jump-host plan.
	ErrProxyCycle = errors.New("proxy jump cycle detected")
)
