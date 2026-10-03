package auth

import (
	"context"
	"errors"
)

// RecoverableRead classifies source availability failures for an explicitly
// interactive caller. Invalid references, conflicts and cancellation never
// authorize temporary credential input, even when joined to an availability
// error. This grants no permission to persist a replacement secret.
func RecoverableRead(err error) bool {
	for _, denied := range []error{context.Canceled, context.DeadlineExceeded, ErrConfigConflict, ErrInvalidRef} {
		if errors.Is(err, denied) {
			return false
		}
	}
	for _, allowed := range []error{ErrCredentialNotFound, ErrCredentialStoreLocked, ErrCredentialStoreUnavailable, ErrCredentialAccessDenied, ErrStoreNotFound} {
		if errors.Is(err, allowed) {
			return true
		}
	}
	return false
}
