package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestRecoveryDenialTakesPrecedence(t *testing.T) {
	for _, denied := range []error{context.Canceled, context.DeadlineExceeded, ErrConfigConflict, ErrInvalidRef} {
		if RecoverableRead(errors.Join(ErrCredentialStoreUnavailable, denied)) {
			t.Errorf("joined %v authorized recovery", denied)
		}
	}
	if !RecoverableRead(fmt.Errorf("read backing store: %w", ErrCredentialStoreUnavailable)) {
		t.Fatal("wrapped source availability failure lost recovery classification")
	}
	if RecoverableRead(errors.New("unclassified failure")) || RecoverableRead(nil) {
		t.Fatal("unknown error authorized recovery")
	}
}
