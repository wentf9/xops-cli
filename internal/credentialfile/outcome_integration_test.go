//go:build integration && linux && amd64

package credentialfile

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestCommittedOutcomeSurvivesCancellation(t *testing.T) {
	for _, mode := range []string{"put", "put-retry", "delete"} {
		t.Run(mode, func(t *testing.T) {
			f := makeFixture(t)
			plain := f.open(t, fileOps{})
			secret := credential.NewSecret([]byte("public-secret"))
			defer secret.Zero()
			if mode != "put" {
				if err := plain.Put(t.Context(), f.ref, secret); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(context.Canceled)
			cause := errors.New("caller canceled after durable commit")
			s := f.open(t, fileOps{after: func(step string) {
				if step == mode+":dir-sync" {
					cancel(cause)
				}
			}})
			var err error
			if mode == "delete" {
				err = s.Delete(ctx, f.ref)
			} else {
				err = s.Put(ctx, f.ref, secret)
			}
			var out *DurabilityError
			if !errors.As(err, &out) || !out.Applied || !out.Durable || !errors.Is(err, cause) {
				t.Fatalf("durable result lost: %v", err)
			}
			want := "put"
			if mode == "delete" {
				want = "delete"
			}
			if out.Op != want {
				t.Fatalf("scope=%s", out.Op)
			}
			got, getErr := plain.Get(t.Context(), f.ref)
			got.Zero()
			if mode == "delete" {
				if !errors.Is(getErr, credential.ErrCredentialNotFound) {
					t.Fatal(getErr)
				}
			} else if getErr != nil {
				t.Fatal(getErr)
			}
		})
	}
}

func TestCommittedOutcomeSurvivesCleanupError(t *testing.T) {
	for _, step := range []string{"put:close", "put-retry:close", "operation:close", "lock:close"} {
		t.Run(step, func(t *testing.T) {
			f := makeFixture(t)
			secret := credential.NewSecret([]byte("public-secret"))
			defer secret.Zero()
			if step == "put-retry:close" {
				s := f.open(t, fileOps{})
				if err := s.Put(t.Context(), f.ref, secret); err != nil {
					t.Fatal(err)
				}
			}
			var committed atomic.Bool
			cause := errors.New("injected cleanup error")
			s := f.open(t, fileOps{
				after: func(name string) {
					if name == "put:dir-sync" || name == "put-retry:dir-sync" {
						committed.Store(true)
					}
				},
				before: func(name string) error {
					if committed.Load() && name == step {
						return cause
					}
					return nil
				},
			})
			err := s.Put(t.Context(), f.ref, secret)
			var out *DurabilityError
			if !errors.As(err, &out) || out.Op != "put" || !out.Applied || !out.Durable || !errors.Is(err, cause) {
				t.Fatalf("cleanup lost outcome: %v", err)
			}
		})
	}
}

func TestBudgetCommitIsNotSecretCommit(t *testing.T) {
	f := makeFixture(t)
	cause := errors.New("budget close failure")
	s := f.open(t, fileOps{before: func(step string) error {
		if step == "budget:close" {
			return cause
		}
		return nil
	}})
	secret := credential.NewSecret([]byte("public-secret"))
	defer secret.Zero()
	err := s.Put(t.Context(), f.ref, secret)
	var out *DurabilityError
	if !errors.As(err, &out) || out.Op != "budget" || !out.Applied || !out.Durable || !errors.Is(err, cause) {
		t.Fatalf("budget scope lost: %v", err)
	}
	if _, err := os.Stat(f.itemPath(t, f.ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("secret was published after reservation error")
	}
	if n := f.budget(t).Consumed; n != 4 {
		t.Fatalf("reservation refunded: %d", n)
	}
}

func TestBudgetCommitSurvivesLaterCancellation(t *testing.T) {
	f := makeFixture(t)
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(context.Canceled)
	cause := errors.New("canceled after durable reservation")
	s := f.open(t, fileOps{after: func(step string) {
		if step == "budget:dir-sync" {
			cancel(cause)
		}
	}})
	secret := credential.NewSecret([]byte("public-secret"))
	defer secret.Zero()
	err := s.Put(ctx, f.ref, secret)
	var out *DurabilityError
	if !errors.As(err, &out) || out.Op != "budget" || !out.Applied || !out.Durable || !errors.Is(err, cause) {
		t.Fatalf("durable reservation lost: %v", err)
	}
	if _, err := os.Stat(f.itemPath(t, f.ref)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("secret published after cancellation")
	}
	if n := f.budget(t).Consumed; n != 4 {
		t.Fatalf("reservation refunded: %d", n)
	}
}
