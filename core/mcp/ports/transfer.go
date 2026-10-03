package ports

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"

	"github.com/wentf9/xops-cli/core/mcp/remotefile"
)

// GuardTransfer takes ownership of remote, including on validation failure.
// The caller owns permits; replacing a permit never closes the transport.
func GuardTransfer(lifetime context.Context, remote remotefile.Remote, permit Permit) (TransferSession, error) {
	if Nil(remote) {
		return nil, errors.New("transfer remote is required")
	}
	if lifetime == nil || Nil(permit) {
		return nil, errors.Join(errors.New("transfer lifetime and permit are required"), remote.Close())
	}
	_, stop, err := WorkContext(lifetime, permit, TransferStart, Commit, Recovery)
	if err != nil {
		return nil, errors.Join(err, remote.Close())
	}
	stop()
	ctx, cancel := context.WithCancel(lifetime)
	return &guardedTransfer{remote: remote, permit: permit, ctx: ctx, cancel: cancel}, nil
}

type guardedTransfer struct {
	mu       sync.Mutex
	remote   remotefile.Remote
	permit   Permit
	ctx      context.Context
	cancel   context.CancelFunc
	closed   bool
	closeErr error
}

func (s *guardedTransfer) Close() error {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.closeErr = s.remote.Close()
	}
	return s.closeErr
}

func (s *guardedTransfer) ReserveCommit(ctx context.Context, permit Permit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return errors.New("transfer session is closed")
	}
	if Nil(permit) || s.permit.Phase() != TransferStart || permit.Binding() != s.permit.Binding() {
		return ErrPurpose
	}
	work, cancel, err := WorkContext(ctx, permit, Commit)
	if err != nil {
		return err
	}
	defer cancel()
	if err := work.Err(); err != nil {
		return err
	}
	// The gate ordered this reservation before a possible streaming revocation.
	// Do not recheck the old permit: it may now be cancelled by publication.
	s.permit = permit
	return nil
}

func transferWork[T any](s *guardedTransfer, ctx context.Context, phases []Phase, call func(context.Context) (T, error)) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var zero T
	if s.closed || s.ctx.Err() != nil {
		return zero, errors.New("transfer session is closed")
	}
	if !slices.Contains(phases, s.permit.Phase()) {
		return zero, ErrPurpose
	}
	work, cancel, err := WorkContext(ctx, s.permit, phases...)
	if err != nil {
		return zero, err
	}
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	if s.ctx.Err() != nil {
		cancel()
	}
	return call(work)
}

func (s *guardedTransfer) Inspect(ctx context.Context, path string, upload, overwrite bool) (remotefile.Metadata, error) {
	return transferWork(s, ctx, []Phase{TransferStart, Recovery}, func(ctx context.Context) (remotefile.Metadata, error) {
		return s.remote.Inspect(ctx, path, upload, overwrite)
	})
}
func (s *guardedTransfer) Upload(ctx context.Context, path string, source io.Reader, size int64, confirm func() error, progress func(int64) error) (remotefile.StreamResult, error) {
	return transferWork(s, ctx, []Phase{TransferStart}, func(ctx context.Context) (remotefile.StreamResult, error) {
		return s.remote.Upload(ctx, path, source, size, confirm, progress)
	})
}
func (s *guardedTransfer) Download(ctx context.Context, metadata remotefile.Metadata, destination io.Writer, progress func(int64) error) (remotefile.StreamResult, error) {
	return transferWork(s, ctx, []Phase{TransferStart, Recovery}, func(ctx context.Context) (remotefile.StreamResult, error) {
		return s.remote.Download(ctx, metadata, destination, progress)
	})
}
func (s *guardedTransfer) Commit(ctx context.Context, temporary, destination string, overwrite bool) (remotefile.CommitResult, error) {
	return transferWork(s, ctx, []Phase{Commit}, func(ctx context.Context) (remotefile.CommitResult, error) {
		return s.remote.Commit(ctx, temporary, destination, overwrite)
	})
}
func (s *guardedTransfer) Remove(ctx context.Context, path string) error {
	_, err := transferWork(s, ctx, []Phase{Recovery}, func(ctx context.Context) (struct{}, error) { return struct{}{}, s.remote.Remove(ctx, path) })
	return err
}
