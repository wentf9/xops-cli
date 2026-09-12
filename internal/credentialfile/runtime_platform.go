//go:build (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/internal/kdfhelper"
)

// Runtime owns process-local sessions, KDF admission and all opened Store handles.
// A composition root must share one Runtime and wait for Close before exiting.
type Runtime struct {
	ctx        context.Context
	cancel     context.CancelCauseFunc
	prompt     PromptProvider
	derive     kdfhelper.Deriver
	mu         sync.Mutex
	closed     bool
	done       chan struct{}
	err        error
	sessions   map[fileID]*session
	stores     []*Store
	queueMu    sync.Mutex
	admitted   int
	worker     chan struct{}
	promptGate chan struct{}
	opening    sync.WaitGroup
	openFile   func(context.Context, context.Context, string, string, Options) (*Store, error)
}

// NewRuntime defaults to the current-binary process runner; nil prompt fails closed.
func NewRuntime(ctx context.Context, prompt PromptProvider, derive kdfhelper.Deriver) *Runtime {
	life, cancel := context.WithCancelCause(ctx)
	if derive == nil {
		derive = kdfhelper.Runner{}
	}
	return &Runtime{ctx: life, cancel: cancel, prompt: prompt, derive: derive, done: make(chan struct{}), sessions: make(map[fileID]*session), worker: make(chan struct{}, 1), promptGate: make(chan struct{}, 1), openFile: openRuntimeFile}
}

func openRuntimeFile(ctx, lifetime context.Context, path, id string, o Options) (*Store, error) {
	return openStoreWithLifetime(ctx, lifetime, path, id, o, fileOps{})
}

func (r *Runtime) beginOpen(ctx context.Context) (context.Context, func(), error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, nil, ErrClosed
	}
	r.opening.Add(1)
	r.mu.Unlock()
	work, cancel := context.WithCancelCause(ctx)
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(r.ctx, func() { defer close(callbackDone); cancel(context.Cause(r.ctx)) })
	finish := func() {
		if !stop() {
			<-callbackDone
		}
		cancel(context.Canceled)
		r.opening.Done()
	}
	if err := context.Cause(r.ctx); err != nil {
		finish()
		return nil, nil, err
	}
	if err := context.Cause(work); err != nil {
		finish()
		return nil, nil, err
	}
	return work, finish, nil
}

func normalizeSession(o SessionOptions) (SessionOptions, error) {
	if o.Mode != "prompt" && o.Mode != "key-file" {
		return o, fmt.Errorf("invalid vault unlock mode")
	}
	if (o.Mode == "key-file") != (o.KeyFile != "") {
		return o, fmt.Errorf("key_file must match unlock mode")
	}
	if o.KeyFile != "" && (!filepath.IsAbs(o.KeyFile) || filepath.Clean(o.KeyFile) != o.KeyFile) {
		return o, fmt.Errorf("key_file must be a clean absolute path")
	}
	if o.IdleTTL < 0 || o.IdleTTL > 30*time.Minute || o.CacheTTL < 0 || o.PromptTimeout < 0 || o.UnlockTimeout < 0 {
		return o, fmt.Errorf("invalid session duration")
	}
	if o.IdleTTL == 0 {
		o.IdleTTL = 5 * time.Minute
	}
	if o.PromptTimeout == 0 {
		o.PromptTimeout = 2 * time.Minute
	}
	if o.UnlockTimeout == 0 {
		o.UnlockTimeout = 30 * time.Second
	}
	return o, nil
}

// OpenStore joins the physical vault session without holding Runtime's map lock over I/O.
func (r *Runtime) OpenStore(ctx context.Context, path, id string, options Options, sessionOptions SessionOptions) (*Store, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	o, err := normalizeSession(sessionOptions)
	if err != nil {
		return nil, err
	}
	work, finish, err := r.beginOpen(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	s, err := r.openFile(work, r.ctx, path, id, options)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.closed {
		err = ErrClosed
	} else if cause := context.Cause(work); cause != nil {
		err = cause
	} else if cause := context.Cause(r.ctx); cause != nil {
		err = cause
	} else {
		shared := r.sessions[s.root.id]
		if shared != nil && (shared.options != o || shared.storeID != id) {
			err = ErrConflict
		} else {
			if shared == nil {
				shared = newSession(r, id, o)
				r.sessions[s.root.id] = shared
			}
			s.session = shared
			r.stores = append(r.stores, s)
		}
	}
	r.mu.Unlock()
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

// Close cancels all tasks and leases and waits for files, timers and workers.
func (r *Runtime) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		<-r.done
		return r.err
	}
	r.closed = true
	r.cancel(ErrClosed)
	stores := append([]*Store(nil), r.stores...)
	sessions := make([]*session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	for _, s := range sessions {
		s.requestLock()
	}
	for _, s := range stores {
		r.err = errors.Join(r.err, s.Close())
	}
	r.opening.Wait()
	for _, s := range sessions {
		<-s.done
	}
	close(r.done)
	return r.err
}

func (r *Runtime) deriveKey(ctx context.Context, req kdfhelper.Request) ([]byte, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	r.queueMu.Lock()
	if r.admitted >= 9 {
		r.queueMu.Unlock()
		return nil, ErrResourceBusy
	}
	r.admitted++
	r.queueMu.Unlock()
	defer func() { r.queueMu.Lock(); r.admitted--; r.queueMu.Unlock() }()
	select {
	case r.worker <- struct{}{}:
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
	defer func() { <-r.worker }()
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	key, err := r.derive.Derive(ctx, req)
	if cause := context.Cause(ctx); cause != nil {
		err = errors.Join(err, cause)
	}
	if err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}

// Lock waits for this Store's shared session to revoke and reap all live leases.
// A canceled wait does not claim completion; Runtime still owns ongoing cleanup.
func (s *Store) Lock(ctx context.Context) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	if s.session == nil {
		return ErrUnsupported
	}
	done := s.session.requestLock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// Unlock explicitly unlocks this process's session without returning any secret.
// It does not create an IPC service or unlock another process.
func (s *Store) Unlock(ctx context.Context) (err error) {
	if s.session == nil {
		return ErrUnsupported
	}
	ctx, finish, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	p, err := s.snapshot(ctx)
	if err != nil {
		return err
	}
	lease, err := s.session.acquire(ctx, p.data)
	if err != nil {
		return err
	}
	defer lease.release()
	work, cancel := context.WithTimeout(lease.ctx, s.options.Timeout)
	defer cancel()
	lock, err := s.lock(work, false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.close()) }()
	current, err := s.publication(work)
	if err != nil {
		return err
	}
	if current.current != p.current {
		return ErrRevisionChanged
	}
	return lease.deliver(work)
}
