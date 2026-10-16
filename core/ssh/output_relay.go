package ssh

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"
)

// ConsoleOutputRelay describes a host-owned Windows helper entry point. The
// executable must dispatch Args followed by a private handle specification to
// ServeConsoleOutputRelay before normal application startup. Env is an explicit
// snapshot; core never discovers or dispatches the host executable.
type ConsoleOutputRelay struct {
	Executable string
	Args       []string
	Env        []string
}

type consoleOutputRelayKey struct{}

type consoleRelayBinding interface{ close() error }

// consoleRelayScope is the ownership part of the injected capability, not a
// global process manager. It retains bindings whose local cleanup failed until
// the command owner retries cleanup. No background reaper is started.
type consoleRelayScope struct {
	config  ConsoleOutputRelay
	cancel  context.CancelFunc
	closeMu sync.Mutex
	mu      sync.Mutex
	closed  bool
	owned   map[consoleRelayBinding]struct{}
}

// WithConsoleOutputRelay opts a command into Windows console output and returns
// its cleanup function. The host MUST retain and call cleanup after command I/O
// finishes, including on failure. Cleanup cancels active writes, retries bindings
// that could not be reaped locally, and can itself be retried on error. It never
// closes borrowed console streams. Other platforms ignore the capability.
func WithConsoleOutputRelay(ctx context.Context, relay ConsoleOutputRelay) (context.Context, func() error) {
	relay.Args = slices.Clone(relay.Args)
	relay.Env = slices.Clone(relay.Env)
	work, cancel := context.WithCancel(ctx)
	scope := &consoleRelayScope{config: relay, cancel: cancel, owned: make(map[consoleRelayBinding]struct{})}
	return context.WithValue(work, consoleOutputRelayKey{}, scope), scope.close
}

func (s *consoleRelayScope) add(binding consoleRelayBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	s.owned[binding] = struct{}{}
	return nil
}

func (s *consoleRelayScope) remove(binding consoleRelayBinding) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.owned, binding)
	s.mu.Unlock()
}

func (s *consoleRelayScope) close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.cancel()
	s.mu.Lock()
	s.closed = true
	owned := make([]consoleRelayBinding, 0, len(s.owned))
	for binding := range s.owned {
		owned = append(owned, binding)
	}
	s.mu.Unlock()
	var err error
	// Do not hold the registry lock while closing: a successfully reaped
	// binding removes itself, and its writer may still be joining cancellation.
	for _, binding := range owned {
		err = errors.Join(err, binding.close())
	}
	return err
}
