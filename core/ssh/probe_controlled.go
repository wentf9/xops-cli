package ssh

import (
	"context"
	"fmt"
	"slices"
)

// NeedsExecutionProbe identifies an unspecified interpreter and unknown outer
// dialect. Explicit interpreter choices, including server, are never replaced.
func NeedsExecutionProbe(execution *ExecutionConfig) bool {
	return execution == nil || (execution.Interpreter == "" &&
		(execution.LaunchDialect == "" || execution.LaunchDialect == LaunchUnknown) && execution.Login == nil)
}

// ProbeControlledExecution resolves a missing adapter for a restricted operation.
// Call only before script/ensure/cwd validation, never after a user command has
// started. Results share the Client's bounded probe cache; neither live command
// defaults nor disk configuration are changed. Consumers must still validate
// whether their operation supports the detected adapter.
func (c *Client) ProbeControlledExecution(ctx context.Context, execution *ExecutionConfig) (*ExecutionConfig, error) {
	if err := execution.Validate(); err != nil {
		return nil, err
	}
	if !NeedsExecutionProbe(execution) {
		return execution.Clone(), nil
	}
	result, err := c.ProbeExecutionConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("probe controlled execution: %w", err)
	}
	resolved := result.SuggestedConfig.Clone()
	// Ordinary CMD recommendations preserve server passthrough. Restricted
	// operations need an actual adapter, so prefer installed PowerShell here.
	if resolved.Interpreter == InterpreterServer && resolved.LaunchDialect == LaunchCmd {
		for _, interpreter := range []Interpreter{InterpreterPowerShell, InterpreterPwsh, InterpreterCmd} {
			if slices.Contains(result.AvailableInterpreters, interpreter) {
				resolved.Interpreter = interpreter
				break
			}
		}
	}
	if err := resolved.Validate(); err != nil {
		return nil, err
	}
	return resolved, nil
}

// DeriveWorkingDirectoryExecution returns a derived ExecutionConfig when an explicit
// server interpreter has a known launch dialect that can safely execute cd.
func DeriveWorkingDirectoryExecution(execution *ExecutionConfig) (*ExecutionConfig, bool) {
	if execution == nil || execution.EffectiveInterpreter() != InterpreterServer {
		return nil, false
	}
	switch execution.LaunchDialect {
	case LaunchCmd:
		resolved := execution.Clone()
		resolved.Interpreter = InterpreterCmd
		return resolved, true
	default:
		return nil, false
	}
}

// ResolveWorkingDirectoryExecution selects an adapter for one cwd-aware command.
// A known server/cmd configuration has native CMD semantics, so CMD can apply
// the directory without changing command language. Keep this derived adapter
// session-local; unspecified configurations still use the bounded probe.
func (c *Client) ResolveWorkingDirectoryExecution(ctx context.Context, execution *ExecutionConfig) (*ExecutionConfig, error) {
	if derived, ok := DeriveWorkingDirectoryExecution(execution); ok {
		if err := derived.Validate(); err != nil {
			return nil, err
		}
		return derived, nil
	}
	return c.ProbeControlledExecution(ctx, execution)
}

// CachedExecutionProbe returns an already completed diagnostic snapshot without
// starting or waiting for network work. A failed or running probe returns false.
func (c *Client) CachedExecutionProbe() (*ProbeResult, bool) {
	if c == nil {
		return nil, false
	}
	cache := c.executionProbeCache()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	attempt := cache.attempt
	if attempt == nil {
		return nil, false
	}
	select {
	case <-attempt.done:
		if attempt.err != nil {
			return nil, false
		}
		return attempt.result.clone(), true
	default:
		return nil, false
	}
}
