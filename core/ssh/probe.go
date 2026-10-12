package ssh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrExecutionProbe identifies an inconclusive or failed execution probe.
var ErrExecutionProbe = errors.New("SSH execution probe failed")

type executionProbeCache struct {
	mu     sync.Mutex
	done   chan struct{}
	result *ProbeResult
	err    error
}

func (c *Client) executionProbeCache() *executionProbeCache {
	c.probeMu.Lock()
	defer c.probeMu.Unlock()
	if c.probeCache == nil {
		c.probeCache = &executionProbeCache{}
	}
	return c.probeCache
}

const (
	probeCommandTimeout = 5 * time.Second
	// Reserve one second for ExecuteCommand's bounded channel shutdown.
	probeWorkTimeout = 12 * time.Second
	probeOutputLimit = 16 << 10

	// The POSIX if/then grammar is intentional: PowerShell 7 can also parse
	// command substitution and ||, and can invoke an external printf on Unix.
	probePOSIX = `if :; then printf '__XOPS_DIALECT_POSIX__:%s:%s\n' "$(uname -s 2>/dev/null || echo UNAME_FAIL)" "$SHELL"; fi`
	// Probe the outer shell itself: invoking cmd.exe under PowerShell would
	// otherwise incorrectly identify a PowerShell DefaultShell as CMD.
	probeCmd               = `echo __XOPS_DIALECT_CMD__:%COMSPEC%`
	probePowerShell        = `Write-Output ('__XOPS_DIALECT_POWERSHELL__:' + $PSVersionTable.PSVersion.ToString()); Write-Output ('__XOPS_PLATFORM__:' + [Environment]::OSVersion.Platform)`
	probePOSIXInterpreters = `for i in bash sh powershell pwsh cmd; do if command -v "$i" >/dev/null 2>&1; then printf '__XOPS_INTERP__:%s\n' "$i"; fi; done; printf '__XOPS_INTERP_END__\n'`
	// Optional failed lookups must not become the enumeration's exit status.
	// Parenthesize the end echo so the separator adds no trailing frame space.
	probeCmdInterpreters = `where bash.exe >nul 2>&1 && (echo __XOPS_INTERP__:bash) & where sh.exe >nul 2>&1 && (echo __XOPS_INTERP__:sh) & where powershell.exe >nul 2>&1 && (echo __XOPS_INTERP__:powershell) & where pwsh.exe >nul 2>&1 && (echo __XOPS_INTERP__:pwsh) & (echo __XOPS_INTERP__:cmd) & (echo __XOPS_INTERP_END__) & exit /b 0`
	// Use the native outer PowerShell so pwsh-only servers do not require
	// powershell.exe merely to enumerate their installed interpreters.
	probePowerShellInterpreters = `foreach ($i in @('bash','sh','powershell','pwsh','cmd')) { if (Get-Command $i -CommandType Application -ErrorAction SilentlyContinue) { Write-Output ('__XOPS_INTERP__:' + $i) } }; Write-Output '__XOPS_INTERP_END__'`
)

// ProbeResult is a diagnostic snapshot. SuggestedConfig is safe to persist only
// when ProbeExecutionConfig returns no error. Unknown results preserve server
// passthrough semantics. Banner and shell path are metadata, never commands.
type ProbeResult struct {
	DetectedDialect        LaunchDialect   `json:"detectedDialect" yaml:"detected_dialect"`
	AvailableInterpreters  []Interpreter   `json:"availableInterpreters" yaml:"available_interpreters"`
	RecommendedInterpreter Interpreter     `json:"recommendedInterpreter" yaml:"recommended_interpreter"`
	SuggestedConfig        ExecutionConfig `json:"suggestedConfig" yaml:"suggested_config"`
	RemoteOS               string          `json:"remoteOS" yaml:"remote_os"`
	RemoteShellPath        string          `json:"remoteShellPath" yaml:"remote_shell_path"`
	ServerVersion          string          `json:"serverVersion" yaml:"server_version"`
	Duration               time.Duration   `json:"duration" yaml:"duration"`
	ProbedAt               time.Time       `json:"probedAt" yaml:"probed_at"`
}

func (r *ProbeResult) clone() *ProbeResult {
	if r == nil {
		return nil
	}
	copy := *r
	copy.AvailableInterpreters = slices.Clone(r.AvailableInterpreters)
	copy.SuggestedConfig = *r.SuggestedConfig.Clone()
	return &copy
}

// ProbeExecutionConfig performs one read-only, bounded two-stage probe per
// authenticated SSH connection lifetime (including pooled wrappers). Callers share that attempt; each
// waiter can cancel independently. Failures are cached as well, preventing
// repeated probes of restricted servers. The initiating caller owns the probe
// context; its cancellation is cached. Returned snapshots can be mutated safely.
// This method neither changes Execution() nor writes configuration or retries
// user commands. A new connection is required to retry an inconclusive probe.
func (c *Client) ProbeExecutionConfig(ctx context.Context) (*ProbeResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is nil", ErrExecutionProbe)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExecutionProbe, err)
	}
	if c == nil || c.sshClient == nil {
		return nil, fmt.Errorf("%w: SSH client is not connected", ErrExecutionProbe)
	}
	cache := c.executionProbeCache()
	cache.mu.Lock()
	if done := cache.done; done != nil {
		cache.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: wait for cached result: %w", ErrExecutionProbe, ctx.Err())
		case <-done:
			cache.mu.Lock()
			defer cache.mu.Unlock()
			return cache.result.clone(), cache.err
		}
	}
	cache.done = make(chan struct{})
	cache.mu.Unlock()

	result, err := c.probeExecution(ctx)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.result, cache.err = result, err
	close(cache.done)
	return result.clone(), err
}

func (c *Client) probeExecution(ctx context.Context) (*ProbeResult, error) {
	started := time.Now()
	result := &ProbeResult{
		DetectedDialect: LaunchUnknown, RecommendedInterpreter: InterpreterServer,
		SuggestedConfig: ExecutionConfig{Interpreter: InterpreterServer, LaunchDialect: LaunchUnknown},
		ServerVersion:   string(c.sshClient.ServerVersion()), ProbedAt: started.UTC(),
	}
	defer func() { result.Duration = time.Since(started) }()
	work, cancel := context.WithTimeout(ctx, probeWorkTimeout)
	defer cancel()
	if err := c.detectProbeDialect(work, result); err != nil {
		return result, fmt.Errorf("%w: detect launch dialect: %w", ErrExecutionProbe, err)
	}
	command, err := probeInterpreterCommand(result.DetectedDialect)
	if err != nil {
		return result, err
	}
	output, err := c.executeProbeCommand(work, command)
	if err != nil {
		return result, fmt.Errorf("%w: enumerate interpreters: %w", ErrExecutionProbe, err)
	}
	interpreters, err := parseProbeInterpreters(output)
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrExecutionProbe, err)
	}
	result.AvailableInterpreters = interpreters
	result.SuggestedConfig = recommendProbeExecution(result.DetectedDialect, interpreters)
	result.RecommendedInterpreter = result.SuggestedConfig.Interpreter
	if err := result.SuggestedConfig.Validate(); err != nil {
		return result, fmt.Errorf("%w: validate recommendation: %w", ErrExecutionProbe, err)
	}
	if result.RecommendedInterpreter == InterpreterServer && result.DetectedDialect != LaunchCmd {
		return result, fmt.Errorf("%w: no supported interpreter found", ErrExecutionProbe)
	}
	return result, nil
}

func (c *Client) executeProbeCommand(ctx context.Context, command string) (string, error) {
	plan, err := PlanCommand(command, CommandOptions{Timeout: probeCommandTimeout, OutputLimit: probeOutputLimit})
	if err != nil {
		return "", fmt.Errorf("plan probe command: %w", err)
	}
	result := c.ExecuteCommand(ctx, plan)
	if err := result.Err(); err != nil {
		return "", fmt.Errorf("execute probe command: %w", err)
	}
	if result.Truncated {
		return "", fmt.Errorf("probe output exceeds %d bytes", probeOutputLimit)
	}
	return result.Output, nil
}

func (c *Client) detectProbeDialect(ctx context.Context, result *ProbeResult) error {
	commands := []string{probePOSIX, probeCmd, probePowerShell}
	if strings.Contains(result.ServerVersion, "OpenSSH_for_Windows") || strings.Contains(result.ServerVersion, "Microsoft:Windows") {
		commands = []string{probeCmd, probePowerShell, probePOSIX}
	}
	var failures []error
	for _, command := range commands {
		output, err := c.executeProbeCommand(ctx, command)
		if err != nil {
			// A syntax error is expected for nonmatching shells. Transport,
			// cancellation, protocol and cleanup errors must stop the probe.
			var exit *CommandExitError
			if !errors.As(err, &exit) || exit.ExitCode == nil || !onlyProbeExitError(err) {
				return err
			}
			failures = append(failures, err)
			continue
		}
		dialect, remoteOS, shell := parseProbeDialect(output, command)
		if dialect != LaunchUnknown {
			result.DetectedDialect, result.RemoteOS, result.RemoteShellPath = dialect, remoteOS, shell
			return nil
		}
	}
	return errors.Join(append(failures, errors.New("no valid launch dialect frame"))...)
}

func onlyProbeExitError(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if !onlyProbeExitError(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyProbeExitError(wrapped.Unwrap())
	}
	var exit *CommandExitError
	return errors.As(err, &exit)
}

func probeFrame(output, prefix string) (string, bool) {
	var frame string
	found := false
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if value, ok := strings.CutPrefix(line, prefix); ok {
			if found || len(value) > 1024 || strings.ContainsAny(value, "\x00\r") {
				return "", false
			}
			frame, found = value, true
		}
	}
	return frame, found
}

func parseProbeDialect(output, command string) (LaunchDialect, string, string) {
	switch command {
	case probePOSIX:
		if frame, ok := probeFrame(output, "__XOPS_DIALECT_POSIX__:"); ok {
			remoteOS, shell, valid := strings.Cut(frame, ":")
			if valid && remoteOS != "" && (shell == "" || strings.HasPrefix(shell, "/")) {
				return LaunchPOSIX, remoteOS, shell
			}
		}
	case probeCmd:
		if frame, ok := probeFrame(output, "__XOPS_DIALECT_CMD__:"); ok {
			if len(frame) > 3 && frame[1] == ':' && (frame[2] == '\\' || frame[2] == '/') && strings.HasSuffix(strings.ToLower(frame), "cmd.exe") {
				return LaunchCmd, "Windows_NT", frame
			}
		}
	case probePowerShell:
		if frame, ok := probeFrame(output, "__XOPS_DIALECT_POWERSHELL__:"); ok && validProbeVersion(frame) {
			// Use the explicit platform query, never the language version, to
			// distinguish Windows PowerShell Core from Unix DefaultShells.
			remoteOS := ""
			if platform, found := probeFrame(output, "__XOPS_PLATFORM__:"); found {
				remoteOS = map[string]string{"Win32NT": "Windows_NT", "Unix": "Unix", "MacOSX": "Darwin"}[platform]
			}
			return LaunchPowerShell, remoteOS, ""
		}
	}
	return LaunchUnknown, "", ""
}

func validProbeVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "+") {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func probeInterpreterCommand(dialect LaunchDialect) (string, error) {
	switch dialect {
	case LaunchPOSIX:
		return shCommandPayload(probePOSIXInterpreters), nil
	case LaunchCmd:
		return cmdCommandPayload(probeCmdInterpreters, dialect)
	case LaunchPowerShell:
		return probePowerShellInterpreters, nil
	default:
		return "", fmt.Errorf("%w: cannot enumerate unknown launch dialect", ErrExecutionProbe)
	}
}

func parseProbeInterpreters(output string) ([]Interpreter, error) {
	var interpreters []Interpreter
	ended := false
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "__XOPS_INTERP_END__" {
			if ended {
				return nil, errors.New("duplicate interpreter end frame")
			}
			ended = true
			continue
		}
		if value, ok := strings.CutPrefix(line, "__XOPS_INTERP__:"); ok {
			interpreter := Interpreter(value)
			if ended || !slices.Contains([]Interpreter{InterpreterBash, InterpreterSh, InterpreterPowerShell, InterpreterPwsh, InterpreterCmd}, interpreter) || slices.Contains(interpreters, interpreter) {
				return nil, errors.New("invalid or duplicate interpreter frame")
			}
			interpreters = append(interpreters, interpreter)
		}
	}
	if !ended {
		return nil, errors.New("missing interpreter end frame")
	}
	return interpreters, nil
}

func recommendProbeExecution(dialect LaunchDialect, available []Interpreter) ExecutionConfig {
	config := ExecutionConfig{Interpreter: InterpreterServer, LaunchDialect: dialect}
	switch dialect {
	case LaunchPOSIX:
		for _, interpreter := range []Interpreter{InterpreterBash, InterpreterSh} {
			if slices.Contains(available, interpreter) {
				login := false
				config.Interpreter, config.Login = interpreter, &login
				break
			}
		}
	case LaunchCmd:
		if !slices.Contains(available, InterpreterPowerShell) && slices.Contains(available, InterpreterCmd) {
			config.Interpreter = InterpreterCmd
		}
	case LaunchPowerShell:
		for _, interpreter := range []Interpreter{InterpreterPowerShell, InterpreterPwsh} {
			if slices.Contains(available, interpreter) {
				config.Interpreter = interpreter
				break
			}
		}
	}
	return config
}
