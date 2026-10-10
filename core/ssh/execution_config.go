package ssh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrExecutionValidation indicates an invalid execution configuration.
var ErrExecutionValidation = errors.New("execution validation error")

// ExecutionConfig specifies the execution environment for commands.
// It can be configured at global, node, playbook settings, or step levels.
type ExecutionConfig struct {
	Interpreter   Interpreter   `yaml:"interpreter,omitempty" json:"interpreter,omitempty"`
	LaunchDialect LaunchDialect `yaml:"launch_dialect,omitempty" json:"launchDialect,omitempty"`
	Login         *bool         `yaml:"login,omitempty" json:"login,omitempty"`
}

// Clone returns a deep copy of ExecutionConfig.
func (e *ExecutionConfig) Clone() *ExecutionConfig {
	if e == nil {
		return nil
	}
	cloned := *e
	if e.Login != nil {
		val := *e.Login
		cloned.Login = &val
	}
	return &cloned
}

// LoginMode returns the effective LoginMode represented by the configuration.
func (e *ExecutionConfig) LoginMode() LoginMode {
	if e == nil || e.Login == nil {
		return LoginInherit
	}
	if *e.Login {
		return LoginEnabled
	}
	return LoginDisabled
}

// EffectiveInterpreter returns the configured interpreter, or the default
// InterpreterBash if unspecified.
func (e *ExecutionConfig) EffectiveInterpreter() Interpreter {
	if e == nil || e.Interpreter == "" {
		return InterpreterBash
	}
	return e.Interpreter
}

// CommandOptions applies P1/P2 caller defaults, then converts execution config.
// Absence retains legacy POSIX Bash+login until P3. An explicit interpreter
// uses its adapter defaults; server never inherits a POSIX launch assumption.
func (e *ExecutionConfig) CommandOptions() CommandOptions {
	if e == nil {
		return CommandOptions{Interpreter: InterpreterBash, LaunchDialect: LaunchPOSIX, Login: LoginEnabled}
	}
	opts := CommandOptions{
		Interpreter:   e.EffectiveInterpreter(),
		LaunchDialect: e.LaunchDialect,
		Login:         e.LoginMode(),
	}
	if e.Interpreter == "" {
		if e.LaunchDialect == "" {
			opts.LaunchDialect = LaunchPOSIX
		}
		if e.Login == nil {
			opts.Login = LoginEnabled
		}
	} else if e.Interpreter == InterpreterServer && e.LaunchDialect == "" {
		opts.LaunchDialect = LaunchUnknown
	}
	return opts
}

// SudoRunOptions rejects unsupported escalation semantics before dispatch and
// maps the validated Bash login mode to the legacy sudo adapter explicitly.
func (e *ExecutionConfig) SudoRunOptions(command string) ([]RunOption, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	opts := e.CommandOptions()
	if opts.Interpreter != InterpreterBash {
		return nil, fmt.Errorf("%w: sudo requires a supported explicit Bash adapter", ErrExecutionValidation)
	}
	plan, err := PlanCommand(command, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: plan sudo command: %w", ErrExecutionValidation, err)
	}
	return []RunOption{WithLoginShell(plan.LoginMode() == LoginEnabled)}, nil
}

// Validate validates that the execution configuration contains supported
// values and mutually compatible settings.
func (e *ExecutionConfig) Validate() error {
	if e == nil {
		return nil
	}
	switch e.Interpreter {
	case "", InterpreterServer, InterpreterBash:
	default:
		return fmt.Errorf("%w: unsupported interpreter %q", ErrExecutionValidation, e.Interpreter)
	}

	switch e.LaunchDialect {
	case "", LaunchPOSIX, LaunchPowerShell, LaunchCmd, LaunchUnknown:
	default:
		return fmt.Errorf("%w: unsupported launch_dialect %q", ErrExecutionValidation, e.LaunchDialect)
	}

	if e.Interpreter == InterpreterServer && e.Login != nil {
		return fmt.Errorf("%w: server interpreter requires inherited login mode", ErrExecutionValidation)
	}

	if e.Interpreter == InterpreterBash && e.LaunchDialect != "" && e.LaunchDialect != LaunchPOSIX {
		return fmt.Errorf("%w: bash interpreter requires posix launch dialect", ErrExecutionValidation)
	}

	return nil
}

// UnmarshalYAML strictly unmarshals and validates an ExecutionConfig from YAML,
// rejecting unknown fields.
func (e *ExecutionConfig) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("%w: expected mapping for execution configuration", ErrExecutionValidation)
	}

	known := map[string]struct{}{
		"interpreter":    {},
		"launch_dialect": {},
		"login":          {},
	}

	for i := 0; i < len(value.Content); i += 2 {
		field := value.Content[i].Value
		if _, ok := known[field]; !ok {
			return fmt.Errorf("%w: unknown field %q in execution configuration", ErrExecutionValidation, field)
		}
	}

	type rawExecution struct {
		Interpreter   Interpreter   `yaml:"interpreter"`
		LaunchDialect LaunchDialect `yaml:"launch_dialect"`
		Login         *bool         `yaml:"login"`
	}

	var raw rawExecution
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("%w: decode execution configuration: %w", ErrExecutionValidation, err)
	}

	e.Interpreter = raw.Interpreter
	e.LaunchDialect = raw.LaunchDialect
	e.Login = raw.Login

	return e.Validate()
}

// MarshalJSON serializes ExecutionConfig using camelCase launchDialect.
func (e ExecutionConfig) MarshalJSON() ([]byte, error) {
	type wire struct {
		Interpreter   Interpreter   `json:"interpreter,omitempty"`
		LaunchDialect LaunchDialect `json:"launchDialect,omitempty"`
		Login         *bool         `json:"login,omitempty"`
	}
	return json.Marshal(wire(e))
}

// UnmarshalJSON strictly unmarshals and validates an ExecutionConfig from JSON,
// supporting both launchDialect and launch_dialect, and login as bool or string.
func (e *ExecutionConfig) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("%w: decode execution json: %w", ErrExecutionValidation, err)
	}

	known := map[string]struct{}{
		"interpreter":    {},
		"launchDialect":  {},
		"launch_dialect": {},
		"login":          {},
	}

	for k := range raw {
		if _, ok := known[k]; !ok {
			return fmt.Errorf("%w: unknown field %q in execution configuration", ErrExecutionValidation, k)
		}
	}

	if msg, ok := raw["interpreter"]; ok {
		var interp Interpreter
		if err := json.Unmarshal(msg, &interp); err != nil {
			return fmt.Errorf("%w: decode interpreter: %w", ErrExecutionValidation, err)
		}
		e.Interpreter = interp
	}

	var dialectMsg json.RawMessage
	if msg, ok := raw["launchDialect"]; ok {
		dialectMsg = msg
	}
	if msg, ok := raw["launch_dialect"]; ok {
		if dialectMsg != nil && !bytes.Equal(dialectMsg, msg) {
			return fmt.Errorf("%w: conflicting launchDialect and launch_dialect values", ErrExecutionValidation)
		}
		dialectMsg = msg
	}
	if dialectMsg != nil {
		var d LaunchDialect
		if err := json.Unmarshal(dialectMsg, &d); err != nil {
			return fmt.Errorf("%w: decode launch_dialect: %w", ErrExecutionValidation, err)
		}
		e.LaunchDialect = d
	}

	if msg, ok := raw["login"]; ok {
		login, err := unmarshalLoginJSON(msg)
		if err != nil {
			return err
		}
		e.Login = login
	}

	return e.Validate()
}

func unmarshalLoginJSON(msg json.RawMessage) (*bool, error) {
	if len(msg) == 0 || bytes.Equal(bytes.TrimSpace(msg), []byte("null")) {
		return nil, nil
	}
	var b bool
	if err := json.Unmarshal(msg, &b); err == nil {
		return &b, nil
	}
	var s string
	if err := json.Unmarshal(msg, &s); err != nil {
		return nil, fmt.Errorf("%w: login must be boolean, string (enabled/disabled/inherit), or null", ErrExecutionValidation)
	}
	switch strings.ToLower(s) {
	case "enabled":
		val := true
		return &val, nil
	case "disabled":
		val := false
		return &val, nil
	case "inherit":
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: invalid login mode %q (must be enabled, disabled, or inherit)", ErrExecutionValidation, s)
	}
}

// ResolveExecution merges a child (higher priority) execution config with a
// parent (lower priority) execution config according to the inheritance rules:
//   - launch_dialect inherits from parent unless explicitly overridden by child.
//   - If child overrides interpreter to a different non-empty interpreter,
//     parent's login option is NOT inherited (child's login applies, or nil).
//   - If child does not override interpreter, parent's interpreter is inherited,
//     and login inherits from parent unless child explicitly sets it.
//   - Explicit incompatible combinations fail validation.
func ResolveExecution(child, parent *ExecutionConfig) (*ExecutionConfig, error) {
	if child == nil && parent == nil {
		return nil, nil
	}
	if child == nil {
		if err := parent.Validate(); err != nil {
			return nil, err
		}
		return parent.Clone(), nil
	}
	if parent == nil {
		if err := child.Validate(); err != nil {
			return nil, err
		}
		return child.Clone(), nil
	}

	if err := child.Validate(); err != nil {
		return nil, err
	}
	if err := parent.Validate(); err != nil {
		return nil, err
	}

	res := &ExecutionConfig{}

	// launch_dialect inherits from parent unless child explicitly sets it
	if child.LaunchDialect != "" {
		res.LaunchDialect = child.LaunchDialect
	} else {
		res.LaunchDialect = parent.LaunchDialect
	}

	// interpreter & login:
	if child.Interpreter != "" {
		res.Interpreter = child.Interpreter
		if child.EffectiveInterpreter() != parent.EffectiveInterpreter() {
			// Changed interpreter (accounting for implicit default Bash): do not inherit parent's login!
			if child.Login != nil {
				val := *child.Login
				res.Login = &val
			}
		} else {
			// Same interpreter:
			if child.Login != nil {
				val := *child.Login
				res.Login = &val
			} else if parent.Login != nil {
				val := *parent.Login
				res.Login = &val
			}
		}
	} else {
		// Child did not specify interpreter: inherit parent's interpreter
		res.Interpreter = parent.Interpreter
		if child.Login != nil {
			val := *child.Login
			res.Login = &val
		} else if parent.Login != nil {
			val := *parent.Login
			res.Login = &val
		}
	}

	if err := res.Validate(); err != nil {
		return nil, err
	}

	return res, nil
}

// EffectiveExecution resolves a hierarchy of execution configs from highest
// priority to lowest priority (e.g. step, settings, node, global).
func EffectiveExecution(layers ...*ExecutionConfig) (*ExecutionConfig, error) {
	var effective *ExecutionConfig
	for i := len(layers) - 1; i >= 0; i-- {
		var err error
		effective, err = ResolveExecution(layers[i], effective)
		if err != nil {
			return nil, err
		}
	}
	return effective, nil
}
