package ssh

import (
	"bytes"
	"fmt"
	"strings"
)

// ShebangInfo describes the result of parsing a script's shebang line.
type ShebangInfo struct {
	HasShebang  bool
	HasBOM      bool
	Supported   bool
	Interpreter Interpreter
	Dialect     LaunchDialect
	RawLine     string
}

// ParseShebang inspects the first line of script data and validates it against
// the supported shebang allowlist (sh and bash paths or /usr/bin/env sh|bash
// without additional arguments). Trailing CR is ignored for metadata parsing.
func ParseShebang(data []byte) ShebangInfo {
	if len(data) == 0 {
		return ShebangInfo{}
	}
	hasBOM := bytes.HasPrefix(data, []byte("\xef\xbb\xbf"))
	firstLine := data
	if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
		firstLine = data[:idx]
	}
	trimmed := strings.TrimRight(string(firstLine), "\r \t")
	if !strings.HasPrefix(trimmed, "#!") {
		return ShebangInfo{HasBOM: hasBOM}
	}
	body := strings.TrimSpace(trimmed[2:])
	info := ShebangInfo{
		HasShebang: true,
		HasBOM:     hasBOM,
		RawLine:    trimmed,
	}
	switch body {
	case "sh", "/bin/sh", "/usr/bin/sh", "/bin/env sh", "/usr/bin/env sh":
		info.Supported = true
		info.Interpreter = InterpreterSh
		info.Dialect = LaunchPOSIX
	case "bash", "/bin/bash", "/usr/bin/bash", "/bin/env bash", "/usr/bin/env bash":
		info.Supported = true
		info.Interpreter = InterpreterBash
		info.Dialect = LaunchPOSIX
	default:
		// Unsupported shebang (e.g. has flags like /bin/bash -e or unsupported interpreter like python)
		info.Supported = false
	}
	return info
}

func isExecutionConfigured(cfg *ExecutionConfig) bool {
	return cfg != nil && (cfg.Interpreter != "" || cfg.LaunchDialect != "" || cfg.Login != nil)
}

func resolveExplicitScriptInterpreter(explicit *ExecutionConfig) (Interpreter, error) {
	if explicit == nil || explicit.Interpreter == "" {
		return "", nil
	}
	if explicit.Interpreter == InterpreterServer {
		return "", fmt.Errorf("%w: explicitly selecting server interpreter for script is unsupported", ErrExecutionValidation)
	}
	return explicit.Interpreter, nil
}

func resolveFallbackScriptInterpreter(node, global *ExecutionConfig) Interpreter {
	if node != nil && node.Interpreter != "" && node.Interpreter != InterpreterServer {
		return node.Interpreter
	}
	if global != nil && global.Interpreter != "" && global.Interpreter != InterpreterServer {
		return global.Interpreter
	}
	return ""
}

func stripServerInterpreter(cfg *ExecutionConfig) *ExecutionConfig {
	if cfg == nil {
		return nil
	}
	cloned := cfg.Clone()
	if cloned.Interpreter == InterpreterServer {
		cloned.Interpreter = ""
	}
	return cloned
}

func determineScriptInterpreter(step, settings, node, global *ExecutionConfig, scriptBytes []byte) (Interpreter, error) {
	if bytes.HasPrefix(scriptBytes, []byte("\xef\xbb\xbf")) {
		return "", fmt.Errorf("%w: script contains unsupported UTF-8 BOM prefix", ErrExecutionValidation)
	}

	stepInterp, err := resolveExplicitScriptInterpreter(step)
	if err != nil {
		return "", err
	}
	setInterp, err := resolveExplicitScriptInterpreter(settings)
	if err != nil {
		return "", err
	}

	shebang := ParseShebang(scriptBytes)
	if shebang.HasShebang && !shebang.Supported && stepInterp == "" && setInterp == "" {
		return "", fmt.Errorf("%w: unsupported shebang %q in script", ErrExecutionValidation, shebang.RawLine)
	}

	if stepInterp != "" {
		return stepInterp, nil
	}
	if setInterp != "" {
		return setInterp, nil
	}
	if shebang.HasShebang {
		return shebang.Interpreter, nil
	}
	if fallback := resolveFallbackScriptInterpreter(node, global); fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("%w: no supported interpreter found for script: server interpreter cannot be used for scripts", ErrExecutionValidation)
}

// ResolveScriptExecution resolves the execution configuration for a script following
// the precedence order:
//  1. Explicit Playbook step execution (step)
//  2. Playbook settings execution (settings)
//  3. Supported shebang declaration in script bytes
//  4. Node execution (non-server only)
//  5. Global execution (non-server only)
//
// Explicitly selecting the server interpreter in step or settings returns an error.
// If the script declares an unsupported shebang without an explicit step or settings
// override, an error is returned.
// If no execution config is configured anywhere across all layers, it returns (nil, nil)
// indicating legacy mode.
// If execution config is present but no valid non-server script interpreter can be
// determined, an error is returned.
func ResolveScriptExecution(step, settings, node, global *ExecutionConfig, scriptBytes []byte) (*ExecutionConfig, error) {
	if !isExecutionConfigured(step) && !isExecutionConfigured(settings) && !isExecutionConfigured(node) && !isExecutionConfigured(global) {
		return nil, nil
	}

	targetInterp, err := determineScriptInterpreter(step, settings, node, global, scriptBytes)
	if err != nil {
		return nil, err
	}

	var stepCopy *ExecutionConfig
	if step != nil {
		stepCopy = step.Clone()
	} else {
		stepCopy = &ExecutionConfig{}
	}
	stepCopy.Interpreter = targetInterp

	var settingsCopy *ExecutionConfig
	if settings != nil {
		settingsCopy = settings.Clone()
	}

	nodeCopy := stripServerInterpreter(node)
	globalCopy := stripServerInterpreter(global)

	res, err := EffectiveExecution(stepCopy, settingsCopy, nodeCopy, globalCopy)
	if err != nil {
		return nil, err
	}
	return validateResolvedScriptExecution(res)
}

// A body shebang cannot establish the server's outer launch dialect. Revalidate
// after selecting an interpreter and freeze its effective login mode, so script
// execution cannot silently fall back to the legacy Bash defaults.
func validateResolvedScriptExecution(res *ExecutionConfig) (*ExecutionConfig, error) {
	if err := res.Validate(); err != nil {
		return nil, err
	}
	if res == nil || (res.Interpreter != InterpreterBash && res.Interpreter != InterpreterSh) {
		return nil, fmt.Errorf("%w: unsupported resolved script interpreter", ErrExecutionValidation)
	}
	plan, err := PlanCommand(":", res.CommandOptions())
	if err != nil {
		return nil, fmt.Errorf("%w: resolve script adapter: %w", ErrExecutionValidation, err)
	}
	login := plan.LoginMode() == LoginEnabled
	res.Login = &login
	return res, nil
}
