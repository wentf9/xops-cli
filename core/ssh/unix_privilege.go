package ssh

import (
	"context"
	"fmt"
	"io"
	"strings"
)

func usesPortableShellAdapter(config *RunConfig) bool {
	return config != nil && (config.Interpreter == InterpreterZsh || config.Interpreter == InterpreterFish || config.LaunchDialect == LaunchFish)
}

// The control shell always speaks POSIX. User code is a separate interpreter
// invocation, quoted for that control shell rather than the SSH outer shell.
func portableUserCommand(command string, config *RunConfig, dialect LaunchDialect) string {
	interpreter := config.Interpreter
	if interpreter == "" {
		interpreter = InterpreterBash
	}
	if command == "" {
		payload := "exec " + string(interpreter)
		if config.LoginShell && interpreter != InterpreterSh {
			payload += " -l"
		}
		return payload
	}
	return unixCommandPayload(interpreter, command, config.LoginShell && interpreter != InterpreterSh, dialect)
}

func (c *Client) runPortableWithSudo(ctx context.Context, content string, script bool, config *RunConfig) (string, error) {
	switch config.Interpreter {
	case "", InterpreterBash, InterpreterSh, InterpreterZsh, InterpreterFish:
	default:
		return "", fmt.Errorf("%w: Unix privilege execution requires bash, sh, zsh or fish", ErrExecutionValidation)
	}
	if err := validatePortableShellConfig(config); err != nil {
		return "", err
	}
	inner := portableUserCommand(content, config, LaunchPOSIX)
	var input io.Reader
	if script {
		inner = strings.TrimPrefix(portableUserCommand("", config, LaunchPOSIX), "exec ")
		if config.Interpreter != InterpreterFish {
			inner += " -s"
		}
		input = strings.NewReader(content)
	}
	mode := c.ConnectionConfig().SudoMode
	switch mode {
	case SudoModeRoot:
		if script {
			return c.RunScript(ctx, content, func(target *RunConfig) { *target = *config })
		}
		return c.runRaw(ctx, portableUserCommand(content, config, config.LaunchDialect), config)
	case SudoModeSudoer, SudoModeSudo, SudoModeSu:
		return c.runPrivilegeWithConfig(ctx, mode, inner, input, config)
	default:
		return "", fmt.Errorf("privilege escalation is unsupported for sudo mode %q", mode)
	}
}

// Avoid sudo -i's extra parsing by the target user's unspecified login shell.
// Login semantics belong to the explicitly selected user-code interpreter.
func (e *privilegeExchange) portableCommand(command string) string {
	if command == "" {
		command = portableUserCommand("", &RunConfig{Interpreter: e.interpreter, LoginShell: true}, LaunchPOSIX)
	}
	body := e.body(command)
	quote := shellQuote
	if e.launchDialect == LaunchFish {
		quote = fishQuote
	}
	if e.mode == SudoModeSu {
		return "env LC_ALL=C su - root -s /bin/sh -c " + quote(body)
	}
	prefix := "sudo -S -p "
	if e.mode == SudoModeSudoer {
		prefix = "sudo -n -S -p "
	}
	return prefix + quote(e.promptToken) + " -- /bin/sh -c " + quote(body)
}

func (c *Client) runInteractivePortableWithSudo(ctx context.Context, mode SudoMode, command string, streams InteractiveIO, shell bool, config *RunConfig, cancelOutput ...context.CancelFunc) error {
	if config.Interpreter == "" || config.Interpreter == InterpreterServer {
		config.Interpreter = InterpreterFish
	}
	switch config.Interpreter {
	case InterpreterBash, InterpreterSh, InterpreterZsh, InterpreterFish:
	default:
		return fmt.Errorf("%w: interactive Unix privilege execution requires bash, sh, zsh or fish", ErrExecutionValidation)
	}
	if shell {
		config.LoginShell = true
	}
	if err := validatePortableShellConfig(config); err != nil {
		return err
	}
	if mode == SudoModeRoot {
		payload := portableUserCommand(command, config, config.LaunchDialect)
		return c.runTerminalSession(ctx, payload, streams, false, shell, cancelOutput...)
	}
	inner := portableUserCommand(command, config, LaunchPOSIX)
	return c.runInteractivePrivilegeSession(ctx, mode, inner, streams, shell, config, cancelOutput...)
}

func validatePortableShellConfig(config *RunConfig) error {
	interpreter := config.Interpreter
	if interpreter == "" {
		interpreter = InterpreterBash
	}
	login := LoginDisabled
	if config.LoginShell && interpreter != InterpreterSh {
		login = LoginEnabled
	}
	if _, err := PlanCommand("true", CommandOptions{Interpreter: interpreter, LaunchDialect: config.LaunchDialect, Login: login}); err != nil {
		return fmt.Errorf("%w: validate Unix privilege adapter: %w", ErrExecutionValidation, err)
	}
	return nil
}
