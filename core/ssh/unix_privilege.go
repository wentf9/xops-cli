package ssh

import (
	"context"
	"fmt"
	"io"
	"strings"
)

func usesPortableShellAdapter(config *RunConfig) bool {
	return config != nil && (config.Interpreter == InterpreterZsh || config.Interpreter == InterpreterFish || config.Interpreter == InterpreterCsh || config.Interpreter == InterpreterTcsh || config.LaunchDialect == LaunchFish || config.LaunchDialect == LaunchCsh)
}

// The control shell always speaks POSIX. User code is a separate interpreter
// invocation, quoted for that control shell rather than the SSH outer shell.
func portableUserCommand(command string, config *RunConfig, dialect LaunchDialect) string {
	interpreter := config.Interpreter
	if interpreter == "" {
		interpreter = InterpreterBash
	}
	supportsLogin := interpreter != InterpreterSh && interpreter != InterpreterCsh && interpreter != InterpreterTcsh
	if command == "" {
		payload := "exec " + string(interpreter)
		if config.LoginShell && supportsLogin {
			payload += " -l"
		}
		return payload
	}
	return unixCommandPayload(interpreter, command, config.LoginShell && supportsLogin, dialect)
}

func (c *Client) runPortableWithSudo(ctx context.Context, content string, script bool, config *RunConfig, mat ...*PrivilegeMaterial) (string, error) {
	switch config.Interpreter {
	case "", InterpreterBash, InterpreterSh, InterpreterZsh, InterpreterFish, InterpreterCsh, InterpreterTcsh:
	default:
		return "", fmt.Errorf("%w: Unix privilege execution requires bash, sh, zsh, fish, csh or tcsh", ErrExecutionValidation)
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
		return c.runPrivilegeWithConfig(ctx, mode, inner, input, config, mat...)
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
	e.commandPreview = e.wrapPortableBody("<privileged payload>", "<password-prompt>")
	return e.wrapPortableBody(e.body(command), e.promptToken)
}

func (e *privilegeExchange) wrapPortableBody(body, prompt string) string {
	quote := shellQuote
	switch e.launchDialect {
	case LaunchFish:
		quote = fishQuote
	case LaunchCsh:
		quote = cshQuote
	}
	if e.mode == SudoModeSu {
		if (e.interpreter == InterpreterSh || e.interpreter == InterpreterCsh || e.interpreter == InterpreterTcsh || e.launchDialect == LaunchCsh) && e.launchDialect != LaunchFish {
			normalized := strings.ReplaceAll(body, "\r\n", "\n")
			trimmed := strings.TrimSuffix(normalized, "\n")
			var suBody string
			if !strings.Contains(trimmed, "\n") {
				suBody = "exec sh -c " + strings.ReplaceAll(shellQuote(trimmed), "!", "'\\!'")
			} else {
				lines := strings.Split(trimmed, "\n")
				quotedLines := make([]string, len(lines))
				for i, line := range lines {
					quotedLines[i] = strings.ReplaceAll(shellQuote(line), "!", "'\\!'")
				}
				suBody = "exec sh -c 'eval \"$(printf '\\''%s\\n'\\'' \"$@\")\"' sh " + strings.Join(quotedLines, " ")
			}
			if e.launchDialect == LaunchCsh {
				return "env LC_ALL=C su - root -c " + quote(suBody)
			}
			return "export LC_ALL=C; su - root -c " + shellQuote(suBody)
		}
		return "env LC_ALL=C su - root -s /bin/sh -c " + quote(body)
	}
	prefix := "sudo -S -p "
	if e.mode == SudoModeSudoer {
		prefix = "sudo -n -S -p "
	}
	return prefix + quote(prompt) + " -- /bin/sh -c " + quote(body)
}

func (c *Client) runInteractivePortableWithSudo(ctx context.Context, mode SudoMode, command string, streams InteractiveIO, shell bool, config *RunConfig, extra ...any) error {
	if config.Interpreter == "" || config.Interpreter == InterpreterServer {
		if config.LaunchDialect == LaunchCsh {
			config.Interpreter = InterpreterCsh
		} else {
			config.Interpreter = InterpreterFish
		}
	}
	switch config.Interpreter {
	case InterpreterBash, InterpreterSh, InterpreterZsh, InterpreterFish, InterpreterCsh, InterpreterTcsh:
	default:
		return fmt.Errorf("%w: interactive Unix privilege execution requires bash, sh, zsh, fish, csh or tcsh", ErrExecutionValidation)
	}
	if shell {
		config.LoginShell = true
	}
	if err := validatePortableShellConfig(config); err != nil {
		return err
	}
	var cancelOutput []context.CancelFunc
	for _, item := range extra {
		if fn, ok := item.(context.CancelFunc); ok {
			cancelOutput = append(cancelOutput, fn)
		}
	}
	if mode == SudoModeRoot {
		payload := portableUserCommand(command, config, config.LaunchDialect)
		return c.runTerminalSession(ctx, payload, streams, false, shell, cancelOutput...)
	}
	inner := portableUserCommand(command, config, LaunchPOSIX)
	return c.runInteractivePrivilegeSession(ctx, mode, inner, streams, shell, config, extra...)
}

func validatePortableShellConfig(config *RunConfig) error {
	interpreter := config.Interpreter
	if interpreter == "" {
		interpreter = InterpreterBash
	}
	login := LoginDisabled
	if config.LoginShell && interpreter != InterpreterSh && interpreter != InterpreterCsh && interpreter != InterpreterTcsh {
		login = LoginEnabled
	}
	if _, err := PlanCommand("true", CommandOptions{Interpreter: interpreter, LaunchDialect: config.LaunchDialect, Login: login}); err != nil {
		return fmt.Errorf("%w: validate Unix privilege adapter: %w", ErrExecutionValidation, err)
	}
	return nil
}
