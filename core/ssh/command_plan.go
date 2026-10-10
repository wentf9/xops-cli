package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Interpreter selects how a command is executed, independently of the server's
// launch dialect. Only validated command adapters are exposed here.
type Interpreter string

const (
	InterpreterServer     Interpreter = "server"
	InterpreterBash       Interpreter = "bash"
	InterpreterSh         Interpreter = "sh"
	InterpreterPowerShell Interpreter = "powershell"
	InterpreterPwsh       Interpreter = "pwsh"
	InterpreterCmd        Interpreter = "cmd"
)

// LaunchDialect describes the server shell parsing the SSH exec payload.
type LaunchDialect string

const (
	LaunchUnknown    LaunchDialect = "unknown"
	LaunchPOSIX      LaunchDialect = "posix"
	LaunchPowerShell LaunchDialect = "powershell"
	LaunchCmd        LaunchDialect = "cmd"
)

// LoginMode preserves the distinction between omission and an explicit false.
type LoginMode string

const (
	LoginInherit  LoginMode = "inherit"
	LoginEnabled  LoginMode = "enabled"
	LoginDisabled LoginMode = "disabled"
)

const (
	// Bound both original and quoted payloads below SSH transport packet and
	// common per-argument limits; remote servers may impose smaller limits.
	MaxCommandBytes       = 64 << 10
	MaxCommandInputBytes  = 16 << 20
	DefaultCommandOutput  = 5 << 20
	MaxCommandOutput      = 64 << 20
	DefaultCommandTimeout = 5 * time.Minute
)

// CommandOptions is copied into an immutable CommandPlan. Stdin is finite user
// data, never a second command or an interpreter-selection probe. Timeout zero
// and OutputLimit zero select bounded defaults; negative values are invalid.
type CommandOptions struct {
	Interpreter   Interpreter
	LaunchDialect LaunchDialect
	Login         LoginMode
	Stdin         []byte
	Timeout       time.Duration
	OutputLimit   int
}

// CommandPlan is immutable and safe to share across execution attempts. The
// zero value is invalid. Accessors return values, never mutable internal state.
// Digest binds command semantics and input but is not an authorization permit.
type CommandPlan struct {
	command     string
	payload     string
	interpreter Interpreter
	dialect     LaunchDialect
	login       LoginMode
	input       string
	timeout     time.Duration
	outputLimit int
	digest      string
}

// PlanCommand validates and freezes one ordinary command without network I/O.
// It never performs OS detection or fallback. Bash requires a known POSIX outer
// shell; server preserves command bytes and accepts only inherited login mode.
func PlanCommand(command string, options CommandOptions) (CommandPlan, error) {
	if command == "" || len(command) > MaxCommandBytes || strings.ContainsRune(command, '\x00') {
		return CommandPlan{}, fmt.Errorf("command must contain 1 to %d bytes without NUL", MaxCommandBytes)
	}
	if len(options.Stdin) > MaxCommandInputBytes {
		return CommandPlan{}, fmt.Errorf("command stdin exceeds %d bytes", MaxCommandInputBytes)
	}
	if options.Timeout < 0 || options.OutputLimit < 0 || options.OutputLimit > MaxCommandOutput {
		return CommandPlan{}, fmt.Errorf("command timeout or output limit is invalid")
	}
	p := CommandPlan{
		command: command, interpreter: options.Interpreter, dialect: options.LaunchDialect,
		login: options.Login, input: string(options.Stdin), timeout: options.Timeout, outputLimit: options.OutputLimit,
	}
	p.defaults()
	if err := p.buildPayload(); err != nil {
		return CommandPlan{}, err
	}
	if len(p.payload) > MaxCommandBytes {
		return CommandPlan{}, fmt.Errorf("generated exec payload exceeds %d bytes", MaxCommandBytes)
	}
	// Encode strings as byte slices to preserve even invalid UTF-8 losslessly.
	encoded, err := json.Marshal(struct {
		Version                 int
		Command, Payload, Input []byte
		Interpreter             Interpreter
		Dialect                 LaunchDialect
		Login                   LoginMode
		Timeout                 time.Duration
		OutputLimit             int
	}{1, []byte(p.command), []byte(p.payload), []byte(p.input), p.interpreter, p.dialect, p.login, p.timeout, p.outputLimit})
	if err != nil {
		return CommandPlan{}, fmt.Errorf("encode command plan: %w", err)
	}
	digest := sha256.Sum256(encoded)
	p.digest = hex.EncodeToString(digest[:])
	return p, nil
}

func (p *CommandPlan) defaults() {
	if p.interpreter == "" {
		p.interpreter = InterpreterServer
	}
	if p.dialect == "" {
		p.dialect = LaunchUnknown
	}
	if p.login == "" {
		p.login = LoginInherit
	}
	if p.timeout == 0 {
		p.timeout = DefaultCommandTimeout
	}
	if p.outputLimit == 0 {
		p.outputLimit = DefaultCommandOutput
	}
}

func (p *CommandPlan) buildPayload() error {
	switch p.dialect {
	case LaunchUnknown, LaunchPOSIX, LaunchPowerShell, LaunchCmd:
	default:
		return fmt.Errorf("unsupported launch dialect %q", p.dialect)
	}
	switch p.login {
	case LoginInherit, LoginEnabled, LoginDisabled:
	default:
		return fmt.Errorf("unsupported login mode %q", p.login)
	}
	switch p.interpreter {
	case InterpreterServer:
		if p.login != LoginInherit {
			return fmt.Errorf("server interpreter requires inherited login mode")
		}
		p.payload = p.command
	case InterpreterBash:
		if p.dialect != LaunchPOSIX {
			return fmt.Errorf("bash interpreter requires posix launch dialect")
		}
		p.payload = bashCommandPayload(p.command, p.login == LoginEnabled)
		if p.login == LoginInherit {
			p.login = LoginDisabled
		}
	case InterpreterSh:
		if p.dialect != LaunchPOSIX {
			return fmt.Errorf("sh interpreter requires posix launch dialect")
		}
		if p.login == LoginEnabled {
			return fmt.Errorf("sh interpreter does not support login shell")
		}
		p.login = LoginDisabled
		p.payload = shCommandPayload(p.command)
	case InterpreterPowerShell:
		if p.login != LoginInherit {
			return fmt.Errorf("powershell interpreter requires inherited login mode")
		}
		payload, err := powershellCommandPayload(p.command, p.dialect)
		if err != nil {
			return err
		}
		p.payload = payload
	case InterpreterPwsh:
		if p.login != LoginInherit {
			return fmt.Errorf("pwsh interpreter requires inherited login mode")
		}
		payload, err := pwshCommandPayload(p.command, p.dialect)
		if err != nil {
			return err
		}
		p.payload = payload
	case InterpreterCmd:
		if p.login != LoginInherit {
			return fmt.Errorf("cmd interpreter requires inherited login mode")
		}
		payload, err := cmdCommandPayload(p.command, p.dialect)
		if err != nil {
			return err
		}
		p.payload = payload
	default:
		return fmt.Errorf("unsupported command interpreter %q", p.interpreter)
	}
	return nil
}

// bashCommandPayload is the only construction of Bash command exec payloads.
// Legacy entry points call it directly to retain their historical lack of
// size limits; PlanCommand additionally applies the new API limits.
func bashCommandPayload(command string, login bool) string {
	if login {
		return "bash -l -c " + shellQuote(command)
	}
	return "bash -c " + shellQuote(command)
}

// bashScriptPayload selects Bash reading the script from stdin. It is used only
// by legacy script entry points until the script model is migrated.
func bashScriptPayload(login bool) string {
	if login {
		return "bash -l -s"
	}
	return "bash -s"
}

// shCommandPayload is the construction of sh command exec payloads.
func shCommandPayload(command string) string {
	return "sh -c " + shellQuote(command)
}

// shScriptPayload selects sh reading the script from stdin.
func shScriptPayload() string {
	return "sh -s"
}

func (p CommandPlan) Command() string              { return p.command }
func (p CommandPlan) Payload() string              { return p.payload }
func (p CommandPlan) Interpreter() Interpreter     { return p.interpreter }
func (p CommandPlan) LaunchDialect() LaunchDialect { return p.dialect }
func (p CommandPlan) LoginMode() LoginMode         { return p.login }
func (p CommandPlan) Digest() string               { return p.digest }
