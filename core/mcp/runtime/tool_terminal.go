package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/session"
	"github.com/wentf9/xops-cli/core/ssh"
)

const (
	onceSession     = "once"
	foldedLogDir    = ".cache/xops-mcp"
	maxFoldedLogs   = 32
	riskActionOnce  = "once"
	riskActionPoll  = "poll"
	riskActionShell = "session"
)

type TerminalInput struct {
	NodeID    string               `json:"nodeID" jsonschema:"Target SSH node ID or alias"`
	Command   string               `json:"cmd,omitempty" jsonschema:"Shell command to execute, empty to poll incremental output on a persistent session, or SIGINT/EOF/SIGTERM/SIGKILL to signal a persistent session"`
	Session   string               `json:"session,omitempty" jsonschema:"Session mode: 'once' (default, stateless) or a custom session name to persist PTY state (cwd, env, background jobs) in the remote POSIX login shell"`
	Cwd       string               `json:"cwd,omitempty" jsonschema:"Optional working directory to switch to before executing cmd"`
	Timeout   int                  `json:"timeout,omitempty" jsonschema:"Max seconds to wait before returning output (once: bounded by the server tool timeout; persistent sessions: default 5s, after which the command keeps running and can be polled)"`
	Sudo      bool                 `json:"sudo,omitempty" jsonschema:"Whether to execute the command with sudo privileges (once mode only)"`
	Execution *ssh.ExecutionConfig `json:"execution,omitempty" jsonschema:"Optional execution configuration overriding node/global defaults (once mode only); supports fish and zsh. Unspecified environments are probed when the backend supports discovery; explicit server preserves passthrough."`
}

func (in TerminalInput) Validate() error {
	if isPersistentSession(in.Session) && (in.Sudo || in.Execution != nil) {
		return errors.New("sudo and execution are supported only with session='once'; run sudo inside the persistent shell instead")
	}
	if !isPersistentSession(in.Session) && strings.TrimSpace(in.Command) == "" {
		return errors.New("cmd is required for once session mode")
	}
	return nil
}

type TerminalOutput struct {
	Output     string  `json:"output" jsonschema:"Command stdout/stderr (folded when verbose)"`
	Status     string  `json:"status" jsonschema:"Operation status: success, running, or failed"`
	Error      string  `json:"error,omitempty" jsonschema:"Error message if failed"`
	Outcome    string  `json:"outcome,omitempty" jsonschema:"Execution outcome: not_started, completed, or unknown"`
	ExitCode   *uint32 `json:"exitCode,omitempty" jsonschema:"Exit status code if received"`
	Signal     string  `json:"signal,omitempty" jsonschema:"Termination signal if terminated by signal"`
	PlanDigest string  `json:"planDigest,omitempty" jsonschema:"Digest of the executed command plan"`
	Truncated  bool    `json:"truncated,omitempty" jsonschema:"Whether output exceeded limit or was folded"`
	NewSession bool    `json:"newSession,omitempty" jsonschema:"True when a new persistent PTY session was opened (initial call or after a previous session expired/closed)"`
}

func isPersistentSession(name string) bool { return name != "" && name != onceSession }

func (r *Runtime) terminalHandler(ctx context.Context, _ *mcp.CallToolRequest, input TerminalInput) (*mcp.CallToolResult, TerminalOutput, error) {
	if input.NodeID == "" {
		return nil, TerminalOutput{}, errors.New("nodeID is required")
	}
	if isPersistentSession(input.Session) {
		return r.terminalSessionHandler(ctx, input)
	}
	if input.Command == "" {
		return nil, TerminalOutput{}, errors.New("cmd is required for once session mode")
	}

	runCtx := ctx
	if input.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(input.Timeout)*time.Second)
		defer cancel()
	}

	result, execErr := r.runOnce(ctx, runCtx, input)
	if execErr != nil && !result.Connected {
		return nil, TerminalOutput{}, execErr
	}

	failed := execErr != nil || (result.ExitCode != nil && *result.ExitCode != 0)
	folded, wasFolded := r.foldOutput(ctx, input.NodeID, result.Output, failed)

	out := TerminalOutput{
		Output:     folded,
		Status:     "success",
		Outcome:    string(result.Outcome),
		ExitCode:   result.ExitCode,
		Signal:     result.Signal,
		PlanDigest: result.PlanDigest,
		Truncated:  result.Truncated || wasFolded,
	}
	if execErr != nil {
		out.Status, out.Error = "failed", FormatMCPError(execErr).Error()
	}
	return nil, out, nil
}

// runOnce executes a stateless command. Setup failures are returned with a
// zero (not connected) result so the caller reports them as tool errors.
func (r *Runtime) runOnce(ctx, runCtx context.Context, input TerminalInput) (ports.CommandResult, error) {
	op, err := currentOperation(ctx)
	if err != nil {
		return ports.CommandResult{}, err
	}
	execution := input.Execution
	if op.execution != nil {
		execution = op.execution.Clone()
	}
	command := ports.Command{Text: input.Command, Sudo: input.Sudo, Execution: execution}

	if input.Cwd != "" {
		_, target, err := op.snapshot.Resolve(input.NodeID)
		if err != nil {
			return ports.CommandResult{}, err
		}
		effective, err := ssh.ResolveExecution(execution, target.Execution)
		if err != nil {
			return ports.CommandResult{}, err
		}
		if command.Text, err = ssh.FormatWorkingDirCommand(input.Cwd, input.Command, effective); err != nil {
			return ports.CommandResult{}, err
		}
		if !input.Sudo {
			plan, err := ssh.PlanCommand(command.Text, effective.CommandOptions())
			if err != nil {
				return ports.CommandResult{}, err
			}
			command.Plan = &plan
		}
	}

	result, err := r.backend.Run(runCtx, op.permit, input.NodeID, command)
	return result, FormatMCPError(err)
}

func (r *Runtime) terminalSessionHandler(ctx context.Context, input TerminalInput) (*mcp.CallToolResult, TerminalOutput, error) {
	if input.Sudo || input.Execution != nil {
		return nil, TerminalOutput{}, errors.New("sudo and execution are supported only with session='once'; run sudo inside the persistent shell instead")
	}
	if r.sessions == nil {
		return nil, TerminalOutput{}, errors.New("persistent terminal sessions are not initialized")
	}
	ptyBackend, ok := r.backend.(ports.PTYBackend)
	if !ok {
		return nil, TerminalOutput{}, errors.New("MCP backend does not support persistent PTY sessions")
	}
	op, err := currentOperation(ctx)
	if err != nil {
		return nil, TerminalOutput{}, err
	}
	nodeID, target, err := op.snapshot.Resolve(input.NodeID)
	if err != nil {
		return nil, TerminalOutput{}, err
	}
	var dialect ssh.LaunchDialect
	if target.Execution != nil && target.Execution.LaunchDialect != "" {
		dialect = target.Execution.LaunchDialect
	}
	if op.execution != nil && op.execution.LaunchDialect != "" && op.execution.LaunchDialect != ssh.LaunchUnknown {
		dialect = op.execution.LaunchDialect
	}
	switch dialect {
	case ssh.LaunchPowerShell, ssh.LaunchCmd:
		return nil, TerminalOutput{}, fmt.Errorf("persistent sessions require a Unix login shell (posix, fish, or csh); node %s uses %s (use session='once')", nodeID, dialect)
	}

	var timeout time.Duration
	if input.Timeout > 0 {
		timeout = time.Duration(input.Timeout) * time.Second
	}
	connKey, err := ssh.ConnectionKey(target.Plan)
	if err != nil {
		return nil, TerminalOutput{}, err
	}
	generation := connKey + "|" + target.Version + "|" + target.ExecutionVersion
	res, err := r.sessions.Execute(ctx, session.ExecuteRequest{
		Key:        session.Key{Scope: r.scope(ctx), NodeID: nodeID, SessionName: input.Session},
		Generation: generation,
		Dialect:    dialect,
		Dial: func(dialCtx context.Context) (ports.PTYSession, error) {
			return ptyBackend.OpenPTY(dialCtx, op.permit, nodeID)
		},
		Command: input.Command,
		Cwd:     input.Cwd,
		Timeout: timeout,
	})
	if err != nil {
		return nil, TerminalOutput{}, FormatMCPError(err)
	}
	return nil, r.sessionOutput(ctx, nodeID, res), nil
}

// sessionOutput maps session state to the terminal contract: only an observed
// completion sentinel is "completed"; a timeout or a lost session is
// "unknown" and never carries an exit code.
func (r *Runtime) sessionOutput(ctx context.Context, nodeID string, res session.ExecuteResult) TerminalOutput {
	out := TerminalOutput{Status: "success", NewSession: res.NewSession}
	failed := false
	switch res.State {
	case session.StateCompleted:
		out.Outcome, out.ExitCode = string(ssh.ExecutionCompleted), res.ExitCode
		failed = res.ExitCode != nil && *res.ExitCode != 0
		if failed {
			out.Status = "failed"
		}
	case session.StateRunning:
		out.Outcome, out.Status = string(ssh.ExecutionUnknown), "running"
	case session.StateLost:
		out.Outcome, out.Status, failed = string(ssh.ExecutionUnknown), "failed", true
		out.Error = "terminal session ended before the command reported completion; verify remote state before retrying"
	}
	folded, wasFolded := r.foldOutput(ctx, nodeID, res.Output, failed)
	out.Output, out.Truncated = folded, res.Truncated || wasFolded
	return out
}

func (r *Runtime) foldOutput(ctx context.Context, nodeID, raw string, failed bool) (string, bool) {
	return foldTerminalOutput(raw, failed, func(full string) string {
		return r.saveFoldedLog(ctx, nodeID, full)
	})
}

// saveFoldedLog stores the unfolded output under the SSH user's home
// directory ($HOME/.cache/xops-mcp, mode 0700) in a new 0600 file created
// exclusively, so shared temporary directories and symlink races are never
// involved. Failures are non-fatal: the folded output is still returned.
func (r *Runtime) saveFoldedLog(ctx context.Context, nodeID, content string) string {
	files, err := r.getMCPSFTPClient(ctx, nodeID)
	if err != nil {
		return ""
	}
	defer func() { _ = files.Close() }()

	suffix, err := randomHex(6)
	if err != nil {
		return ""
	}
	var logPath string
	if err := files.Do(ctx, func(c *pkgsftp.Client) error {
		home, err := c.RealPath(".")
		if err != nil {
			return err
		}
		dir := path.Join(home, foldedLogDir)
		if err := c.MkdirAll(dir); err != nil {
			return err
		}
		info, err := c.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		if err := c.Chmod(dir, 0o700); err != nil {
			return err
		}
		pruneFoldedLogs(c, dir, maxFoldedLogs-1)
		logPath = path.Join(dir, "cmd-"+time.Now().UTC().Format("20060102T150405")+"-"+suffix+".log")
		return nil
	}); err != nil {
		return ""
	}
	if _, _, err := files.CreatePrivateExclusive(ctx, logPath, func(w io.Writer) error {
		_, err := io.WriteString(w, content)
		return err
	}); err != nil {
		return ""
	}
	return logPath
}

func pruneFoldedLogs(c *pkgsftp.Client, dir string, keep int) {
	entries, err := c.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.Mode().IsRegular() && strings.HasPrefix(name, "cmd-") && strings.HasSuffix(name, ".log") {
			names = append(names, name)
		}
	}
	if len(names) <= keep {
		return
	}
	slices.Sort(names)
	for _, old := range names[:len(names)-keep] {
		_ = c.Remove(path.Join(dir, old))
	}
}

func terminalRiskInput(in TerminalInput) guardrail.RiskInput {
	action := riskActionOnce
	if isPersistentSession(in.Session) {
		action = riskActionShell
		if strings.TrimSpace(in.Command) == "" && in.Cwd == "" {
			action = riskActionPoll
		}
	}
	var paths []string
	if in.Cwd != "" {
		paths = []string{in.Cwd}
	}
	ri := guardrail.RiskInput{
		Action:    action,
		NodeID:    in.NodeID,
		Command:   in.Command,
		Paths:     paths,
		Sudo:      in.Sudo,
		Execution: in.Execution,
	}
	if action != riskActionOnce {
		ri.Details = "session=" + in.Session
	}
	return ri
}

func (r *Runtime) registerTerminal(server *mcp.Server, g *guardrail.Guardrail) {
	destructive := true
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "terminal",
			Description: "Execute a shell command or interact with a persistent PTY session on a managed SSH node. Use session='once' (default) for stateless commands or a custom session name to persist cwd, env, and background processes (idle sessions expire after 30m). A running persistent command must be polled (empty cmd) or interrupted (SIGINT/EOF/SIGTERM/SIGKILL) before the next command.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
			InputSchema: terminalInputSchema(),
		},
		withOperation(r, g, "terminal", terminalRiskInput, r.terminalHandler),
	)
}

func terminalInputSchema() *jsonschema.Schema {
	schema, err := jsonschema.For[TerminalInput](nil)
	if err != nil {
		panic(fmt.Sprintf("generate terminalInputSchema: %v", err))
	}
	if execSchema, ok := schema.Properties["execution"]; ok && execSchema != nil {
		if execSchema.Properties != nil {
			execSchema.Properties["launch_dialect"] = &jsonschema.Schema{
				Type: "string",
			}
			execSchema.Properties["login"] = &jsonschema.Schema{
				Types: []string{"null", "boolean", "string"},
			}
			execSchema.PropertyOrder = []string{"interpreter", "launchDialect", "launch_dialect", "login"}
		}
	}
	return schema
}
