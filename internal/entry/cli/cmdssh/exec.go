package cmdssh

import (
	"bytes"
	"context"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

type execArgs struct {
	common          clikit.CommonFlags
	cliOpts         option.OptionLayer
	requestTTY      engine.RequestTTYMode
	ttyCount        int
	targets         []string
	allNodes        bool
	nodeIDs         []inventory.NodeID
	tags            []inventory.Tag
	excludeNodes    []inventory.NodeID
	excludeTags     []inventory.Tag
	concurrency     int
	failFast        bool
	stream          bool
	maxOutputBytes  algebraic.Option[uint64]
	outputDir       algebraic.Option[pathalg.LocalDir]
	timeout         algebraic.Option[algebraic.Duration]
	dialect         algebraic.Option[execution.LaunchDialect]
	interpreter     execution.Interpreter
	loginMode       execution.LoginMode
	workDir         algebraic.Option[pathalg.RemotePath]
	envVars         map[string]string
	privMethod      engine.PrivilegeMethod
	privUser        string
	privPasswordRef algebraic.Option[secret.Ref]
	promptPassword  bool
	commandArgs     []string
}

// RunExec 执行 `xops exec`：自动依据目标选择路由至单机 Exec/ExecPrivileged 或多机并发 BatchExec。
func RunExec(ctx context.Context, rt *clikit.Runtime, args []string) int {
	parsed, err := parseExecArgs(args)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
	}
	if parsed.common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, ExecHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(parsed.common.JSON)
	cmdPlan, err := buildExecCommandPlan(parsed)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	initOpts := rt.EffectiveInitOptions(parsed.common.ConfigFile, parsed.common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitSSHError, jsonOut, func(runner clikit.SessionRunner) int {
		if parsed.isBatch() {
			return runBatchExec(ctx, rt, runner, parsed, cmdPlan, jsonOut)
		}
		return runSingleExec(ctx, rt, runner, parsed, cmdPlan, jsonOut)
	})
}

func (a execArgs) isBatch() bool {
	return a.allNodes || len(a.nodeIDs) > 0 || len(a.tags) > 0 || len(a.targets) > 1
}

func parseExecArgs(args []string) (execArgs, error) {
	out := execArgs{
		cliOpts: option.UnsetOptionLayer(),
		envVars: map[string]string{},
	}
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		tok := cur.Peek()
		if tok == "--" {
			cur.Next()
			out.commandArgs = cur.Rest()
			break
		}
		if tok == "-h" || tok == "--help" {
			out.common.ShowHelp = true
			return out, nil
		}
		if !strings.HasPrefix(tok, "-") || tok == "-" {
			collectExecPositional(cur, &out)
			break
		}
		if err := parseExecFlag(cur, &out); err != nil {
			return execArgs{}, err
		}
		if out.common.ShowHelp {
			return out, nil
		}
	}
	return finalizeExecArgs(out)
}

func collectExecPositional(cur *clikit.FlagCursor, out *execArgs) {
	rest := cur.Rest()
	if !out.isBatch() && len(out.targets) == 0 {
		out.targets = []string{rest[0]}
		rest = rest[1:]
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
	}
	out.commandArgs = rest
}

func parseExecFlag(cur *clikit.FlagCursor, out *execArgs) error {
	if strings.HasPrefix(cur.Peek(), "--") {
		return parseExecLongFlag(cur, out)
	}
	tok := cur.Next()
	return parseExecShortCluster(cur, tok[1:], out)
}

func parseExecShortCluster(cur *clikit.FlagCursor, cluster string, out *execArgs) error {
	for i := 0; i < len(cluster); i++ {
		ch := cluster[i]
		if ok, err := clikit.ApplyCommonSSHShortOption(cur, ch, cluster[i+1:], &out.cliOpts, &out.common.ConfigFile); ok || err != nil {
			return err
		}
		switch ch {
		case 'h':
			out.common.ShowHelp = true
			return nil
		case 't':
			out.ttyCount++
			if out.ttyCount >= 2 {
				out.requestTTY = engine.RequestTTYForce
			} else {
				out.requestTTY = engine.RequestTTYYes
			}
		case 'T':
			out.ttyCount = 0
			out.requestTTY = engine.RequestTTYNo
		default:
			r, _ := utf8.DecodeRuneInString(cluster[i:])
			return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownShortFlag, i18n.BoundStr("flag", string(r)))
		}
	}
	return nil
}

func parseExecLongFlag(cur *clikit.FlagCursor, out *execArgs) error {
	if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &out.common); err != nil || consumed {
		return err
	}
	tok := cur.Next()
	name, inlineVal, hasEq := clikit.SplitLongFlag(tok)
	if handled, err := parseExecSelectorFlag(cur, name, inlineVal, hasEq, out); handled || err != nil {
		return err
	}
	if handled, err := parseExecRuntimeFlag(cur, name, inlineVal, hasEq, out); handled || err != nil {
		return err
	}
	return parseExecPrivFlag(cur, name, inlineVal, hasEq, tok, out)
}

func parseExecSelectorFlag(cur *clikit.FlagCursor, name, inlineVal string, hasEq bool, out *execArgs) (bool, error) {
	switch name {
	case "all":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.allNodes = v
		return true, err
	case "target", "targets":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err == nil {
			out.targets = append(out.targets, clikit.SplitCSV(raw)...)
		}
		return true, err
	case "nodes":
		return true, appendParsedNodeIDs(cur, name, inlineVal, hasEq, &out.nodeIDs)
	case "exclude-nodes":
		return true, appendParsedNodeIDs(cur, name, inlineVal, hasEq, &out.excludeNodes)
	case "tags":
		return true, appendParsedTags(cur, name, inlineVal, hasEq, &out.tags)
	case "exclude-tags":
		return true, appendParsedTags(cur, name, inlineVal, hasEq, &out.excludeTags)
	default:
		return false, nil
	}
}

func parseExecRuntimeFlag(cur *clikit.FlagCursor, name, inlineVal string, hasEq bool, out *execArgs) (bool, error) {
	switch name {
	case "concurrency":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return true, err
		}
		out.concurrency, err = clikit.ParsePositiveInt("--concurrency", raw)
		return true, err
	case "fail-fast":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.failFast = v
		return true, err
	case "stream":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.stream = v
		return true, err
	case "max-output-bytes":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return true, err
		}
		v, err := clikit.ParseNonNegUint64("--max-output-bytes", raw)
		if err == nil {
			out.maxOutputBytes = algebraic.Some(v)
		}
		return true, err
	case "out-dir":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return true, err
		}
		d, err := pathalg.ParseLocalDir(raw)
		if err != nil {
			return true, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--out-dir"), i18n.BoundStr("value", raw))
		}
		out.outputDir = algebraic.Some(d)
		return true, nil
	case "timeout":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return true, err
		}
		d, err := clikit.ParsePositiveDuration("--timeout", raw)
		if err == nil {
			out.timeout = algebraic.Some(d)
		}
		return true, err
	default:
		return parseExecPlanFlag(cur, name, inlineVal, hasEq, out)
	}
}

func parseExecPlanFlag(cur *clikit.FlagCursor, name, inlineVal string, hasEq bool, out *execArgs) (bool, error) {
	switch name {
	case "dialect", "interpreter", "login", "workdir", "env":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return true, err
		}
		return true, applyExecPlanFlagValue(name, raw, out)
	default:
		return false, nil
	}
}

func applyExecPlanFlagValue(name, raw string, out *execArgs) error {
	switch name {
	case "dialect":
		d, err := execution.ParseLaunchDialect(raw)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--dialect"), i18n.BoundStr("value", raw))
		}
		out.dialect = algebraic.Some(d)
	case "interpreter":
		interp, err := execution.ParseInterpreter(raw)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--interpreter"), i18n.BoundStr("value", raw))
		}
		out.interpreter = interp
	case "login":
		lm, err := execution.ParseLoginMode(raw)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--login"), i18n.BoundStr("value", raw))
		}
		out.loginMode = lm
	case "workdir":
		rp, err := pathalg.ParseRemotePath(raw)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--workdir"), i18n.BoundStr("value", raw))
		}
		out.workDir = algebraic.Some(rp)
	case "env":
		k, v, err := clikit.ParseKeyValue("--env", raw)
		if err != nil {
			return err
		}
		out.envVars[k] = v
	}
	return nil
}

func parseExecPrivFlag(cur *clikit.FlagCursor, name, inlineVal string, hasEq bool, rawTok string, out *execArgs) error {
	switch name {
	case "sudo":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		if err == nil && v {
			out.privMethod = engine.PrivilegeMethodSudo
		}
		return err
	case "su":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		if err == nil && v {
			out.privMethod = engine.PrivilegeMethodSu
		}
		return err
	case "doas":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		if err == nil && v {
			out.privMethod = engine.PrivilegeMethodDoas
		}
		return err
	case "privilege-user", "sudo-user":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		out.privUser = raw
		return err
	case "password-ref":
		raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
		if err != nil {
			return err
		}
		ref, err := secret.ParseRef(raw)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--password-ref"), i18n.BoundStr("value", raw))
		}
		out.privPasswordRef = algebraic.Some(ref)
		return nil
	case "prompt-password":
		v, err := clikit.ParseOptionalBool(name, inlineVal, hasEq)
		out.promptPassword = v
		return err
	default:
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", rawTok))
	}
}

func finalizeExecArgs(out execArgs) (execArgs, error) {
	if !out.isBatch() && len(out.targets) == 0 {
		return execArgs{}, i18n.EF(clikit.ErrUsage, i18n.KeyCLIExecMissingTarget)
	}
	if len(out.commandArgs) == 0 {
		return execArgs{}, i18n.EF(clikit.ErrUsage, i18n.KeyCLIExecMissingCommand)
	}
	if out.isBatch() && out.privMethod.IsValid() {
		return execArgs{}, i18n.EF(clikit.ErrUsage, i18n.KeyCLIExecBatchPrivUnsupported)
	}
	if err := out.cliOpts.Validate(); err != nil {
		return execArgs{}, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidOptionLayer)
	}
	return out, nil
}

func buildExecCommandPlan(parsed execArgs) (cp execution.CommandPlan, err error) {
	prof, pErr := clikit.BuildLaunchProfile(parsed.dialect, parsed.interpreter, parsed.loginMode)
	if pErr != nil {
		return cp, pErr
	}
	spec := execution.CommandPlanSpec{
		Kind:           execution.PlanKindCommand,
		Profile:        prof,
		WorkDir:        parsed.workDir,
		Env:            parsed.envVars,
		Timeout:        parsed.timeout,
		MaxOutputBytes: parsed.maxOutputBytes,
		PTY:            parsed.requestTTY == engine.RequestTTYYes || parsed.requestTTY == engine.RequestTTYForce,
	}
	if len(parsed.commandArgs) == 1 {
		spec.Command = parsed.commandArgs[0]
	} else {
		spec.Command = strings.Join(parsed.commandArgs, " ")
	}
	built, cErr := execution.NewCommandPlan(spec)
	if cErr != nil {
		return cp, i18n.WrapS(clikit.ErrUsage, cErr, i18n.KeyCLIExecPlanFailed)
	}
	return built, nil
}

func runSingleExec(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed execArgs, cmdPlan execution.CommandPlan, jsonOut bool) int {
	client, err := requireSSHClient(runner)
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	var outBuf, errBuf bytes.Buffer
	stdout, stderr := rt.Stdout, rt.Stderr
	if jsonOut {
		stdout, stderr = &outBuf, &errBuf
	}
	if parsed.privMethod.IsValid() {
		return runPrivilegedExec(ctx, rt, client, parsed, cmdPlan, stdout, stderr, &outBuf, &errBuf, jsonOut)
	}
	outcome, runErr := client.Exec(ctx, engine.ExecRequest{
		TargetSpec:  parsed.targets[0],
		CLIOptions:  parsed.cliOpts,
		CommandPlan: algebraic.Some(cmdPlan),
		Stdin:       rt.Stdin,
		Stdout:      stdout,
		Stderr:      stderr,
		RequestTTY:  parsed.requestTTY,
	})
	return finishExecOutcome(rt, outcome, runErr, outBuf.String(), errBuf.String(), jsonOut)
}

func runPrivilegedExec(
	ctx context.Context,
	rt *clikit.Runtime,
	client clikit.SSHClient,
	parsed execArgs,
	cmdPlan execution.CommandPlan,
	stdout, stderr io.Writer,
	outBuf, errBuf *bytes.Buffer,
	jsonOut bool,
) int {
	var targetUserOpt algebraic.Option[option.Username]
	if strings.TrimSpace(parsed.privUser) != "" {
		u, uErr := option.ParseUsername(parsed.privUser)
		if uErr != nil {
			return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, uErr, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--privilege-user"), i18n.BoundStr("value", parsed.privUser)))
		}
		targetUserOpt = algebraic.Some(u)
	}
	privReq, pErr := engine.NewPrivilegeRequest(engine.PrivilegeRequestSpec{
		Method:     parsed.privMethod,
		TargetUser: targetUserOpt,
		Command:    cmdPlan,
	})
	if pErr != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, pErr, i18n.KeyCLIExecPlanFailed))
	}
	outcome, runErr := client.ExecPrivileged(ctx, engine.PrivilegeExecRequest{
		RemoteCall: engine.RemoteCall{
			TargetInput: engine.TargetInput{TargetSpec: parsed.targets[0], CLIOptions: parsed.cliOpts},
		},
		Privilege:      privReq,
		PasswordRef:    parsed.privPasswordRef,
		PromptPassword: parsed.promptPassword,
		Stdin:          rt.Stdin,
		Stdout:         stdout,
		Stderr:         stderr,
		RequestTTY:     parsed.requestTTY,
	})
	return finishExecOutcome(rt, outcome, runErr, outBuf.String(), errBuf.String(), jsonOut)
}

func finishExecOutcome(rt *clikit.Runtime, outcome execution.ExecutionOutcome, runErr error, stdoutText, stderrText string, jsonOut bool) int {
	loc := rt.Loc()
	if jsonOut {
		view, code, _ := clikit.BuildExecOutcomeViewLocalized(loc, outcome, runErr, stdoutText, stderrText)
		if mErr := clikit.WriteJSON(rt.Stdout, view); mErr != nil {
			rt.WriteErr(loc.T(i18n.KeyCLIMarshalJSONFailed, i18n.BoundStr("err", loc.RenderError(mErr))))
			return clikit.ExitGeneral
		}
		return code
	}
	code, diag, _ := clikit.MapOutcomeToExitLocalized(loc, outcome, runErr)
	if diag != "" {
		rt.WriteErr(diag)
	}
	return code
}
