package cmdops

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

const defaultAuditListLimit = 50

// RunAudit 执行 `xops audit` 命令族：reconcile（调用 Engine.ReconcileCrashedAudits）与 list/tail/inspect（经宿主只读钩子）。
func RunAudit(ctx context.Context, rt *clikit.Runtime, args []string) int {
	d := rt.PrepareSubcommand("audit", args, AuditHelpText)
	if d.Handled {
		return d.ExitCode
	}
	rt, sub, rest := d.RT, d.Sub, d.Rest
	switch sub {
	case "reconcile":
		return runAuditReconcile(ctx, rt, rest)
	case "list", "tail":
		return runAuditQuery(ctx, rt, sub, rest)
	case "inspect":
		return runAuditInspect(ctx, rt, rest)
	default:
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("audit", rest)), i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownSubcommand, i18n.Str("cmd", "audit"), i18n.BoundStr("sub", sub)))
	}
}

func runAuditReconcile(ctx context.Context, rt *clikit.Runtime, args []string) int {
	var common clikit.CommonFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &common); err != nil || consumed {
			if err != nil {
				return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("audit", args)), err)
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			common.ShowHelp = true
			break
		}
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("audit", args)), i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnexpectedArg, i18n.BoundStr("arg", tok)))
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, AuditHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	initOpts := rt.EffectiveInitOptions(common.ConfigFile, common.Policy)
	return rt.WithEngine(ctx, initOpts, clikit.ExitGeneral, jsonOut, func(runner clikit.SessionRunner) int {
		client, err := requireReconcileClient(runner)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		rep, err := client.ReconcileCrashedAudits(ctx)
		if err != nil {
			return rt.Fail(clikit.ExitGeneral, jsonOut, err)
		}
		loc := rt.Loc()
		return rt.WriteResult(jsonOut, rep, func(w io.Writer) {
			_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLIAuditReconcileSummary,
				i18n.Int("scanned", rep.ScannedLocks()),
				i18n.Int("live", rep.LiveLocksSkipped()),
				i18n.Int("dead_claimed", rep.DeadLocksClaimed()),
				i18n.Int("aborted", len(rep.AbortedOperations())),
			))
		})
	})
}

func runAuditQuery(ctx context.Context, rt *clikit.Runtime, sub string, args []string) int {
	var common clikit.CommonFlags
	req := clikit.AuditQueryRequest{Limit: defaultAuditListLimit, Tail: sub == "tail"}
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &common); err != nil || consumed {
			if err != nil {
				return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("audit", args)), err)
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			common.ShowHelp = true
			break
		}
		if err := parseAuditQueryFlag(cur, tok, &req); err != nil {
			return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("audit", args)), err)
		}
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, AuditHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	return executeAuditRead(ctx, rt, req, jsonOut)
}

func parseAuditQueryFlag(cur *clikit.FlagCursor, rawTok string, req *clikit.AuditQueryRequest) error {
	name, inlineVal, hasEq, isLong := clikit.ParseLongFlagName(rawTok)
	if !isLong {
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnexpectedArg, i18n.BoundStr("arg", rawTok))
	}
	val, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	switch name {
	case "limit":
		req.Limit, err = clikit.ParsePositiveInt("--limit", val)
		return err
	case "phase":
		return setValidatedAuditPhase(&req.Phase, val)
	case "outcome":
		return setValidatedAuditOutcome(&req.Outcome, val)
	case "node":
		req.NodeID = strings.TrimSpace(val)
	case "op-id":
		id, err := security.ParseOperationID(val)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--op-id"), i18n.BoundStr("value", val))
		}
		req.OperationID = algebraic.Some(id)
	case "trace-id":
		id, err := security.ParseTraceID(val)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.Str("flag", "--trace-id"), i18n.BoundStr("value", val))
		}
		req.TraceID = algebraic.Some(id)
	default:
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", rawTok))
	}
	return nil
}

func setValidatedAuditPhase(dst *string, raw string) error {
	p := strings.ToLower(strings.TrimSpace(raw))
	switch p {
	case "denied", "authorized", "finalized":
		*dst = p
		return nil
	default:
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIInvalidFlagValueEnum, i18n.Str("flag", "--phase"), i18n.Str("allowed", "denied|authorized|finalized"), i18n.BoundStr("value", raw))
	}
}

func setValidatedAuditOutcome(dst *string, raw string) error {
	o := strings.ToLower(strings.TrimSpace(raw))
	switch o {
	case "pending", "denied", "succeeded", "failed", "canceled", "escalated", "aborted_by_crash", "outcome_unknown":
		*dst = o
		return nil
	default:
		return i18n.EF(clikit.ErrUsage, i18n.KeyCLIInvalidFlagValueEnum, i18n.Str("flag", "--outcome"), i18n.Str("allowed", "pending|denied|succeeded|failed|canceled|escalated|aborted_by_crash|outcome_unknown"), i18n.BoundStr("value", raw))
	}
}

func runAuditInspect(ctx context.Context, rt *clikit.Runtime, args []string) int {
	var common clikit.CommonFlags
	var pos []string
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &common); err != nil || consumed {
			if err != nil {
				return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("audit", args)), err)
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			common.ShowHelp = true
			break
		}
		if strings.HasPrefix(tok, "-") && tok != "-" {
			return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlagForCommand("audit", args)), i18n.EF(clikit.ErrUsage, i18n.KeyCLIUnknownLongFlag, i18n.BoundStr("flag", tok)))
		}
		pos = append(pos, tok)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, AuditHelpText(rt.Loc()))
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	if len(pos) != 1 {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.EF(clikit.ErrUsage, i18n.KeyCLIArgCountExact, i18n.Str("cmd", "audit inspect"), i18n.Int("count", 1), i18n.Str("usage", "<operation_id>")))
	}
	opID, err := security.ParseOperationID(pos[0])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidField, i18n.Str("field", "OperationID"), i18n.BoundStr("value", pos[0])))
	}
	return executeAuditRead(ctx, rt, clikit.AuditQueryRequest{Limit: defaultAuditListLimit, OperationID: algebraic.Some(opID)}, jsonOut)
}

func executeAuditRead(ctx context.Context, rt *clikit.Runtime, req clikit.AuditQueryRequest, jsonOut bool) int {
	if rt.Hooks.ReadAuditLog == nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, i18n.EF(clikit.ErrNotConfigured, i18n.KeyCLIHookNotConfigured, i18n.Str("hook", "ReadAuditLog")))
	}
	res, err := rt.Hooks.ReadAuditLog(ctx, req)
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	loc := rt.Loc()
	return rt.WriteResult(jsonOut, res, func(w io.Writer) {
		_, _ = fmt.Fprintln(w, loc.T(i18n.KeyCLIAuditEntriesSummary,
			i18n.Int("matched", res.TotalMatched),
			i18n.Int("shown", len(res.Entries)),
			i18n.Bool("truncated", res.Truncated),
		))
		for _, e := range res.Entries {
			_, _ = fmt.Fprintf(w, "  %s op=%s phase=%s outcome=%s risk=%s tool=%s/%s node=%s\n",
				e.Timestamp.UTC().Format("2006-01-02T15:04:05Z"), e.OperationID, e.Phase, e.Outcome, e.Risk, e.Tool, e.Action, e.NodeID)
		}
	})
}
