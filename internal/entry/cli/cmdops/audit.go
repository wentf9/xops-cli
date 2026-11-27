package cmdops

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

const defaultAuditListLimit = 50

// RunAudit 执行 `xops audit` 命令族：reconcile（调用 Engine.ReconcileCrashedAudits）与 list/tail/inspect（经宿主只读钩子）。
func RunAudit(ctx context.Context, rt *clikit.Runtime, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, _ = io.WriteString(rt.Stdout, AuditHelpText())
		return clikit.ExitOK
	}
	switch args[0] {
	case "reconcile":
		return runAuditReconcile(ctx, rt, args[1:])
	case "list", "tail":
		return runAuditQuery(ctx, rt, args[0], args[1:])
	case "inspect":
		return runAuditInspect(ctx, rt, args[1:])
	default:
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args[1:])), fmt.Errorf("%w: 未知 audit 子命令 %q", clikit.ErrUsage, args[0]))
	}
}

func runAuditReconcile(ctx context.Context, rt *clikit.Runtime, args []string) int {
	var common clikit.CommonFlags
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &common); err != nil || consumed {
			if err != nil {
				return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			common.ShowHelp = true
			break
		}
		return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), fmt.Errorf("%w: audit reconcile 未知参数 %q", clikit.ErrUsage, tok))
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, AuditHelpText())
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
		return rt.WriteResult(jsonOut, rep, func(w io.Writer) {
			_, _ = fmt.Fprintf(w, "audit reconcile: scanned=%d live=%d dead_claimed=%d aborted=%d\n",
				rep.ScannedLocks(), rep.LiveLocksSkipped(), rep.DeadLocksClaimed(), len(rep.AbortedOperations()))
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
				return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			common.ShowHelp = true
			break
		}
		if err := parseAuditQueryFlag(cur, tok, sub, &req); err != nil {
			return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
		}
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, AuditHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	return executeAuditRead(ctx, rt, req, jsonOut)
}

func parseAuditQueryFlag(cur *clikit.FlagCursor, rawTok, sub string, req *clikit.AuditQueryRequest) error {
	name, inlineVal, hasEq, isLong := clikit.ParseLongFlagName(rawTok)
	if !isLong {
		return fmt.Errorf("%w: audit %s 未知参数 %q", clikit.ErrUsage, sub, rawTok)
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
			return fmt.Errorf("%w: --op-id 非法: %w", clikit.ErrUsage, err)
		}
		req.OperationID = algebraic.Some(id)
	case "trace-id":
		id, err := security.ParseTraceID(val)
		if err != nil {
			return fmt.Errorf("%w: --trace-id 非法: %w", clikit.ErrUsage, err)
		}
		req.TraceID = algebraic.Some(id)
	default:
		return fmt.Errorf("%w: audit %s 未知选项 %q", clikit.ErrUsage, sub, rawTok)
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
		return fmt.Errorf("%w: --phase 必须为 denied|authorized|finalized，实际=%q", clikit.ErrUsage, raw)
	}
}

func setValidatedAuditOutcome(dst *string, raw string) error {
	o := strings.ToLower(strings.TrimSpace(raw))
	switch o {
	case "pending", "denied", "succeeded", "failed", "canceled", "escalated", "aborted_by_crash", "outcome_unknown":
		*dst = o
		return nil
	default:
		return fmt.Errorf("%w: --outcome 非法，实际=%q", clikit.ErrUsage, raw)
	}
}

func runAuditInspect(ctx context.Context, rt *clikit.Runtime, args []string) int {
	var common clikit.CommonFlags
	var pos []string
	cur := clikit.NewFlagCursor(args)
	for cur.HasNext() {
		if consumed, err := clikit.TryConsumeCommonLongFlag(cur, &common); err != nil || consumed {
			if err != nil {
				return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), err)
			}
			continue
		}
		tok := cur.Next()
		if tok == "-h" {
			common.ShowHelp = true
			break
		}
		if strings.HasPrefix(tok, "-") && tok != "-" {
			return rt.Fail(clikit.ExitUsage, rt.EffectiveJSON(clikit.HasJSONFlag(args)), fmt.Errorf("%w: audit inspect 未知选项 %q", clikit.ErrUsage, tok))
		}
		pos = append(pos, tok)
	}
	if common.ShowHelp {
		_, _ = io.WriteString(rt.Stdout, AuditHelpText())
		return clikit.ExitOK
	}
	jsonOut := rt.EffectiveJSON(common.JSON)
	if len(pos) != 1 {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: audit inspect 需要恰好 1 个 OperationID", clikit.ErrUsage))
	}
	opID, err := security.ParseOperationID(pos[0])
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, fmt.Errorf("%w: OperationID %q 非法: %w", clikit.ErrUsage, pos[0], err))
	}
	return executeAuditRead(ctx, rt, clikit.AuditQueryRequest{Limit: defaultAuditListLimit, OperationID: algebraic.Some(opID)}, jsonOut)
}

func executeAuditRead(ctx context.Context, rt *clikit.Runtime, req clikit.AuditQueryRequest, jsonOut bool) int {
	if rt.Hooks.ReadAuditLog == nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, fmt.Errorf("%w: 未注入 ReadAuditLog 宿主只读钩子，无法检索本地审计日志", clikit.ErrNotConfigured))
	}
	res, err := rt.Hooks.ReadAuditLog(ctx, req)
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	return rt.WriteResult(jsonOut, res, func(w io.Writer) {
		_, _ = fmt.Fprintf(w, "audit entries: matched=%d shown=%d truncated=%v\n", res.TotalMatched, len(res.Entries), res.Truncated)
		for _, e := range res.Entries {
			_, _ = fmt.Fprintf(w, "  %s op=%s phase=%s outcome=%s risk=%s tool=%s/%s node=%s\n",
				e.Timestamp.UTC().Format("2006-01-02T15:04:05Z"), e.OperationID, e.Phase, e.Outcome, e.Risk, e.Tool, e.Action, e.NodeID)
		}
	})
}
