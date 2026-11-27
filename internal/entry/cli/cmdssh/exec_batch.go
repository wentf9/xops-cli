package cmdssh

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

const defaultNodeStreamBuffer = 128

func runBatchExec(ctx context.Context, rt *clikit.Runtime, runner clikit.SessionRunner, parsed execArgs, cmdPlan execution.CommandPlan, jsonOut bool) int {
	client, err := requireAutomationClient(runner)
	if err != nil {
		return rt.Fail(clikit.ExitGeneral, jsonOut, err)
	}
	resolvedTargets, err := resolveBatchTargets(ctx, client, parsed.targets, parsed.cliOpts)
	if err != nil {
		return rt.Fail(clikit.ExitSSHError, jsonOut, err)
	}
	selOpt, err := buildBatchSelector(parsed)
	if err != nil {
		return rt.Fail(clikit.ExitUsage, jsonOut, err)
	}
	req := engine.BatchExecRequest{
		Targets:        resolvedTargets,
		Selector:       selOpt,
		CLIOptions:     parsed.cliOpts,
		ExcludeNodes:   parsed.excludeNodes,
		ExcludeTags:    parsed.excludeTags,
		Command:        cmdPlan,
		Concurrency:    parsed.concurrency,
		MaxOutputBytes: parsed.maxOutputBytes.OrElse(0),
		OutputDir:      parsed.outputDir,
		FailFast:       parsed.failFast,
	}
	rep, runErr, streamed := executeBatchWithOptionalStream(ctx, rt, client, req, parsed.stream && !jsonOut)
	return renderBatchExecResult(rt, rep, runErr, jsonOut, streamed)
}

func resolveBatchTargets(ctx context.Context, client clikit.AutomationClient, specs []string, cliOpts option.OptionLayer) ([]engine.ResolvedTarget, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	out := make([]engine.ResolvedTarget, 0, len(specs))
	for _, spec := range specs {
		res, err := client.ResolveTarget(ctx, engine.ResolveTargetRequest{Target: spec, CLIOptions: cliOpts})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildBatchSelector(parsed execArgs) (algebraic.Option[playbook.TargetSelector], error) {
	if !parsed.allNodes && len(parsed.nodeIDs) == 0 && len(parsed.tags) == 0 {
		return algebraic.None[playbook.TargetSelector](), nil
	}
	sel, err := playbook.NewTargetSelector(playbook.TargetSelectorSpec{
		All:          parsed.allNodes,
		Nodes:        parsed.nodeIDs,
		Tags:         parsed.tags,
		ExcludeNodes: parsed.excludeNodes,
		ExcludeTags:  parsed.excludeTags,
	})
	if err != nil {
		return algebraic.None[playbook.TargetSelector](), i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIExecSelectorInvalid)
	}
	return algebraic.Some(sel), nil
}

// executeBatchWithOptionalStream 在开启 --stream 时通过 req.NodeStreamFactory 为每个节点创建隔离的
// OperationStream（对齐 core/internal/usecase/automation/batch_exec.go 实时分块输出契约），
// 并使用 core/conc.RunWait + 互斥写锁并发排空节点流，确保无竞态、无静默回退与零协程泄漏。
func executeBatchWithOptionalStream(
	ctx context.Context,
	rt *clikit.Runtime,
	client clikit.AutomationClient,
	req engine.BatchExecRequest,
	stream bool,
) (engine.BatchExecReport, error, bool) {
	if !stream {
		rep, err := client.BatchExec(ctx, req)
		return rep, err, false
	}
	var rep engine.BatchExecReport
	var batchErr error
	var outMu sync.Mutex
	var streamedChunks atomic.Bool
	waitErr := conc.RunWait(ctx, func(waitCtx context.Context, n *conc.Nursery) error {
		req.NodeStreamFactory = newNodeStreamFactory(n, &outMu, rt.Stdout, rt.Stderr, &streamedChunks)
		rep, batchErr = client.BatchExec(waitCtx, req)
		return nil
	})
	if batchErr == nil && waitErr != nil {
		batchErr = waitErr
	}
	return rep, batchErr, streamedChunks.Load()
}

func newNodeStreamFactory(
	n *conc.Nursery,
	outMu *sync.Mutex,
	stdout, stderr io.Writer,
	streamedChunks *atomic.Bool,
) engine.NodeStreamFactory {
	return func(nodeID inventory.NodeID, traceID security.TraceID, opID security.OperationID) (*events.OperationStream, error) {
		st, err := events.NewOperationStream(events.OperationStreamConfig{
			TraceID:         traceID,
			OperationID:     opID,
			OperationBuffer: defaultNodeStreamBuffer,
		})
		if err != nil {
			return nil, err
		}
		if gErr := n.Go(func(c context.Context) error {
			drainStreamOutput(c, st, nodeID, outMu, stdout, stderr, streamedChunks)
			return nil
		}); gErr != nil {
			st.Close()
			return nil, gErr
		}
		return st, nil
	}
}

func drainStreamOutput(
	ctx context.Context,
	stream *events.OperationStream,
	fallbackNode inventory.NodeID,
	outMu *sync.Mutex,
	stdout, stderr io.Writer,
	streamedChunks *atomic.Bool,
) {
	for {
		ev, ok, err := stream.Next(ctx)
		if err != nil || !ok {
			return
		}
		chunk, isChunk := ev.(*events.OutputChunkEvent)
		if !isChunk || !chunk.IsValid() {
			continue
		}
		streamedChunks.Store(true)
		w := stdout
		if chunk.Stream() == events.OutputStreamStderr {
			w = stderr
		}
		label := fallbackNode
		if nodeID, hasNode := chunk.Meta().NodeID().Get(); hasNode && nodeID.IsValid() {
			label = nodeID
		}
		outMu.Lock()
		if label.IsValid() {
			_, _ = fmt.Fprintf(w, "[%s] %s", label, string(chunk.Data()))
		} else {
			_, _ = w.Write(chunk.Data())
		}
		outMu.Unlock()
	}
}

type batchExecJSONEnvelope struct {
	OK        bool                   `json:"ok"`
	Error     string                 `json:"error,omitzero"`
	ErrorCode string                 `json:"error_code,omitzero"`
	Report    engine.BatchExecReport `json:"report"`
}

func renderBatchExecResult(rt *clikit.Runtime, rep engine.BatchExecReport, runErr error, jsonOut, streamed bool) int {
	if !rep.IsValid() {
		return rt.Fail(clikit.ExitGeneral, jsonOut, runErr)
	}
	code := clikit.ExitOK
	if runErr != nil || rep.FailedCount() > 0 || rep.UnknownCount() > 0 || rep.NotStartedCount() > 0 {
		code = clikit.ExitGeneral
	}
	loc := rt.Loc()
	if jsonOut {
		env := batchExecJSONEnvelope{OK: code == clikit.ExitOK, Report: rep}
		if runErr != nil {
			env.Error = loc.RenderError(runErr)
			env.ErrorCode = clikit.ClassifyErrorCode(runErr)
		}
		if err := clikit.WriteJSON(rt.Stdout, env); err != nil {
			rt.WriteErr(loc.T(i18n.KeyCLIMarshalJSONFailed, i18n.BoundStr("err", loc.RenderError(err))))
			return clikit.ExitGeneral
		}
		return code
	}
	for _, nr := range rep.Results() {
		writeBatchNodeResult(rt, loc, nr, streamed)
	}
	_, _ = fmt.Fprintln(rt.Stdout, loc.T(
		i18n.KeyCLIExecBatchSummary,
		i18n.Int("succeeded", rep.SucceededCount()),
		i18n.Int("failed", rep.FailedCount()),
		i18n.Int("unknown", rep.UnknownCount()),
		i18n.Int("not_started", rep.NotStartedCount()),
		i18n.Str("duration", rep.Duration().String()),
	))
	if runErr != nil {
		rt.WriteErr(loc.RenderError(runErr))
	}
	return code
}

func writeBatchNodeResult(rt *clikit.Runtime, loc *i18n.Localizer, nr engine.BatchNodeResult, streamed bool) {
	_, _ = fmt.Fprintln(rt.Stdout, loc.T(
		i18n.KeyCLIExecBatchNodeHeader,
		i18n.BoundStr("node", nr.NodeID().String()),
		i18n.BoundStr("status", localizeBatchNodeStatus(loc, nr)),
		i18n.Str("duration", nr.Duration().String()),
	))
	if !streamed && len(nr.Stdout()) > 0 {
		_, _ = rt.Stdout.Write(nr.Stdout())
	}
	if !streamed && len(nr.Stderr()) > 0 {
		_, _ = rt.Stderr.Write(nr.Stderr())
	}
	if nr.ErrorMessage() != "" {
		rt.WriteErr(fmt.Sprintf("%s: %s", nr.NodeID(), nr.ErrorMessage()))
	}
}

func localizeBatchNodeStatus(loc *i18n.Localizer, nr engine.BatchNodeResult) string {
	if nr.Succeeded() {
		return loc.T(i18n.KeyCLIExecStatusOK)
	}
	if nr.Outcome() == nil {
		return loc.T(i18n.KeyCLIExecStatusFailed)
	}
	switch nr.Outcome().Kind() {
	case execution.OutcomeKindNotStarted:
		return loc.T(i18n.KeyCLIExecStatusNotStarted)
	case execution.OutcomeKindCompleted:
		return loc.T(i18n.KeyCLIExecStatusCompleted)
	case execution.OutcomeKindUnknown:
		return loc.T(i18n.KeyCLIExecStatusUnknown)
	default:
		return loc.T(i18n.KeyCLIExecStatusFailed)
	}
}

func appendParsedNodeIDs(cur *clikit.FlagCursor, name, inlineVal string, hasEq bool, dst *[]inventory.NodeID) error {
	raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	for _, item := range clikit.SplitCSV(raw) {
		id, err := inventory.ParseNodeID(item)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.BoundStr("flag", "--"+name), i18n.BoundStr("value", item))
		}
		*dst = append(*dst, id)
	}
	return nil
}

func appendParsedTags(cur *clikit.FlagCursor, name, inlineVal string, hasEq bool, dst *[]inventory.Tag) error {
	raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	for _, item := range clikit.SplitCSV(raw) {
		tag, err := inventory.ParseTag(item)
		if err != nil {
			return i18n.WrapS(clikit.ErrUsage, err, i18n.KeyCLIInvalidFlagValue, i18n.BoundStr("flag", "--"+name), i18n.BoundStr("value", item))
		}
		*dst = append(*dst, tag)
	}
	return nil
}
