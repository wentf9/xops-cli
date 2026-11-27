package cmdssh

import (
	"context"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

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
	rep, runErr := executeBatchWithOptionalStream(ctx, rt, client, req, parsed.stream && !jsonOut)
	return renderBatchExecResult(rt, rep, runErr, jsonOut, parsed.stream)
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
		return algebraic.None[playbook.TargetSelector](), fmt.Errorf("%w: 目标选择器非法: %w", clikit.ErrUsage, err)
	}
	return algebraic.Some(sel), nil
}

// executeBatchWithOptionalStream 在开启 --stream 时创建隔离的 OperationStream，
// 并使用 core/conc.RunWait 并行排空实时事件流，确保 EOF 后确定性收敛且零协程泄漏。
func executeBatchWithOptionalStream(ctx context.Context, rt *clikit.Runtime, client clikit.AutomationClient, req engine.BatchExecRequest, stream bool) (engine.BatchExecReport, error) {
	if !stream {
		return client.BatchExec(ctx, req)
	}
	opStream, err := client.NewOperationStream(ctx, 128)
	if err != nil {
		return client.BatchExec(ctx, req)
	}
	req.OperationStream = opStream
	var rep engine.BatchExecReport
	var batchErr error
	_ = conc.RunWait(ctx, func(waitCtx context.Context, n *conc.Nursery) error {
		if err := n.Go(func(c context.Context) error {
			drainStreamOutput(c, opStream, rt.Stdout, rt.Stderr)
			return nil
		}); err != nil {
			opStream.Close()
			return err
		}
		rep, batchErr = client.BatchExec(waitCtx, req)
		opStream.Close()
		return nil
	})
	return rep, batchErr
}

func drainStreamOutput(ctx context.Context, stream *events.OperationStream, stdout, stderr io.Writer) {
	for {
		ev, ok, err := stream.Next(ctx)
		if err != nil || !ok {
			return
		}
		chunk, isChunk := ev.(*events.OutputChunkEvent)
		if !isChunk || !chunk.IsValid() {
			continue
		}
		w := stdout
		if chunk.Stream() == events.OutputStreamStderr {
			w = stderr
		}
		if nodeID, hasNode := chunk.Meta().NodeID().Get(); hasNode && nodeID.IsValid() {
			_, _ = fmt.Fprintf(w, "[%s] %s", nodeID, string(chunk.Data()))
		} else {
			_, _ = w.Write(chunk.Data())
		}
	}
}

func renderBatchExecResult(rt *clikit.Runtime, rep engine.BatchExecReport, runErr error, jsonOut, streamed bool) int {
	if !rep.IsValid() {
		return rt.Fail(clikit.ExitGeneral, jsonOut, runErr)
	}
	code := clikit.ExitOK
	if runErr != nil || rep.FailedCount() > 0 || rep.UnknownCount() > 0 || rep.NotStartedCount() > 0 {
		code = clikit.ExitGeneral
	}
	if jsonOut {
		if err := clikit.WriteJSON(rt.Stdout, rep); err != nil {
			rt.WriteErr("marshal json failed: " + err.Error())
			return clikit.ExitGeneral
		}
		return code
	}
	for _, nr := range rep.Results() {
		writeBatchNodeResult(rt, nr, streamed)
	}
	_, _ = fmt.Fprintf(rt.Stdout, "summary: succeeded=%d failed=%d unknown=%d not_started=%d duration=%s\n",
		rep.SucceededCount(), rep.FailedCount(), rep.UnknownCount(), rep.NotStartedCount(), rep.Duration())
	return code
}

func writeBatchNodeResult(rt *clikit.Runtime, nr engine.BatchNodeResult, streamed bool) {
	status := "ok"
	if !nr.Succeeded() {
		status = nr.Outcome().Kind().String()
	}
	_, _ = fmt.Fprintf(rt.Stdout, "== %s [%s] (%s) ==\n", nr.NodeID(), status, nr.Duration())
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

func appendParsedNodeIDs(cur *clikit.FlagCursor, name, inlineVal string, hasEq bool, dst *[]inventory.NodeID) error {
	raw, err := cur.ConsumeLongValue(name, inlineVal, hasEq)
	if err != nil {
		return err
	}
	for _, item := range clikit.SplitCSV(raw) {
		id, err := inventory.ParseNodeID(item)
		if err != nil {
			return fmt.Errorf("%w: --%s 节点标识 %q 非法: %w", clikit.ErrUsage, name, item, err)
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
			return fmt.Errorf("%w: --%s 标签 %q 非法: %w", clikit.ErrUsage, name, item, err)
		}
		*dst = append(*dst, tag)
	}
	return nil
}
