package engine_test

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
)

func TestEngine_PreResolvedTargetRejectsExtraResolveOptions(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newLoopbackRigBase(t, false)
	clientPub, keyPath := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_preresolved")
	srv := newLoopbackSSHServer(t, clientPub)
	eng := mustNewDirectLoopbackEngine(t, rig, srv, nil)
	defer closeEngineChecked(t, eng)

	resolved, err := eng.ResolveTarget(context.Background(), engine.ResolveTargetRequest{
		Target:     "ops@127.0.0.1:22025",
		CLIOptions: option.UnsetOptionLayer().WithIdentityFiles(mustIdentityPathList(t, keyPath)).WithIdentitiesOnly(true),
	})
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	authAgent, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent: %v", err)
	}
	cases := []engine.ExecRequest{
		{Target: resolved, Command: "uname", CLIOptions: option.UnsetOptionLayer().WithBatchMode(true)},
		{Target: resolved, Command: "uname", ExplicitOrigin: algebraic.Some(option.OriginAdHoc)},
		{Target: resolved, Command: "uname", ExplicitAuth: authAgent},
	}
	for i, req := range cases {
		out, execErr := eng.Exec(context.Background(), req)
		if !errors.Is(execErr, engine.ErrInvalidRequest) {
			t.Fatalf("case[%d] 预解析 Target 混传解析覆盖项期望 ErrInvalidRequest，实际=%v", i, execErr)
		}
		if ns, ok := out.(*execution.OutcomeNotStarted); !ok || ns.Phase() != execution.StartPhaseValidate {
			t.Fatalf("case[%d] 期望 OutcomeNotStarted(validate)，实际=%#v", i, out)
		}
	}
	if srv.dialCount.Load() != 0 {
		t.Fatalf("非法请求组合不得触发任何拨号，实际=%d", srv.dialCount.Load())
	}
}

func TestEngine_CloseInterruptsIdleLoopbackRawTerminalSessionNoLeak(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newLoopbackRigBase(t, true)
	rig.term.SetInput(nil)
	rig.term.SetBlockInputAfterData(true)

	clientPub, keyPath := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_close_idle")
	srv := newLoopbackSSHServer(t, clientPub)
	eng := mustNewDirectLoopbackEngine(t, rig, srv, nil)

	stream, err := eng.NewOperationStream(context.Background(), 32)
	if err != nil {
		t.Fatalf("NewOperationStream: %v", err)
	}
	cliOpts := option.UnsetOptionLayer().
		WithIdentityFiles(mustIdentityPathList(t, keyPath)).
		WithIdentitiesOnly(true).
		WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew)

	var out execution.ExecutionOutcome
	var runErr error
	var closeErr error
	var sawCompleted bool
	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			sawCompleted, closeErr = closeEngineOnFirstOutputChunk(eng, stream)
			return nil
		}); gErr != nil {
			return gErr
		}
		out, runErr = eng.InteractiveSSH(context.Background(), engine.InteractiveSSHRequest{
			TargetSpec:      "ops@127.0.0.1:22026",
			CLIOptions:      cliOpts,
			RequestTTY:      engine.RequestTTYAuto,
			OperationStream: stream,
		})
		return nil
	})
	if err != nil {
		t.Fatalf("RunWait: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("Engine.Close 在途取消应优雅收敛无错，实际=%v", closeErr)
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Engine.Close 取消在途原始终端会话期望 context.Canceled，实际=%v", runErr)
	}
	if unk, ok := out.(*execution.OutcomeUnknown); !ok || unk.Phase() != execution.ExecPhaseCanceled {
		t.Fatalf("期望 OutcomeUnknown(canceled)，实际=%#v", out)
	}
	if !sawCompleted {
		t.Fatalf("Engine.Close 取消在途会话后 OperationStream 仍应收到终态 OperationCompletedEvent(Succeeded=false)")
	}
}

func closeEngineOnFirstOutputChunk(eng *engine.Engine, stream *events.OperationStream) (sawCompleted bool, closeErr error) {
	closedTriggered := false
	for ev, iterErr := range stream.All(context.Background()) {
		if iterErr != nil {
			return false, iterErr
		}
		if ev.Kind() == events.EventKindOutputChunk && !closedTriggered {
			closedTriggered = true
			closeErr = eng.Close(context.Background())
		}
		if comp, ok := ev.(*events.OperationCompletedEvent); ok && !comp.Succeeded() {
			sawCompleted = true
		}
	}
	return sawCompleted, closeErr
}
