package muxdaemon_test

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/muxdaemon"
)

func zeroVal[T any]() (z T) { return z }

type stubDaemonClient struct {
	startMasterErr error
	seenReq        engine.ControlMasterRequest
}

func (s *stubDaemonClient) StartControlMaster(_ context.Context, req engine.ControlMasterRequest) (engine.ControlMasterInfo, error) {
	s.seenReq = req
	if s.startMasterErr != nil {
		return zeroVal[engine.ControlMasterInfo](), s.startMasterErr
	}
	return zeroVal[engine.ControlMasterInfo](), errors.New("unexpected success in stub")
}
func (s *stubDaemonClient) StopControlMaster(context.Context, plan.ManagedHandle[plan.KindMux]) error {
	return nil
}
func (s *stubDaemonClient) StartForward(context.Context, engine.StartForwardRequest) (engine.ForwardInfo, error) {
	return zeroVal[engine.ForwardInfo](), errors.New("unexpected")
}
func (s *stubDaemonClient) StopForward(context.Context, plan.ManagedHandle[plan.KindTunnel]) error {
	return nil
}

func TestRun_PublicValidationFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	var nilCtx context.Context
	if err := muxdaemon.Run(nilCtx, muxdaemon.Config{}); !errors.Is(err, muxdaemon.ErrNilContext) {
		t.Fatalf("nil ctx 期望 ErrNilContext，实际=%v", err)
	}
	if err := muxdaemon.Run(ctx, muxdaemon.Config{}); !errors.Is(err, muxdaemon.ErrInvalidConfig) {
		t.Fatalf("nil client 期望 ErrInvalidConfig，实际=%v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	stub := &stubDaemonClient{startMasterErr: errors.New("start failed")}
	if err := muxdaemon.Run(canceled, muxdaemon.Config{Client: stub, TargetSpec: "h1"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("已取消 ctx 期望 context.Canceled，实际=%v", err)
	}

	if err := muxdaemon.Run(ctx, muxdaemon.Config{Client: stub}); !errors.Is(err, muxdaemon.ErrInvalidConfig) {
		t.Fatalf("空目标期望 ErrInvalidConfig，实际=%v", err)
	}
	if err := muxdaemon.Run(ctx, muxdaemon.Config{
		Client:     stub,
		TargetSpec: "h1",
		Forwards:   []engine.ForwardSpec{zeroVal[engine.ForwardSpec]()},
	}); !errors.Is(err, muxdaemon.ErrInvalidConfig) {
		t.Fatalf("无效 ForwardSpec 期望 ErrInvalidConfig，实际=%v", err)
	}
	if err := muxdaemon.Run(ctx, muxdaemon.Config{
		Client:          stub,
		TargetSpec:      "h1",
		ShutdownTimeout: algebraic.Some(algebraic.ZeroDuration()),
	}); !errors.Is(err, muxdaemon.ErrInvalidConfig) {
		t.Fatalf("零 ShutdownTimeout 期望 ErrInvalidConfig，实际=%v", err)
	}

	// 验证自动补全 ControlMaster=yes 与显式 SocketPath -> ControlPath 映射。
	sock, err := pathalg.ParseLocalSourcePath("/tmp/xops-mux-public-test.sock")
	if err != nil {
		t.Fatalf("ParseLocalSourcePath: %v", err)
	}
	err = muxdaemon.Run(ctx, muxdaemon.Config{
		Client:     stub,
		TargetSpec: "deploy@host.internal",
		SocketPath: algebraic.Some(sock),
	})
	if !errors.Is(err, stub.startMasterErr) {
		t.Fatalf("应透传 StartControlMaster 错误，实际=%v", err)
	}
	ctrl := stub.seenReq.CLIOptions.Control()
	if !ctrl.Master().IsSet() || ctrl.Path().IsUnset() {
		t.Fatalf("应自动补全 ControlMaster 与 ControlPath，实际=%+v", ctrl)
	}
}
