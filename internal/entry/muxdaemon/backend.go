package muxdaemon

import (
	"context"

	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
)

// masterLease / forwardLease / daemonBackend 为包内可测试窄缝，
// 生产路径 100% 直接委托给 *engine.Engine、engine.ControlMasterInfo 与 engine.ForwardInfo。
type (
	masterLease interface {
		SocketPath() string
		ReusedExisting() bool
		MasterPID() uint32
		EffectivePersist() option.ControlPersistSpec
		Done() <-chan struct{}
		Wait(ctx context.Context) error
		Stop(ctx context.Context) error
	}
	forwardLease interface {
		Spec() engine.ForwardSpec
		BoundAddr() string
		Done() <-chan struct{}
		Wait(ctx context.Context) error
		Stop(ctx context.Context) error
	}
	daemonBackend interface {
		StartMaster(ctx context.Context, rc engine.RemoteCall) (masterLease, error)
		StartForward(ctx context.Context, rc engine.RemoteCall, spec engine.ForwardSpec) (forwardLease, error)
	}
)

type engineBackend struct {
	client DaemonClient
}

func (b engineBackend) StartMaster(ctx context.Context, rc engine.RemoteCall) (masterLease, error) {
	info, err := b.client.StartControlMaster(ctx, engine.ControlMasterRequest{RemoteCall: rc})
	if err != nil {
		return nil, err
	}
	return engineMasterLease{client: b.client, info: info}, nil
}

func (b engineBackend) StartForward(ctx context.Context, rc engine.RemoteCall, spec engine.ForwardSpec) (forwardLease, error) {
	info, err := b.client.StartForward(ctx, engine.StartForwardRequest{RemoteCall: rc, Spec: spec})
	if err != nil {
		return nil, err
	}
	return engineForwardLease{client: b.client, info: info}, nil
}

type engineMasterLease struct {
	client DaemonClient
	info   engine.ControlMasterInfo
}

func (l engineMasterLease) SocketPath() string { return l.info.SocketPath().String() }
func (l engineMasterLease) ReusedExisting() bool {
	return l.info.ReusedExisting()
}
func (l engineMasterLease) MasterPID() uint32 { return l.info.MasterPID() }
func (l engineMasterLease) EffectivePersist() option.ControlPersistSpec {
	return l.info.EffectivePersist()
}
func (l engineMasterLease) Done() <-chan struct{}          { return l.info.Done() }
func (l engineMasterLease) Wait(ctx context.Context) error { return l.info.Wait(ctx) }
func (l engineMasterLease) Stop(ctx context.Context) error {
	if l.info.ReusedExisting() {
		return nil
	}
	h, ok := l.info.Handle().Get()
	if !ok || !h.IsValid() {
		return nil
	}
	return l.client.StopControlMaster(ctx, h)
}

type engineForwardLease struct {
	client DaemonClient
	info   engine.ForwardInfo
}

func (l engineForwardLease) Spec() engine.ForwardSpec       { return l.info.Spec() }
func (l engineForwardLease) BoundAddr() string              { return l.info.BoundAddr() }
func (l engineForwardLease) Done() <-chan struct{}          { return l.info.Done() }
func (l engineForwardLease) Wait(ctx context.Context) error { return l.info.Wait(ctx) }
func (l engineForwardLease) Stop(ctx context.Context) error {
	h := l.info.Handle()
	if !h.IsValid() {
		return nil
	}
	return l.client.StopForward(ctx, h)
}
