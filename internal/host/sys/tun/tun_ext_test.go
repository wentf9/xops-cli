package tun_test

import (
	"context"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/sys/tun"
	"go.uber.org/goleak"
)

// 编译期接口契约断言（ADR-002 / P4-T4）。
var _ ports.TUNDevicePort = (*tun.SystemTUNDevice)(nil)

// TestSystemTUNDeviceZeroValueFailsClosed 验证零值 SystemTUNDevice 严格失败关闭。
func TestSystemTUNDeviceZeroValueFailsClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zero tun.SystemTUNDevice
	spec, err := ports.NewTUNSpec(ports.TUNModePointToPoint, ports.TUNUnitAny, 0)
	if err != nil {
		t.Fatalf("NewTUNSpec 失败: %v", err)
	}
	if _, _, err := zero.OpenLocalTUN(context.Background(), spec); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 OpenLocalTUN 期望 ErrInvalidArgument，实际得到: %v", err)
	}
}
