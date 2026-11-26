package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"go.uber.org/goleak"
)

// TestTCKTUNDevice 通过包内非导出 driverOpener 测试缝隙验证 SystemTUNDevice 完整通过 core/ports/tck.RunTUNDeviceSuite。
func TestTCKTUNDevice(t *testing.T) {
	defer goleak.VerifyNone(t)
	tck.RunTUNDeviceSuite(t, tck.TUNDeviceFixture{
		NewDevice: func(*testing.T) ports.TUNDevicePort {
			return newSystemTUNDeviceWithOpener(func(_ context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, string, error) {
				local, peer := net.Pipe()
				_ = peer.Close()
				prefix := "tun"
				if spec.Mode() == ports.TUNModeEthernet {
					prefix = "tap"
				}
				unit := spec.LocalUnit()
				if unit == ports.TUNUnitAny {
					unit = 0
				}
				return local, fmt.Sprintf("%s%d", prefix, unit), nil
			})
		},
		NewUnavailableDevice: func(*testing.T) ports.TUNDevicePort {
			return newSystemTUNDeviceWithOpener(func(context.Context, ports.TUNSpec) (io.ReadWriteCloser, string, error) {
				return nil, "", ports.ErrPermissionDenied
			})
		},
	})
}

// TestSystemTUNDeviceNativeSmoke 验证原生内核驱动在无特权/不支持环境下严格失败关闭，不发生 panic 或泄漏。
func TestSystemTUNDeviceNativeSmoke(t *testing.T) {
	defer goleak.VerifyNone(t)
	dev := NewSystemTUNDevice()
	spec, err := ports.NewTUNSpec(ports.TUNModePointToPoint, ports.TUNUnitAny, 0)
	if err != nil {
		t.Fatalf("NewTUNSpec 失败: %v", err)
	}
	rwc, iface, err := dev.OpenLocalTUN(context.Background(), spec)
	if err == nil {
		if iface == "" || rwc == nil {
			t.Fatalf("打开原生 TUN 成功但返回空接口或流: iface=%q", iface)
		}
		if cErr := rwc.Close(); cErr != nil {
			t.Fatalf("关闭原生 TUN 失败: %v", cErr)
		}
		return
	}
	if !errors.Is(err, ports.ErrPermissionDenied) && !errors.Is(err, ports.ErrUnsupported) {
		t.Fatalf("原生 TUN 失败须归一化为 ErrPermissionDenied 或 ErrUnsupported，实际得到: %v", err)
	}
}
