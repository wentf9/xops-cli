package tun

import (
	"context"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/ports"
)

// driverOpener 为包内白盒 TCK 与单测预留的非导出底层设备打开缝隙，生产默认绑定 openLocalTUNOS。
type driverOpener func(ctx context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, string, error)

// SystemTUNDevice 实现 ports.TUNDevicePort，负责按平台协议打开本机 TUN/TAP 虚拟网卡；零值恒无效。
//
//xops:opaque
//xops:failclosed
type SystemTUNDevice struct {
	opener driverOpener
	valid  bool
}

// NewSystemTUNDevice 构造使用当前操作系统原生内核驱动的本机 TUN/TAP 适配器。
func NewSystemTUNDevice() *SystemTUNDevice {
	return &SystemTUNDevice{
		opener: openLocalTUNOS,
		valid:  true,
	}
}

func newSystemTUNDeviceWithOpener(opener driverOpener) *SystemTUNDevice {
	if opener == nil {
		return &SystemTUNDevice{}
	}
	return &SystemTUNDevice{
		opener: opener,
		valid:  true,
	}
}

// OpenLocalTUN 校验上下文与强类型 TUNSpec 后打开本机 TUN/TAP 虚拟网卡并返回双向帧流与实际接口名。
func (d *SystemTUNDevice) OpenLocalTUN(ctx context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, string, error) {
	if ctx == nil {
		return nil, "", ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if d == nil || !d.valid || d.opener == nil {
		return nil, "", fmt.Errorf("%w: SystemTUNDevice 未初始化", ports.ErrInvalidArgument)
	}
	if !spec.IsValid() {
		return nil, "", fmt.Errorf("%w: TUNSpec 无效", ports.ErrInvalidArgument)
	}
	return d.opener(ctx, spec)
}
