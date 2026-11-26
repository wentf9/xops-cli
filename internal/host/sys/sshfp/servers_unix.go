//go:build unix

package sshfp

import (
	"context"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	unixResolvConfPath = "/etc/resolv.conf"
	maxResolvConfBytes = 64 * 1024
)

func loadSystemDNSConfigOS(ctx context.Context, opFS ports.OperatorReadFS) (dnsSystemConfig, error) {
	srcPath, err := pathalg.ParseLocalSourcePath(unixResolvConfPath)
	if err != nil {
		return dnsSystemConfig{}, err
	}
	var raw []byte
	err = opFS.WithOperatorRead(ctx, srcPath, pathalg.SymlinkFollowOperatorSource, func(r ports.BoundedReadHandle, _ int64) error {
		var rErr error
		raw, rErr = io.ReadAll(io.LimitReader(r, maxResolvConfBytes))
		return rErr
	})
	if err != nil {
		return dnsSystemConfig{}, fmt.Errorf("通过 OperatorReadFS 读取 %s 失败: %w", unixResolvConfPath, err)
	}
	servers, trustAD := ParseResolvConf(raw)
	if len(servers) == 0 {
		return dnsSystemConfig{}, fmt.Errorf("%w: %s 未包含可用 nameserver", ports.ErrNotFound, unixResolvConfPath)
	}
	return dnsSystemConfig{servers: servers, trustAD: trustAD}, nil
}
