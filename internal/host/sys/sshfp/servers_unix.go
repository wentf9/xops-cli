//go:build unix

package sshfp

import (
	"context"
	"io"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
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
		return dnsSystemConfig{}, i18n.Wrap(err, i18n.KeyHostReadFailed, i18n.Str("path", unixResolvConfPath))
	}
	servers, trustAD := ParseResolvConf(raw)
	if len(servers) == 0 {
		return dnsSystemConfig{}, i18n.EF(ports.ErrNotFound, i18n.KeyHostSSHFPNoServers)
	}
	return dnsSystemConfig{servers: servers, trustAD: trustAD}, nil
}
