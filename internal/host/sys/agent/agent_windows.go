//go:build windows

package agent

import (
	"context"
	"net"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	windowsDefaultAgentPipe = `\\.\pipe\openssh-ssh-agent`
	windowsPipePrefix       = `\\.\pipe\`
)

func defaultAgentTarget() string { return windowsDefaultAgentPipe }

func dialAgentPlatform(ctx context.Context, target string) (net.Conn, error) {
	norm := strings.ReplaceAll(target, "/", `\`)
	if strings.HasPrefix(strings.ToLower(norm), windowsPipePrefix) {
		conn, err := osfs.DialWindowsNamedPipeVerified(ctx, norm)
		if err != nil {
			return nil, mapAgentOpError(ctx, err)
		}
		return conn, nil
	}
	ctrlPath, err := osfs.ValidateControlSocketPath(target)
	if err != nil {
		return nil, domi18n.WrapSentinel(ports.ErrSignerUnavailable, err)
	}
	conn, _, err := osfs.DialUnixVerified(ctx, ctrlPath)
	if err != nil {
		return nil, mapAgentOpError(ctx, err)
	}
	return conn, nil
}
