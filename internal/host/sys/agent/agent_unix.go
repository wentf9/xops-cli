//go:build unix

package agent

import (
	"context"
	"fmt"
	"net"

	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

func defaultAgentTarget() string { return "" }

func dialAgentPlatform(ctx context.Context, target string) (net.Conn, error) {
	ctrlPath, err := osfs.ValidateControlSocketPath(target)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ports.ErrSignerUnavailable, err)
	}
	conn, _, err := osfs.DialUnixVerified(ctx, ctrlPath)
	if err != nil {
		return nil, mapAgentOpError(ctx, err)
	}
	return conn, nil
}
