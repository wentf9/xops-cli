//go:build windows

package ssh

import (
	"context"
	"errors"
	"io"

	core "github.com/wentf9/xops-cli/core/ssh"
)

type windowsInputBridge struct{}

func platformInputBridge() core.InputBridge { return windowsInputBridge{} }

func (windowsInputBridge) Start(ctx context.Context, streams core.InteractiveIO, dst io.Writer) (core.InputCopy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cancel, done, err := copyStdinTo(streams.Stdin, dst)
	if err != nil {
		return nil, err
	}
	copy, err := core.NewInputCopy(ctx, cancel, done)
	if err != nil {
		return nil, errors.Join(err, cancel(), <-done)
	}
	return copy, nil
}
