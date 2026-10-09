//go:build !linux

package ssh

import (
	"context"
	"fmt"
	"io"
	"os"
)

// Native owned output handles need platform acceptance before exposure. Legacy
// terminal entry points retain their existing I/O until that adapter migrates.
func prepareFileOutput(_ context.Context, _ *os.File) (io.Writer, func() error, error) {
	return nil, nil, fmt.Errorf("cancelable native PTY output is not validated on this platform: provide a ContextWriter")
}
