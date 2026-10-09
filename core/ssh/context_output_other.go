//go:build !linux

package ssh

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

// Native owned output handles need platform acceptance before exposure. Legacy
// terminal entry points retain their existing I/O until that adapter migrates.
func prepareFileOutput(_ context.Context, _ *os.File, _ time.Duration) (io.Writer, func() error, error) {
	return nil, nil, fmt.Errorf("cancelable native output is not validated on %s: provide a ContextWriter", runtime.GOOS)
}
