//go:build windows

package ssh

import (
	"fmt"
	"io"
	"os"
)

// Native Windows console ownership belongs to the application input bridge.
func copyStdinTo(_ *os.File, _ io.Writer) (func() error, <-chan error, error) {
	return nil, nil, fmt.Errorf("Windows file input requires an input bridge: %w", ErrInteractionRequired)
}
