package mcpserver

import (
	"errors"
	"fmt"
	"io"
)

func joinCloseError(errp *error, closer io.Closer, resource string) {
	if closer == nil {
		return
	}
	if closeErr := closer.Close(); closeErr != nil {
		*errp = errors.Join(*errp, fmt.Errorf("close %s failed: %w", resource, closeErr))
	}
}
