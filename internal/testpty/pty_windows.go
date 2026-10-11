//go:build windows

package testpty

import (
	"errors"
	"os"
)

// Open returns an error on Windows where UNIX PTY pairs are not supported.
func Open() (*os.File, *os.File, error) {
	return nil, nil, errors.New("PTY is not supported on Windows")
}
