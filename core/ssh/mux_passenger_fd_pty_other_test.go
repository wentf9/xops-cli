//go:build darwin || freebsd

package ssh

import (
	"os"
	"testing"
)

func saturatePTYMasterInput(*testing.T, *os.File, *os.File) {}
