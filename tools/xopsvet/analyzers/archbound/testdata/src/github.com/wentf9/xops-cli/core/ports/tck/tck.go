package tck

import (
	"testing"

	"github.com/wentf9/xops-cli/core/ports"
)

func CheckRootFS(t *testing.T, fs ports.ScopedRootFS) {
	t.Helper()
	_ = fs
}
