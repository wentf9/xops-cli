package tck

import (
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/ports"
	"go.uber.org/goleak"
)

func CheckRootFS(t *testing.T, fs ports.ScopedRootFS) {
	t.Helper()
	goleak.VerifyNone(t)
	_ = conc.Nursery{}
	_ = fs
}
