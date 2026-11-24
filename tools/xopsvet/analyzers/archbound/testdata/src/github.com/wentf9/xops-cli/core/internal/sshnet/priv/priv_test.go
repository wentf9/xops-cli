package priv

import (
	"testing"

	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"go.uber.org/goleak"
)

func TestPrivAllowsTCKSimGoleak(t *testing.T) {
	goleak.VerifyNone(t)
	_ = sim.SimFS{}
	tck.CheckRootFS(t, nil)
}
