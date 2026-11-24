package engine

import (
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"go.uber.org/goleak"
)

func TestEngineTestAllowsSimConcGoleak(t *testing.T) {
	goleak.VerifyNone(t)
	_ = conc.Nursery{}
	_ = sim.SimFS{}
}
