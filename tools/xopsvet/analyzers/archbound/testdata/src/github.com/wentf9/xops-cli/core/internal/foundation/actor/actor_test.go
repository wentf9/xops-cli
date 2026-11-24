package actor

import (
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"go.uber.org/goleak"
)

func TestActorAllowsConcGoleakSim(t *testing.T) {
	goleak.VerifyNone(t)
	_ = conc.Nursery{}
	_ = sim.SimFS{}
}
