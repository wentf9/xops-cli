package badpool_test

import (
	"testing"

	"github.com/wentf9/xops-cli/core/internal/pool/badpool"
	"github.com/wentf9/xops-cli/core/internal/sim"
)

func TestBadPoolExternal(t *testing.T) {
	_ = sim.SimFS{}
	_ = badpool.Bad{}
}
