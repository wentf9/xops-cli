package good_test

import (
	"testing"

	"github.com/wentf9/xops-cli/core/domain/good"
	"github.com/wentf9/xops-cli/core/internal/sim"
)

func TestGoodExternal(t *testing.T) {
	_ = sim.SimFS{}
	if good.UseAllAllowedStdlibs() == 0 {
		t.Fatal("zero")
	}
}
