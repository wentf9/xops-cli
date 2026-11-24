package badconc

import (
	"testing"

	"github.com/wentf9/xops-cli/core/internal/sim" // want "架构边界违规：当前层禁止导入"
)

func TestConcCannotImportSim(t *testing.T) {
	_ = sim.SimFS{}
}
