package mystery // want "未登记的 core/ 包路径"

import (
	"testing"

	_ "github.com/wentf9/xops-cli/core/internal/sim"
)

func TestMystery(t *testing.T) {}
