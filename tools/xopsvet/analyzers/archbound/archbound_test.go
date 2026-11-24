package archbound_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/archbound"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestArchBound(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		archbound.NewAnalyzer(),
		"github.com/wentf9/xops-cli/core/domain/algebraic",
		"github.com/wentf9/xops-cli/core/domain/good",
		"github.com/wentf9/xops-cli/core/domain/badstdlib",
		"github.com/wentf9/xops-cli/core/domain/badtime",
		"github.com/wentf9/xops-cli/core/ports",
		"github.com/wentf9/xops-cli/core/ports/tck",
		"github.com/wentf9/xops-cli/core/events",
		"github.com/wentf9/xops-cli/core/events/badevents",
		"github.com/wentf9/xops-cli/core/osfs",
		"github.com/wentf9/xops-cli/core/osfs/badosfs",
		"github.com/wentf9/xops-cli/core/internal/foundation/conc",
		"github.com/wentf9/xops-cli/core/internal/foundation/trace",
		"github.com/wentf9/xops-cli/core/internal/pool",
		"github.com/wentf9/xops-cli/core/internal/pool/badpool",
		"github.com/wentf9/xops-cli/core/internal/gate",
		"github.com/wentf9/xops-cli/core/internal/gate/badgate",
		"github.com/wentf9/xops-cli/core/internal/sshnet/dial",
		"github.com/wentf9/xops-cli/core/internal/sim",
		"github.com/wentf9/xops-cli/core/internal/usecase/session",
		"github.com/wentf9/xops-cli/core/internal/usecase/baduc",
		"github.com/wentf9/xops-cli/core/internal/mcpruntime",
		"github.com/wentf9/xops-cli/core/internal/mcpruntime/badmcp",
		"github.com/wentf9/xops-cli/core/engine",
		"github.com/wentf9/xops-cli/internal/host/sys",
		"github.com/wentf9/xops-cli/internal/host/badhost",
		"github.com/wentf9/xops-cli/internal/entry/cli",
		"github.com/wentf9/xops-cli/internal/entry/badentry",
		"github.com/wentf9/xops-cli/cmd/xops",
	)
}
