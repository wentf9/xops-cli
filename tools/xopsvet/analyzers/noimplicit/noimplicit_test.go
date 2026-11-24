package noimplicit_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/noimplicit"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestNoImplicit(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		noimplicit.NewAnalyzer(),
		"github.com/wentf9/xops-cli/core/domain/algebraic",
		"github.com/wentf9/xops-cli/core/internal/foundation/trace",
		"github.com/wentf9/xops-cli/core/osfs",
		"github.com/wentf9/xops-cli/core/events",
		"github.com/wentf9/xops-cli/core/internal/mcpruntime",
		"github.com/wentf9/xops-cli/internal/host/audit",
		"example.com/violations",
	)
}
