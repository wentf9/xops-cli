package i18nguard

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestI18nGuardFullScopeAndConcWhitelist(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		newAnalyzer(true),
		"github.com/wentf9/xops-cli/core/conc",
		"github.com/wentf9/xops-cli/internal/entry/cli",
		"github.com/wentf9/xops-cli/core/ports/tck",
		"github.com/wentf9/xops-cli/core/internal/sim",
		"github.com/wentf9/xops-cli/tools/xopsvet/sample",
	)
}
