package i18nguard_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/i18nguard"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestI18nGuardM1StagedScope(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		i18nguard.NewAnalyzer(),
		"github.com/wentf9/xops-cli/core/domain/i18n",
		"github.com/wentf9/xops-cli/internal/i18n",
		"github.com/wentf9/xops-cli/core/engine",
		"github.com/wentf9/xops-cli/core/ports/tck",
		"github.com/wentf9/xops-cli/core/internal/sim",
		"github.com/wentf9/xops-cli/tools/xopsvet/sample",
	)
}
