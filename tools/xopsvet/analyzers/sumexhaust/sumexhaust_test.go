package sumexhaust_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/sumexhaust"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestSumExhaust(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		sumexhaust.NewAnalyzer(),
		"example.com/sumdef",
		"example.com/sumalias",
		"example.com/sumuse",
		"example.com/sumusealias",
		"github.com/wentf9/xops-cli/core/domain/security",
		"github.com/wentf9/xops-cli/core/internal/gate",
		"github.com/wentf9/xops-cli/core/ports/tck",
	)
}
