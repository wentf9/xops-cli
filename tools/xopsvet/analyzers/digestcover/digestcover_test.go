package digestcover_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/digestcover"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestDigestCover(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		digestcover.NewAnalyzer(),
		"example.com/extbase",
		"example.com/hashes",
	)
}
