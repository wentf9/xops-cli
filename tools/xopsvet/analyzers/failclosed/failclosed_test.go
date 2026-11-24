package failclosed_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/failclosed"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestFailClosed(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		failclosed.NewAnalyzer(),
		"example.com/opaquedef",
		"example.com/consumer",
		"example.com/errswallow",
		"example.com/zerocheck",
	)
}
