package linearlease_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/linearlease"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestLinearLease(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		linearlease.NewAnalyzer(secretfact.NewAnalyzer()),
		"github.com/wentf9/xops-cli/core/conc",
		"github.com/wentf9/xops-cli/core/conc_test",
		"example.com/leasedef",
		"example.com/leaseuse",
	)
}
