package osboundary_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/osboundary"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestOSBoundary(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		osboundary.NewAnalyzer(),
		"github.com/wentf9/xops-cli/core/domain/pathalg",
		"github.com/wentf9/xops-cli/core/osfs",
		"github.com/wentf9/xops-cli/internal/host/sys",
		"example.com/violations",
	)
}
