package secretfact_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestSecretFactExport(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, secretfact.NewAnalyzer(), "example.com/secretdef")
}
