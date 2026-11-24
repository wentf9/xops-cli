package secretbox_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/secretbox"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestSecretBox(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		secretbox.NewAnalyzer(secretfact.NewAnalyzer()),
		"github.com/wentf9/xops-cli/core/domain/secret",
		"github.com/wentf9/xops-cli/core/domain/secret_test",
		"github.com/wentf9/xops-cli/core/ports",
		"github.com/wentf9/xops-cli/core/events",
		"github.com/wentf9/xops-cli/core/domain/plan",
		"github.com/wentf9/xops-cli/internal/host/vault",
		"github.com/wentf9/xops-cli/core/internal/usecase/credential",
	)
}
