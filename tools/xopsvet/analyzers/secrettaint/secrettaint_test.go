package secrettaint_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/secrettaint"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestSecretTaint(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		secrettaint.NewAnalyzer(),
		"github.com/wentf9/xops-cli/core/domain/secret",
		"github.com/wentf9/xops-cli/core/domain/secret_test",
		"github.com/wentf9/xops-cli/internal/host/vault",
		"github.com/wentf9/xops-cli/core/internal/sshnet/dial",
		"github.com/wentf9/xops-cli/core/internal/sshnet/priv",
		"github.com/wentf9/xops-cli/core/internal/sim",
		"github.com/wentf9/xops-cli/core/events",
		"github.com/wentf9/xops-cli/core/domain/plan",
		"github.com/wentf9/xops-cli/core/internal/usecase/credential",
	)
}
