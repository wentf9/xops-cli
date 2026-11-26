package secrettaint_test

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/secrettaint"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestSecretTaint(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		secrettaint.NewAnalyzer(secretfact.NewAnalyzer()),
		"github.com/wentf9/xops-cli/core/domain/secret",
		"github.com/wentf9/xops-cli/internal/host/vault",
		"github.com/wentf9/xops-cli/internal/host/vault/forge_add",
		"github.com/wentf9/xops-cli/internal/host/vault/forge_slice",
		"github.com/wentf9/xops-cli/internal/host/vault/forge_uintptr",
		"github.com/wentf9/xops-cli/internal/host/vault/forge_cast",
		"github.com/wentf9/xops-cli/internal/host/vault/forge_ptr",
		"github.com/wentf9/xops-cli/internal/host/vault/wincred",
		"github.com/wentf9/xops-cli/internal/host/vault/keychain",
		"github.com/wentf9/xops-cli/internal/host/vault/secretservice",
		"github.com/wentf9/xops-cli/internal/host/vault/helper",
		"github.com/wentf9/xops-cli/core/internal/sshnet/dial",
		"github.com/wentf9/xops-cli/core/internal/sshnet/priv",
		"github.com/wentf9/xops-cli/core/internal/sim",
	)
}
