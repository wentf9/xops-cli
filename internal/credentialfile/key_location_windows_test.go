//go:build windows && (amd64 || arm64)

package credentialfile

import (
	"errors"
	"github.com/wentf9/xops-cli/pkg/credential"
	"testing"
)

func TestWindowsWrappingKeyCanUseAnotherVolume(t *testing.T) {
	for _, key := range []string{`D:\keys\vault.key`, `\\server\keys\vault.key`} {
		if err := validateWrappingKeyLocation(`C:\vault`, Wrapping{Mode: "key-file", KeyFile: key}); err != nil {
			t.Fatalf("separate key volume rejected: %v", err)
		}
	}
	if err := validateWrappingKeyLocation(`C:\vault`, Wrapping{Mode: "key-file", KeyFile: `C:\vault\CURRENT`}); !errors.Is(err, credential.ErrCredentialAccessDenied) {
		t.Fatal("key inside vault accepted")
	}
}
