//go:build linux

package credentialhelper

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestLinuxNonInteractiveRejectsBeforeLaunchingSecretTool(t *testing.T) {
	store := &linuxNativeStore{storeID: "system", toolPath: "must-never-execute"}
	_, err := store.Get(credential.WithoutInteraction(t.Context()), credential.Ref{StoreID: "system", ItemID: "item"})
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("non-interactive Secret Service: %v", err)
	}
	if !strings.Contains(err.Error(), "cannot guarantee prompt-free") {
		t.Fatalf("backend was launched instead of rejecting policy: %v", err)
	}
}
