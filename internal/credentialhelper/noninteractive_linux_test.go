//go:build linux

package credentialhelper

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestLinuxNonInteractiveUsesBusWithoutLaunchingSecretTool(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/xops-test-bus")
	store := &linuxNativeStore{storeID: "system", toolPath: "must-never-execute"}
	_, err := store.Get(credential.WithoutInteraction(t.Context()), credential.Ref{StoreID: "system", ItemID: "item"})
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("non-interactive Secret Service: %v", err)
	}
	if !strings.Contains(err.Error(), "connect bus") {
		t.Fatalf("expected direct bus connection failure: %v", err)
	}
}
