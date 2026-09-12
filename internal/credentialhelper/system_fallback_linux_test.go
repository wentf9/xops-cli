//go:build linux

package credentialhelper

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestLinuxMissingSecretToolDoesNotFallbackToSelf(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus")
	_, err := NewSystemStore("system", SystemStoreConfig{})
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) || !strings.Contains(err.Error(), "install libsecret-tools") {
		t.Fatalf("expected actionable missing dependency error, got %v", err)
	}
}

func TestLinuxMissingSecretToolUsesExternalHelper(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' '{\"code\":\"not-found\"}'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, DefaultSystemHelperCommand), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus")
	st, err := NewSystemStore("system", SystemStoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Get(t.Context(), credential.Ref{StoreID: "system", ItemID: "probe"})
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("external helper was not used: %v", err)
	}
}
