//go:build linux

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
)

func TestDoctorSystemMissingDependency(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus")
	item := checkDoctorStore(t.Context(), "system", config.StoreConfig{Type: config.StoreTypeSystem})
	if item.Status != "FAIL" || !strings.Contains(item.Message, "libsecret-tools") {
		t.Fatalf("missing dependency passed: %+v", item)
	}
	item = checkUnconfiguredSystemStore(t.Context())
	if item.Status != "WARN" || !strings.Contains(item.Message, "libsecret-tools") {
		t.Fatalf("implicit destination not diagnosed: %+v", item)
	}
}

func TestDoctorSystemRejectsDeadBus(t *testing.T) {
	dir := t.TempDir()
	// A successful executable lookup must not be mistaken for a working service.
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(dir, "missing-bus"))
	item := checkDoctorStore(t.Context(), "system", config.StoreConfig{Type: config.StoreTypeSystem})
	if item.Status != "FAIL" || !strings.Contains(item.Message, "connect bus") {
		t.Fatalf("dead bus passed: %+v", item)
	}
}
