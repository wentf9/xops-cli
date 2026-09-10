package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedBackendPreservesRawIdentityAndPaths(t *testing.T) {
	owner := NewEncryptedRuntime(t.Context(), filepath.Join(t.TempDir(), "config.yaml"), nil)
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	base := StoreConfig{Type: StoreTypeEncryptedFile, Path: "vault", Unlock: "key-file", KeyFile: "key"}
	for _, field := range []string{"id", "path", "key_file"} {
		t.Run(field, func(t *testing.T) {
			first, second := base, base
			firstID, secondID := "offline", "offline"
			switch field {
			case "id":
				firstID, secondID = "offline\xff", "offline\xfe"
			case "path":
				first.Path, second.Path = "vault\xff", "vault\xfe"
			case "key_file":
				first.KeyFile, second.KeyFile = "key\xff", "key\xfe"
			}
			a, err := owner.backend(firstID, first)
			if err != nil {
				t.Fatal(err)
			}
			b, err := owner.backend(secondID, second)
			if err != nil {
				t.Fatal(err)
			}
			if a == b {
				t.Fatal("distinct raw bytes share one backend")
			}
			again, err := owner.backend(firstID, first)
			if err != nil || again != a {
				t.Fatal("identical configuration did not reuse its backend", err)
			}
		})
	}
}

func TestEncryptedBackendSeparatesSessionPolicies(t *testing.T) {
	owner := NewEncryptedRuntime(t.Context(), filepath.Join(t.TempDir(), "config.yaml"), nil)
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	base := StoreConfig{Type: StoreTypeEncryptedFile, Path: "vault", Unlock: "prompt"}
	first, err := owner.backend("offline", base)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*StoreConfig){
		func(c *StoreConfig) { c.ReadOnly = true },
		func(c *StoreConfig) { c.NonInteractive = true },
		func(c *StoreConfig) { c.Timeout = time.Second },
		func(c *StoreConfig) { c.UnlockTimeout = time.Second },
		func(c *StoreConfig) { c.PromptTimeout = time.Second },
		func(c *StoreConfig) { c.UnlockIdleTTL = time.Second },
		func(c *StoreConfig) { c.CacheTTL = time.Second },
	} {
		cfg := base
		mutate(&cfg)
		got, err := owner.backend("offline", cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got == first {
			t.Fatal("different session policies share a backend")
		}
	}
}
