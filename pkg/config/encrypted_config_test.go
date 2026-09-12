package config

import (
	"github.com/wentf9/xops-cli/pkg/credential"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestEncryptedConfigDurations(t *testing.T) {
	base := "type: encrypted-file\npath: credentials/offline\nunlock: prompt\n"
	var cfg StoreConfig
	if err := yaml.Unmarshal([]byte(base), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 10*time.Second || cfg.UnlockIdleTTL != 5*time.Minute || cfg.PromptTimeout != 2*time.Minute || cfg.UnlockTimeout != 30*time.Second || cfg.CacheTTL != 0 {
		t.Fatalf("defaults: %+v", cfg)
	}
	for _, extra := range []string{"timeout: 0s", "timeout: null", "unlock_idle_ttl: 0s", "unlock_idle_ttl: 31m", "prompt_timeout: -1s", "unlock_timeout: 0s", "cache_ttl: -1s", "command: ''", "args: []", "prefix: ''", "key_file: /key", "unknown: true", "timeout: 1s\ntimeout: 2s"} {
		t.Run(extra, func(t *testing.T) {
			var c StoreConfig
			if err := yaml.Unmarshal([]byte(base+extra+"\n"), &c); err == nil {
				t.Fatalf("accepted %q", extra)
			}
		})
	}
	if _, err := ResolveFileStore(cfg, ""); err == nil {
		t.Fatal("relative path without base accepted")
	}
	filename := filepath.Join(t.TempDir(), "config.yaml")
	got, err := ResolveFileStore(cfg, filename)
	if err != nil || got.Path != filepath.Join(filepath.Dir(filename), "credentials/offline") {
		t.Fatalf("resolve: %+v %v", got, err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var round StoreConfig
	if err := yaml.Unmarshal(data, &round); err != nil {
		t.Fatal(err)
	}
	if round.Timeout != cfg.Timeout || round.UnlockIdleTTL != cfg.UnlockIdleTTL {
		t.Fatal("duration roundtrip changed")
	}
}

func TestEncryptedConfigOldBackendDefaults(t *testing.T) {
	var cfg StoreConfig
	if err := yaml.Unmarshal([]byte("type: none\ntimeout: 0s\ncache_ttl: 0s\n"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 0 || cfg.UnlockIdleTTL != 0 {
		t.Fatal("old defaults changed")
	}
}

func TestEncryptedReferenceBounds(t *testing.T) {
	cfg := StoreConfig{Type: StoreTypeEncryptedFile, Path: "/vault", Unlock: "prompt"}
	if err := validateStoreConfig(strings.Repeat("a", 1025), cfg); err == nil {
		t.Fatal("long offline StoreID accepted")
	}
	ref := credential.Ref{StoreID: "file", ItemID: strings.Repeat("b", 1025)}
	if err := validateConfiguredRef(ref, map[string]StoreConfig{"file": cfg}); err == nil {
		t.Fatal("long offline ItemID accepted")
	}
	if err := validateConfiguredRef(ref, map[string]StoreConfig{"file": {Type: StoreTypeNone}}); err != nil {
		t.Fatal("other backend bound changed", err)
	}
}
