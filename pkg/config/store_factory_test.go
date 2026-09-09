package config

import (
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestBuildStoreTypes(t *testing.T) {
	// 1. none
	noneStore, err := BuildStore("none-1", StoreConfig{Type: StoreTypeNone})
	if err != nil {
		t.Fatalf("BuildStore none failed: %v", err)
	}
	if _, ok := noneStore.(*credential.NoneStore); !ok {
		t.Fatalf("expected *credential.NoneStore, got %T", noneStore)
	}

	// 2. helper
	helperStore, err := BuildStore("helper-1", StoreConfig{
		Type:    StoreTypeHelper,
		Command: "/bin/true",
	})
	if err != nil {
		t.Fatalf("BuildStore helper failed: %v", err)
	}
	if helperStore == nil {
		t.Fatalf("expected non-nil helperStore")
	}

	// helper without command should fail
	_, err = BuildStore("helper-bad", StoreConfig{Type: StoreTypeHelper})
	if !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("expected ErrSchemaValidation when helper command is missing, got: %v", err)
	}

	// 3. pass
	passStore, err := BuildStore("pass-1", StoreConfig{
		Type:    StoreTypePass,
		Prefix:  "custom-pfx",
		Command: "pass",
	})
	if err != nil {
		t.Fatalf("BuildStore pass failed: %v", err)
	}
	if passStore == nil {
		t.Fatalf("expected non-nil passStore")
	}

	// 4. system
	sysStore, err := BuildStore("sys-1", StoreConfig{
		Type:    StoreTypeSystem,
		Command: "echo",
	})
	if err != nil {
		t.Fatalf("BuildStore system failed: %v", err)
	}
	if sysStore == nil {
		t.Fatalf("expected non-nil sysStore")
	}

	// 5. with cache_ttl
	cachedStore, err := BuildStore("cached-1", StoreConfig{
		Type:     StoreTypeNone,
		CacheTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("BuildStore with cache failed: %v", err)
	}
	if _, ok := cachedStore.(*credential.CachedStore); !ok {
		t.Fatalf("expected *credential.CachedStore decorator, got %T", cachedStore)
	}

	// 6. unsupported type
	_, err = BuildStore("bad-type", StoreConfig{Type: "unknown-type"})
	if !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("expected ErrSchemaValidation on unknown store type, got: %v", err)
	}
}

func TestBuildRegistryFromConfig(t *testing.T) {
	credCfg := &CredentialConfig{
		DefaultStore: "none-store",
		Stores: map[string]StoreConfig{
			"none-store": {
				Type: StoreTypeNone,
			},
			"pass-store": {
				Type:     StoreTypePass,
				Prefix:   "xops",
				Command:  "pass",
				CacheTTL: 10 * time.Minute,
			},
		},
	}

	reg, err := BuildRegistryFromConfig(credCfg)
	if err != nil {
		t.Fatalf("BuildRegistryFromConfig failed: %v", err)
	}

	// 获取已注册的 none-store
	st1, err := reg.GetStore("none-store")
	if err != nil {
		t.Fatalf("GetStore none-store failed: %v", err)
	}
	if _, err := st1.Get(t.Context(), credential.Ref{StoreID: "none-store", ItemID: "missing"}); !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("none get: %v", err)
	}

	// 获取已注册的 pass-store（包装了 CachedStore）
	st2, err := reg.GetStore("pass-store")
	if err != nil {
		t.Fatalf("GetStore pass-store failed: %v", err)
	}
	if st2 == nil {
		t.Fatal("missing lazy pass store")
	}

	// 查询不存在的 store 应该报错
	_, err = reg.GetStore("non-existent")
	if !errors.Is(err, credential.ErrStoreNotFound) {
		t.Fatalf("expected ErrStoreNotFound, got: %v", err)
	}
}
