package config

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestLazyRegistryInitializationAndCancellation(t *testing.T) {
	reg, err := BuildRegistryFromConfig(&CredentialConfig{Stores: map[string]StoreConfig{
		"system": {Type: StoreTypeSystem},
		"none":   {Type: StoreTypeNone},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reg.Resolve(ctx, credential.Ref{StoreID: "system", ItemID: "item"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled initialization: %v", err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, err := reg.Resolve(t.Context(), credential.Ref{StoreID: "none", ItemID: "item"})
			if !errors.Is(err, credential.ErrCredentialNotFound) {
				t.Errorf("concurrent read: %v", err)
			}
		})
	}
	wg.Wait()
}
