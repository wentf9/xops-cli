//go:build integration && vaultpowercut && linux && amd64

package credentialfile

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// TestVaultPowerCut is driven across separate VM boots. It never powers off
// the machine itself: the host kills only its own disposable QEMU process.
func TestVaultPowerCut(t *testing.T) {
	phase := os.Getenv("XOPS_POWER_PHASE")
	if phase == "" {
		t.Skip("requires the disposable VM driver")
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(string(cmdline), "xops_vault_lab=1") {
		t.Fatal("not a validation VM")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	key := bytes.Repeat([]byte{37}, 32)
	defer clear(key)
	material := Wrapping{Mode: "key-file", KeyFile: "/data/key"}
	ref := credential.Ref{StoreID: "offline", ItemID: "powercut-original"}
	secret := credential.NewSecret([]byte("public-powercut-original"))
	defer secret.Zero()
	if phase == "prepare" {
		preparePowerCut(t, ctx, key, material, ref, secret)
		return
	}
	keys := powerCutKeys(key)
	ops := fileOps{}
	if phase == "cut" {
		point := os.Getenv("XOPS_POWER_POINT")
		ops.after = func(step string) {
			if step != point {
				return
			}
			if _, err := fmt.Fprintln(os.Stdout, "XOPS_POWER_CUT_READY"); err != nil {
				t.Fatal(err)
			}
			<-ctx.Done()
			t.Fatal("host did not cut VM power before deadline")
		}
	}
	s, err := openStore(ctx, "/data/vault", "offline", Options{Keys: keys}, ops)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	if phase == "cut" {
		if os.Getenv("XOPS_POWER_OPERATION") == "prune" {
			_, err = s.Prune(ctx, true)
		} else {
			_, err = s.Reencrypt(ctx, material)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("requested cut point was not reached")
	}
	if phase != "verify" {
		t.Fatal("unknown power-cut phase")
	}
	if _, err := s.Resume(ctx, material, material); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Zero()
	if !bytes.Equal(got.Value, secret.Value) {
		t.Fatal("original value changed across power loss")
	}
	// A fresh write must validate/reserve the recovered budget; an idempotent
	// same-item retry would not exercise this safety boundary.
	if err := s.Put(ctx, credential.Ref{StoreID: "offline", ItemID: "after-powercut"}, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(ctx, true); err != nil {
		t.Fatal(err)
	}
}

func powerCutKeys(key []byte) KeySource {
	return unlockFunc(func(_ context.Context, b []byte) ([]byte, error) {
		m, err := format.ParseMeta(b)
		if err != nil {
			return nil, err
		}
		wrap, err := format.KeyFileWrappingKey(m, key)
		if err != nil {
			return nil, err
		}
		defer clear(wrap)
		_, dek, err := format.OpenMeta(b, wrap, "offline")
		return dek, err
	})
}

func preparePowerCut(t *testing.T, ctx context.Context, key []byte, material Wrapping, ref credential.Ref, secret credential.Secret) {
	t.Helper()
	writeFixtureFile(t, material.KeyFile, key)
	r := testRuntime(t, nil, nil)
	if _, err := r.Init(ctx, "/data/vault", "offline", material); err != nil {
		t.Fatal(err)
	}
	s, err := r.OpenStore(ctx, "/data/vault", "offline", Options{}, SessionOptions{Mode: "key-file", KeyFile: material.KeyFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, ref, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reencrypt(ctx, material); err != nil {
		t.Fatal(err)
	}
}
