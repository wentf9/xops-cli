//go:build integration && (linux || darwin || windows) && (amd64 || arm64)

package credentialfile

import (
	"context"
	"errors"
	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestMaintenanceProcessHelper(t *testing.T) {
	root := os.Getenv("XOPS_TEST_ADMIN_ROOT")
	if root == "" {
		return
	}
	data := fixtureData(t)
	keys := unlockFunc(func(ctx context.Context, b []byte) ([]byte, error) {
		m, err := format.ParseMeta(b)
		if err != nil {
			return nil, err
		}
		wrap, err := format.KeyFileWrappingKey(m, data["file_key"])
		if err != nil {
			return nil, err
		}
		defer clear(wrap)
		_, key, err := format.OpenMeta(b, wrap, "offline")
		return key, err
	})
	point := os.Getenv("XOPS_TEST_ADMIN_CRASH")
	s, err := openStore(t.Context(), root, "offline", Options{Keys: keys}, fileOps{after: func(step string) {
		if step == point {
			os.Exit(77)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := s.Reencrypt(t.Context(), Wrapping{Mode: "key-file", KeyFile: os.Getenv("XOPS_TEST_ADMIN_KEY")}); err != nil {
		t.Fatal(err)
	}
}

func TestMaintenanceProcessRecovery(t *testing.T) {
	for _, point := range []string{"admin:meta:file-sync", "admin:stage-1", "admin:stage-2", "admin:budget:file-sync", "admin:budget:publish", "admin:budget:dir-sync", "admin:item:file-sync", "admin:item:publish", "admin:stage-3", "admin:current:file-sync", "admin:current:publish", "admin:current:dir-sync", "admin:stage-4", "admin:stage-5", "admin:archive"} {
		t.Run(point, func(t *testing.T) {
			f := makeFixture(t)
			s := f.open(t, fileOps{})
			material := adminMaterial(t, f)
			secret := credential.NewSecret([]byte("public-crash-secret"))
			defer secret.Zero()
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMaintenanceProcessHelper$", "-test.count=1")
			cmd.WaitDelay = time.Second
			cmd.Env = append(os.Environ(), "XOPS_TEST_ADMIN_ROOT="+f.root, "XOPS_TEST_ADMIN_KEY="+material.KeyFile, "XOPS_TEST_ADMIN_CRASH="+point)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("child exit %v %s", err, out)
			}
			result, err := s.Resume(t.Context(), material, material)
			if point == "admin:meta:file-sync" {
				if !errors.Is(err, ErrMaintenanceRequired) {
					t.Fatalf("orphan accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !result.Durable {
				t.Fatalf("result %+v", result)
			}
			got, err := s.Get(t.Context(), f.ref)
			got.Zero()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Put(t.Context(), f.ref, secret); err != nil {
				t.Fatal("still blocked", err)
			}
		})
	}
}
