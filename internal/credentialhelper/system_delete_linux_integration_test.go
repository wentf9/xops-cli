//go:build linux && integration

package credentialhelper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestLinuxNativeDeleteWithMetadata(t *testing.T) {
	for _, command := range []string{"secret-tool", "dbus-run-session", "gnome-keyring-daemon", "gdbus"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("native keyring test requires %s: %v", command, err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if os.Getenv("XOPS_NATIVE_DELETE_CHILD") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "dbus-run-session", "--", executable, "-test.run=^TestLinuxNativeDeleteWithMetadata$", "-test.v")
		command.Env = append(os.Environ(), "XOPS_NATIVE_DELETE_CHILD=1")
		command.WaitDelay = time.Second
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated native keyring test: %v\n%s", err, output)
		}
		t.Logf("isolated native keyring test:\n%s", output)
		return
	}

	startIsolatedDeleteKeyring(t, ctx)
	store, err := newNativeSystemStore("system", SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"delete", "gc"} {
		t.Run(mode, func(t *testing.T) {
			ref := credential.Ref{StoreID: "system", ItemID: credential.GenerateItemID()}
			secret := credential.NewSecret([]byte("disposable-test-secret"))
			defer secret.Zero()
			if err := store.Put(ctx, ref, secret); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, "secret-tool", "search", "--all", "--unlock", "xops-store", ref.StoreID, "xops-item", ref.ItemID)
			var diagnostic bytes.Buffer
			command.Stdout, command.Stderr = io.Discard, &diagnostic
			command.WaitDelay = time.Second
			if err := command.Run(); err != nil {
				t.Fatalf("native search failed: %v", err)
			}
			if !strings.Contains(diagnostic.String(), "attribute.xops-item = "+ref.ItemID) || !strings.Contains(diagnostic.String(), "attribute.xops-store = system") {
				t.Fatalf("native search did not emit expected metadata: %q", diagnostic.String())
			}
			if mode == "gc" {
				collectNativeDeleteJournal(t, ctx, store, ref)
			} else if err := store.Delete(ctx, ref); err != nil {
				t.Fatal(err)
			}
			remaining, err := store.Get(ctx, ref)
			remaining.Zero()
			if !errors.Is(err, coreauth.ErrCredentialNotFound) {
				t.Fatalf("native cleanup retained credential: %v", err)
			}
		})
	}
}

func startIsolatedDeleteKeyring(t *testing.T, ctx context.Context) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("GNOME_KEYRING_CONTROL", t.TempDir())
	work, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(work, "gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets", "--control-directory="+os.Getenv("GNOME_KEYRING_CONTROL"))
	command.Stdin = strings.NewReader("disposable-keyring-password\n")
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.WaitDelay = time.Second
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		var exitErr *exec.ExitError
		if err := command.Wait(); err != nil && !errors.As(err, &exitErr) && !errors.Is(err, context.Canceled) {
			t.Errorf("stop isolated keyring: %v", err)
		}
	})
	wait := exec.CommandContext(ctx, "gdbus", "wait", "--session", "--timeout", "5", "org.freedesktop.secrets")
	wait.WaitDelay = time.Second
	if output, err := wait.CombinedOutput(); err != nil {
		t.Fatalf("wait for isolated keyring: %v\n%s", err, output)
	}
}

func collectNativeDeleteJournal(t *testing.T, ctx context.Context, store credential.Store, ref credential.Ref) {
	t.Helper()
	registry := credential.NewRegistry()
	if err := registry.Register(ref.StoreID, store); err != nil {
		t.Fatal(err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	entry := credential.JournalEntry{ID: credential.GenerateJournalID(), Op: credential.OpAssetDelete, OldRef: &ref}
	if err := journal.RecordIntent(&entry); err != nil {
		t.Fatal(err)
	}
	if err := journal.MarkCleanup(entry.ID); err != nil {
		t.Fatal(err)
	}
	service, err := credential.NewService(registry, journal, deletedAssetConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	results, err := service.GC(ctx)
	if err != nil || len(results) != 1 || results[0].Err != nil || results[0].Action != credential.RecoveryActionCommittedCleaned {
		t.Fatalf("native GC failed: %+v, %v", results, err)
	}
	assertSystemStorePendingCleanup(t, journal, 0)
}
