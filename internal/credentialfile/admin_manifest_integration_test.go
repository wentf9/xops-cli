//go:build integration && linux && amd64

package credentialfile

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/internal/credentialfile/format"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestMaintenanceExternalManifestSort(t *testing.T) {
	f := makeFixture(t)
	s := f.open(t, fileOps{})
	secret := credential.NewSecret([]byte("public-manifest"))
	defer secret.Zero()
	const count = 1000
	for i := range count {
		ref := credential.Ref{StoreID: "offline", ItemID: fmt.Sprintf("%04d-%s", count-i-1, strings.Repeat("x", 1019))}
		data, err := format.SealItem(format.ItemIdentity{VaultID: identityVault(t, f), Generation: 1, Ref: ref}, [12]byte{byte(i), byte(i >> 8)}, f.data["dek"], secret)
		if err != nil {
			t.Fatal(err)
		}
		name, err := format.ItemFilename(ref.ItemID)
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, filepath.Join(f.root, "revisions/1/items", name), data)
	}
	a, err := s.admin(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := a.close(); err != nil {
			t.Error(err)
		}
	}()
	if err := a.acquire(); err != nil {
		t.Fatal(err)
	}
	rev, err := revisionDir(s.root, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFileTest(t, rev.file)
	items, err := rev.child("items")
	if err != nil {
		t.Fatal(err)
	}
	defer closeFileTest(t, items.file)
	scratch, err := s.root.mkdir(t.Context(), "manifest-test", false, fileOps{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFileTest(t, scratch.file)
	run, err := scanSource(t.Context(), items, scratch, a.key, a.pub, fileOps{}, a.check)
	if err != nil {
		t.Fatal(err)
	}
	if run.items != count || run.blocks < 2 {
		t.Fatalf("not multiblock: %+v", run)
	}
	verified, err := loadManifest(t.Context(), scratch, "source", run.root, run.items)
	if err != nil {
		t.Fatal(err)
	}
	reader := manifestReader{dir: scratch, run: verified}
	for i := range count {
		entry, ok, err := reader.next(t.Context())
		if err != nil || !ok {
			t.Fatalf("entry %d: %v", i, err)
		}
		if !strings.HasPrefix(entry.ItemID, fmt.Sprintf("%04d-", i)) {
			t.Fatalf("unsorted entry %d", i)
		}
	}
	if _, ok, err := reader.next(t.Context()); ok || err != nil {
		t.Fatalf("extra entries: %v", err)
	}
}
