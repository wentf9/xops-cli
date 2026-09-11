//go:build darwin

package vaultsys

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func TestDarwinACLGrantIsNotPrivate(t *testing.T) {
	name := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(name, []byte("public-test-data"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	var before Stat_t
	if err := Fstat(int(file.Fd()), &before); err != nil {
		t.Fatal(err)
	}
	if before.Mode != S_IFREG|0600 {
		t.Fatal("fresh private file has unexpected permissions")
	}
	if output, err := exec.Command("/bin/chmod", "+a", "everyone allow read", name).CombinedOutput(); err != nil {
		t.Fatalf("set test ACL: %v %s", err, output)
	}
	var after Stat_t
	if err := Fstat(int(file.Fd()), &after); err != nil {
		t.Fatal(err)
	}
	if after.Mode == S_IFREG|0600 {
		t.Fatal("extended ACL grant was ignored")
	}
}

func TestDarwinACLConcurrentStat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(path, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	var group sync.WaitGroup
	failures := make(chan error, 2)
	for range 2 {
		group.Go(func() {
			for range 1000 {
				if t.Context().Err() != nil {
					return
				}
				var st Stat_t
				if err := Fstat(int(file.Fd()), &st); err != nil {
					failures <- err
					return
				}
			}
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
