package format

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

// The independent v1 corpus is a frozen reference, not output to regenerate
// alongside encoder changes. Add future-version vectors in separate files.
func TestFrozenV1ReferenceCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	const want = "0991874cd848a7f6a6be96fef4d2d8843fed277e4d0c08e50284a6d188551ced"
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		t.Fatalf("frozen v1 reference corpus changed: got %s, want %s", got, want)
	}
	if Version != 1 {
		t.Fatal("v1 codec version changed in place")
	}
}
