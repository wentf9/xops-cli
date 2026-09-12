//go:build linux && amd64

package credentialfile

import (
	"bytes"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

type partialKeyReader struct {
	observed []byte
	failure  error
}

func (r *partialKeyReader) Read(p []byte) (int, error) {
	copy(p, "public-partial-key")
	r.observed = p[:18]
	return 18, r.failure
}

func TestPartialKeyReadClearsOwnedBuffer(t *testing.T) {
	failure := errors.New("injected partial read")
	r := &partialKeyReader{failure: failure}
	key, err := readKeyMaterial(r)
	if !errors.Is(err, failure) || key != nil {
		t.Fatalf("partial read returned material: %v", err)
	}
	if !bytes.Equal(r.observed, make([]byte, len(r.observed))) {
		t.Fatal("partial key buffer was not cleared")
	}
}

func TestKeyMaterialExactLength(t *testing.T) {
	for _, n := range []int{0, 31, 32, 33, 64} {
		key, err := readKeyMaterial(bytes.NewReader(bytes.Repeat([]byte{0x42}, n)))
		if n == 32 {
			if err != nil || len(key) != 32 {
				t.Fatal(err)
			}
			clear(key)
			continue
		}
		if !errors.Is(err, credential.ErrCredentialStoreLocked) || key != nil {
			t.Fatalf("length %d accepted: %v", n, err)
		}
	}
}
