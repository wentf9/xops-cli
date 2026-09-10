package format

import (
	"bytes"
	"testing"
)

func TestInspectionRequiresAuthentication(t *testing.T) {
	v := vectors(t)
	identity, err := InspectItem(v["item"])
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Clone(v["item"])
	changed[len(changed)-1] ^= 1
	inspected, err := InspectItem(changed)
	if err != nil || inspected != identity {
		t.Fatalf("inspection: %v", err)
	}
	secret, err := OpenItem(changed, v["dek"], identity)
	secret.Zero()
	if err == nil {
		t.Fatal("inspection authenticated ciphertext")
	}
	for _, data := range [][]byte{nil, v["item"][:10], make([]byte, MaxItemBytes+1)} {
		if _, err := InspectItem(data); err == nil {
			t.Fatal("invalid item accepted")
		}
	}
}

func TestTransactionInspectionStrict(t *testing.T) {
	v := vectors(t)
	original := v["state"]
	tx, err := InspectTransaction(original)
	if err != nil {
		t.Fatal(err)
	}
	if tx.OperationID == ([16]byte{}) {
		t.Fatal("missing identity")
	}
	for _, data := range [][]byte{nil, []byte(`{"unknown":true}`), append(bytes.Clone(original), []byte(` {}`)...), make([]byte, MaxStateBytes+1)} {
		if _, err := InspectTransaction(data); err == nil {
			t.Fatal("invalid transaction accepted")
		}
	}
}
