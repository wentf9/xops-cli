package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func sourceIdentity() KeyIdentity {
	i := identity()
	return KeyIdentity{VaultID: i.VaultID, StoreID: i.Ref.StoreID, Generation: i.Generation}
}

func TestIndependentManifestVectors(t *testing.T) {
	v := vectors(t)
	var hashes [][32]byte
	for _, name := range []string{"manifest0", "manifest1"} {
		m, err := ParseManifestBlock(v[name])
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Entries) != 1 {
			t.Fatal("entry count differs")
		}
		b, err := m.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, v[name]) {
			t.Fatal("manifest differs")
		}
		hashes = append(hashes, sha256.Sum256(b))
	}
	root, err := ManifestRoot(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root[:], v["manifest_root"]) {
		t.Fatal("manifest root differs")
	}
	empty, err := ManifestRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty[:], v["empty_root"]) {
		t.Fatal("empty root differs")
	}
	hashes[0], hashes[1] = hashes[1], hashes[0]
	changed, err := ManifestRoot(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if changed == root {
		t.Fatal("block reordering ignored")
	}
}

func TestIndependentTransactionVector(t *testing.T) {
	v := vectors(t)
	tx, err := OpenTransaction(v["state"], v["dek"], sourceIdentity(), false)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Operation != OpReencrypt || tx.Stage != Verified || tx.Target.Generation != 2 {
		t.Fatal("wrong state")
	}
	got, err := SealTransaction(tx, v["dek"], v["target_key"])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, v["state"]) {
		t.Fatal("state differs from independent HMAC vector")
	}
	i := sourceIdentity()
	i.Generation = 2
	if _, err := OpenTransaction(v["state"], v["target_key"], i, true); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTransaction(v["state"], v["dek"], i, true); !errors.Is(err, ErrCorrupt) {
		t.Fatal("wrong target key accepted")
	}
	if _, err := OpenTransaction(v["state"], v["target_key"], sourceIdentity(), true); !errors.Is(err, ErrIdentity) {
		t.Fatal("wrong expected identity accepted")
	}
}

func TestStateRejectsPayloadTampering(t *testing.T) {
	v := vectors(t)
	var envelope stateEnvelope
	if err := json.Unmarshal(v["state"], &envelope); err != nil {
		t.Fatal(err)
	}
	for at := range v["state_payload"] {
		bad := bytes.Clone(v["state_payload"])
		bad[at] ^= 1
		envelope.Payload = base64.StdEncoding.EncodeToString(bad)
		data, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenTransaction(data, v["dek"], sourceIdentity(), false); err == nil {
			t.Fatalf("changed payload byte %d accepted", at)
		}
	}
}

func TestStateEnvelopeRejectsAmbiguity(t *testing.T) {
	v := vectors(t)
	s := string(v["state"])
	for _, tc := range []struct{ name, data string }{
		{"duplicate", strings.Replace(s, "{", "{\"payload\":\"\",", 1)},
		{"unknown", strings.Replace(s, "{", "{\"unknown\":\"\",", 1)},
		{"null", strings.Replace(s, "\"source_mac\":", "\"source_mac\":null,\"discard\":", 1)},
		{"trailing", s + "{}"},
		{"base64_newline", strings.Replace(s, "\"payload\":\"", "\"payload\":\"\\n", 1)},
		{"missing", "{\"payload\":\"\",\"target_mac\":\"\"}"},
		{"oversize", strings.Repeat(" ", MaxStateBytes+1) + s},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := OpenTransaction([]byte(tc.data), v["dek"], sourceIdentity(), false); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	// Null must be rejected even on the side not used for verification.
	var e map[string]any
	if err := json.Unmarshal(v["state"], &e); err != nil {
		t.Fatal(err)
	}
	e["target_mac"] = nil
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTransaction(b, v["dek"], sourceIdentity(), false); err == nil {
		t.Fatal("null MAC accepted")
	}
}

func TestTransactionMissingSidesAndRelations(t *testing.T) {
	v := vectors(t)
	tx, err := OpenTransaction(v["state"], v["dek"], sourceIdentity(), false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealTransaction(tx, v["dek"], nil)
	if err != nil {
		t.Fatal(err)
	}
	i := sourceIdentity()
	i.Generation = 2
	if _, err := OpenTransaction(b, v["target_key"], i, true); err == nil {
		t.Fatal("missing MAC accepted")
	}
	if _, err := SealTransaction(tx, nil, nil); err == nil {
		t.Fatal("unsigned state accepted")
	}
	tx.Operation = OpRewrap
	if _, err := SealTransaction(tx, v["dek"], nil); err == nil {
		t.Fatal("rewrap changes DEK")
	}
	tx.Operation = OpInit
	tx.Source = Endpoint{}
	if _, err := SealTransaction(tx, nil, v["target_key"]); err != nil {
		t.Fatal(err)
	}
	tx.Stage = Verified
	tx.Target.MetaHash = [32]byte{}
	if _, err := SealTransaction(tx, nil, v["target_key"]); err == nil {
		t.Fatal("verified target without hash accepted")
	}
}

func TestTransactionRequiresFrozenSourceManifest(t *testing.T) {
	v := vectors(t)
	tx, err := OpenTransaction(v["state"], v["dek"], sourceIdentity(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		stage Stage
	}{{"prepared", Prepared}, {"verified", Verified}, {"committed", Committed}} {
		t.Run(tc.name, func(t *testing.T) {
			bad := tx
			bad.Stage = tc.stage
			bad.Source.ManifestRoot = [32]byte{}
			if _, err := SealTransaction(bad, v["dek"], nil); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("missing source root accepted: %v", err)
			}
		})
	}
	// An empty source still has a real authenticated empty-manifest hash.
	empty, err := ManifestRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	tx.Source.ItemCount = 0
	tx.Source.ManifestRoot = empty
	if _, err := SealTransaction(tx, v["dek"], nil); err != nil {
		t.Fatal(err)
	}
}

func TestManifestBoundsAndOrdering(t *testing.T) {
	v := vectors(t)
	m, err := ParseManifestBlock(v["manifest0"])
	if err != nil {
		t.Fatal(err)
	}
	m.Entries = append(m.Entries, m.Entries[0])
	if _, err := m.MarshalBinary(); err == nil {
		t.Fatal("duplicate item accepted")
	}
	for n := range v["manifest0"] {
		if _, err := ParseManifestBlock(v["manifest0"][:n]); err == nil {
			t.Fatalf("truncated manifest accepted at %d", n)
		}
	}
	bad := bytes.Clone(v["manifest0"])
	binary.BigEndian.PutUint32(bad[14:18], ^uint32(0))
	if _, err := ParseManifestBlock(bad); err == nil {
		t.Fatal("unbounded count accepted")
	}
	if _, err := ParseManifestBlock(append(bytes.Clone(v["manifest0"]), 0)); err == nil {
		t.Fatal("trailing manifest data accepted")
	}
}

func TestManifestVerifierChecksWholeSnapshot(t *testing.T) {
	v := vectors(t)
	var root [32]byte
	copy(root[:], v["manifest_root"])
	check, err := NewManifestVerifier(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := check.Add(v["manifest1"]); err == nil {
		t.Fatal("out-of-order block accepted")
	}
	if err := check.Add(v["manifest0"]); err != nil {
		t.Fatal(err)
	}
	duplicate, err := ParseManifestBlock(v["manifest0"])
	if err != nil {
		t.Fatal(err)
	}
	duplicate.Index = 1
	b, err := duplicate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := check.Add(b); err == nil {
		t.Fatal("duplicate ID across blocks accepted")
	}
	if err := check.Add(v["manifest1"]); err != nil {
		t.Fatal(err)
	}
	if err := check.Finish(root); err != nil {
		t.Fatal(err)
	}
	if err := check.Add(v["manifest0"]); err == nil {
		t.Fatal("write after finish accepted")
	}
	if err := check.Finish(root); err == nil {
		t.Fatal("repeated finish accepted")
	}
}

func TestManifestVerifierRequiresCountsAndRoot(t *testing.T) {
	v := vectors(t)
	for _, tc := range []struct {
		name   string
		blocks uint32
		items  uint64
		add    bool
	}{
		{"missing", 2, 2, false}, {"count", 1, 2, true}, {"root", 1, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check, err := NewManifestVerifier(tc.blocks, tc.items)
			if err != nil {
				t.Fatal(err)
			}
			if tc.add {
				if err := check.Add(v["manifest0"]); err != nil {
					t.Fatal(err)
				}
			}
			if err := check.Finish([32]byte{}); err == nil {
				t.Fatal("incomplete or wrong snapshot accepted")
			}
		})
	}
	if _, err := NewManifestVerifier(0, 1); err == nil {
		t.Fatal("invalid expected counts")
	}
	check, err := NewManifestVerifier(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var root [32]byte
	copy(root[:], v["empty_root"])
	if err := check.Finish(root); err != nil {
		t.Fatal(err)
	}
}

func FuzzRecoveryFormats(f *testing.F) {
	v := vectors(f)
	f.Add(v["state"])
	f.Add(v["manifest0"])
	f.Add(v["manifest1"])
	f.Fuzz(func(t *testing.T, b []byte) {
		if tx, err := OpenTransaction(b, v["dek"], sourceIdentity(), false); err == nil {
			if _, err := tx.payload(); err != nil {
				t.Fatal("accepted invalid transaction")
			}
		}
		if m, err := ParseManifestBlock(b); err == nil {
			out, err := m.MarshalBinary()
			if err != nil || !bytes.Equal(out, b) {
				t.Fatal("noncanonical manifest")
			}
		}
	})
}
