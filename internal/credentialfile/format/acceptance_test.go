package format

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func validTransaction(t *testing.T, operation Operation) Transaction {
	t.Helper()
	v := vectors(t)
	tx, err := OpenTransaction(v["state"], v["dek"], sourceIdentity(), false)
	if err != nil {
		t.Fatal(err)
	}
	tx.Operation = operation
	switch operation {
	case OpInit:
		tx.Source = Endpoint{}
	case OpRewrap:
		tx.Target.Generation = tx.Source.Generation
	case OpClone:
		tx.Target.VaultID[0] ^= 1
		tx.Target.StoreID = "cloned"
		tx.Target.Generation, tx.Target.Revision = 1, 1
	case OpPrune:
		tx.Source.Revision = 300
		tx.Target = tx.Source
		tx.Stage = CleanupPending
		tx.CleanupRevisions = []uint64{1, 2}
	}
	return tx
}

func checkTransactionRoundTrip(t *testing.T, tx Transaction) {
	t.Helper()
	tx.CleanupRevisions = append([]uint64(nil), tx.CleanupRevisions...)
	v := vectors(t)
	sourceKey, targetKey := v["dek"], v["target_key"]
	if tx.Operation == OpInit {
		sourceKey = nil
	}
	if tx.Operation == OpRewrap || tx.Operation == OpPrune {
		targetKey = sourceKey
	}
	b, err := SealTransaction(tx, sourceKey, targetKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct {
		name     string
		endpoint Endpoint
		key      []byte
		target   bool
	}{
		{"source", tx.Source, sourceKey, false}, {"target", tx.Target, targetKey, true},
	} {
		if len(side.key) == 0 {
			continue
		}
		expected := KeyIdentity{VaultID: side.endpoint.VaultID, StoreID: side.endpoint.StoreID, Generation: side.endpoint.Generation}
		got, err := OpenTransaction(b, side.key, expected, side.target)
		if err != nil {
			t.Fatalf("%s verification: %v", side.name, err)
		}
		// Empty cleanup lists may decode as an empty slice instead of nil.
		got.CleanupRevisions = append([]uint64(nil), got.CleanupRevisions...)
		if !reflect.DeepEqual(got, tx) {
			t.Fatalf("%s changed transaction fields", side.name)
		}
	}
}

func TestMaintenanceOperationAcceptance(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   Operation
	}{
		{"init", OpInit}, {"rewrap", OpRewrap}, {"reencrypt", OpReencrypt},
		{"restore", OpRestore}, {"clone", OpClone}, {"prune", OpPrune},
	} {
		t.Run(tc.name, func(t *testing.T) { checkTransactionRoundTrip(t, validTransaction(t, tc.op)) })
	}
}

func TestMaintenanceOperationRejectsInvalidRelations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		op     Operation
		mutate func(*Transaction)
	}{
		{"init_with_source", OpInit, func(tx *Transaction) { tx.Source = tx.Target }},
		{"restore_other_vault", OpRestore, func(tx *Transaction) { tx.Target.VaultID[0] ^= 1 }},
		{"restore_other_store", OpRestore, func(tx *Transaction) { tx.Target.StoreID = "other" }},
		{"restore_same_key_generation", OpRestore, func(tx *Transaction) { tx.Target.Generation = tx.Source.Generation }},
		{"restore_old_revision", OpRestore, func(tx *Transaction) { tx.Target.Revision = tx.Source.Revision }},
		{"clone_same_vault", OpClone, func(tx *Transaction) { tx.Target.VaultID = tx.Source.VaultID }},
		{"prune_other_endpoint", OpPrune, func(tx *Transaction) { tx.Target.Generation++ }},
		{"prune_current", OpPrune, func(tx *Transaction) { tx.CleanupRevisions = []uint64{tx.Target.Revision} }},
		{"prune_duplicate", OpPrune, func(tx *Transaction) { tx.CleanupRevisions = []uint64{1, 1} }},
		{"prune_unsorted", OpPrune, func(tx *Transaction) { tx.CleanupRevisions = []uint64{2, 1} }},
		{"prune_zero", OpPrune, func(tx *Transaction) { tx.CleanupRevisions = []uint64{0} }},
		{"clone_cleanup", OpClone, func(tx *Transaction) { tx.CleanupRevisions = []uint64{10} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := validTransaction(t, tc.op)
			tc.mutate(&tx)
			v := vectors(t)
			if _, err := SealTransaction(tx, nil, v["target_key"]); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid relation accepted: %v", err)
			}
		})
	}
}

func TestCleanupListCountBoundaries(t *testing.T) {
	for _, n := range []int{256, 257} {
		t.Run(fmt.Sprintf("count_%d", n), func(t *testing.T) {
			tx := validTransaction(t, OpPrune)
			tx.CleanupRevisions = make([]uint64, n)
			for i := range tx.CleanupRevisions {
				tx.CleanupRevisions[i] = uint64(i + 1)
			}
			if n == 256 {
				checkTransactionRoundTrip(t, tx)
				return
			}
			v := vectors(t)
			if _, err := SealTransaction(tx, v["dek"], v["dek"]); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("257 entries: %v", err)
			}
		})
	}
	// Build a correctly authenticated 257-entry wire payload without the encoder,
	// so this tests decoder validation rather than MAC failure.
	tx := validTransaction(t, OpPrune)
	tx.CleanupRevisions = nil
	p, err := tx.payload()
	if err != nil {
		t.Fatal(err)
	}
	p = p[:len(p)-2]
	p = binary.BigEndian.AppendUint16(p, 257)
	for i := uint64(1); i <= 257; i++ {
		p = binary.BigEndian.AppendUint64(p, i)
	}
	v := vectors(t)
	mac, err := transactionMAC(tx.Source, v["dek"], p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(stateEnvelope{Payload: base64.StdEncoding.EncodeToString(p), SourceMAC: base64.StdEncoding.EncodeToString(mac)})
	if err != nil {
		t.Fatal(err)
	}
	expected := KeyIdentity{VaultID: tx.Source.VaultID, Generation: tx.Source.Generation, StoreID: tx.Source.StoreID}
	if _, err := OpenTransaction(b, v["dek"], expected, false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("257-entry wire: %v", err)
	}
}

func TestUnsignedCounterExtremes(t *testing.T) {
	v := vectors(t)
	i := identity()
	i.Generation = math.MaxUint64
	s := credential.NewSecret([]byte("public boundary secret"))
	defer s.Zero()
	b, err := SealItem(i, [12]byte{}, v["dek"], s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenItem(b, v["dek"], i)
	if err != nil {
		t.Fatal(err)
	}
	got.Zero()
	m, err := ParseMeta(v["meta_file"])
	if err != nil {
		t.Fatal(err)
	}
	m.Generation, m.Revision = math.MaxUint64, math.MaxUint64
	b, err = SealMeta(m, v["wrapping_key"], v["dek"])
	if err != nil {
		t.Fatal(err)
	}
	parsed, key, err := OpenMeta(b, v["wrapping_key"], m.StoreID)
	defer clear(key)
	if err != nil || parsed.Generation != math.MaxUint64 || parsed.Revision != math.MaxUint64 {
		t.Fatalf("meta counter extrema: %v", err)
	}
	budget := Budget{VaultID: i.VaultID, Generation: math.MaxUint64, Sequence: math.MaxUint64, Consumed: MaxEncryptions, StoreID: "offline"}
	b, err = SealBudget(budget, v["dek"])
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := OpenBudget(b, v["dek"], i.VaultID, math.MaxUint64, "offline")
	if err != nil || decoded != budget {
		t.Fatalf("budget extrema: %v", err)
	}
	c := Current{VaultID: i.VaultID, Generation: math.MaxUint64, Revision: math.MaxUint64}
	b, err = c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	pc, err := ParseCurrent(b)
	if err != nil || pc != c {
		t.Fatalf("CURRENT extrema: %v", err)
	}
}

func TestZeroCounterRejection(t *testing.T) {
	v := vectors(t)
	for _, tc := range []struct {
		name                 string
		generation, revision uint64
	}{{"generation", 0, 1}, {"revision", 1, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseMeta(v["meta_file"])
			if err != nil {
				t.Fatal(err)
			}
			m.Generation, m.Revision = tc.generation, tc.revision
			if _, err := SealMeta(m, v["wrapping_key"], v["dek"]); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("zero meta counter: %v", err)
			}
			c := Current{Generation: tc.generation, Revision: tc.revision}
			if _, err := c.MarshalBinary(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("zero CURRENT counter: %v", err)
			}
		})
	}
	if _, err := SealBudget(Budget{Generation: 1, Sequence: 0, StoreID: "offline"}, v["dek"]); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("zero sequence: %v", err)
	}
}

func TestExpirySignedExtremes(t *testing.T) {
	v := vectors(t)
	for _, tc := range []struct {
		name    string
		instant time.Time
		valid   bool
	}{
		{"min_i64", time.Unix(0, math.MinInt64), true},
		{"max_i64", time.Unix(0, math.MaxInt64), true},
		{"epoch", time.Unix(0, 0), true},
		{"below_min", time.Unix(0, math.MinInt64).Add(-time.Nanosecond), false},
		{"above_max", time.Unix(0, math.MaxInt64).Add(time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := credential.NewSecretWithExpiry([]byte("public boundary secret"), tc.instant)
			defer s.Zero()
			b, err := SealItem(identity(), [12]byte{}, v["dek"], s)
			if !tc.valid {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("overflow: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := OpenItem(b, v["dek"], identity())
			if err != nil {
				t.Fatal(err)
			}
			defer got.Zero()
			if got.ExpiresAt == nil || !got.ExpiresAt.Equal(tc.instant) {
				t.Fatal("timestamp did not round-trip exactly")
			}
		})
	}
}

func TestMaximumItemIdentifiersAndPayload(t *testing.T) {
	v := vectors(t)
	i := identity()
	i.Ref.StoreID, i.Ref.ItemID = strings.Repeat("s", MaxIDBytes), strings.Repeat("i", MaxIDBytes)
	s := credential.NewSecret(bytes.Repeat([]byte{0x42}, MaxSecretBytes))
	defer s.Zero()
	b, err := SealItem(i, [12]byte{}, v["dek"], s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != MaxItemBytes {
		t.Fatalf("maximum item length: %d", len(b))
	}
	got, err := OpenItem(b, v["dek"], i)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Zero()
	if !bytes.Equal(got.Value, s.Value) {
		t.Fatal("maximum payload changed")
	}
	for _, field := range []string{"store", "item"} {
		t.Run(field, func(t *testing.T) {
			bad := i
			if field == "store" {
				bad.Ref.StoreID += "x"
			} else {
				bad.Ref.ItemID += "x"
			}
			if _, err := SealItem(bad, [12]byte{}, v["dek"], s); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("oversized identifier: %v", err)
			}
		})
	}
}

func TestManifestExactByteLimit(t *testing.T) {
	block := ManifestBlock{Entries: make([]ManifestEntry, 1024)}
	for i := range block.Entries {
		// 1023 entries of 1024 bytes, one of 1006, and the 18-byte header.
		length := 986
		if i == len(block.Entries)-1 {
			length = 968
		}
		block.Entries[i] = ManifestEntry{ItemID: fmt.Sprintf("%04x", i) + strings.Repeat("x", length-4), FileSize: 100}
	}
	b, err := block.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != MaxManifestBytes {
		t.Fatalf("manifest boundary length = %d", len(b))
	}
	parsed, err := ParseManifestBlock(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, block) {
		t.Fatal("maximum manifest changed")
	}
	block.Entries[len(block.Entries)-1].ItemID += "x"
	if _, err := block.MarshalBinary(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("oversized manifest: %v", err)
	}
	if _, err := ParseManifestBlock(append(b, 0)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("oversized wire manifest: %v", err)
	}
}

func TestTransactionCounterRolloverRejected(t *testing.T) {
	tx := validTransaction(t, OpRestore)
	tx.Source.Generation, tx.Source.Revision = math.MaxUint64-1, math.MaxUint64-1
	tx.Target.Generation, tx.Target.Revision = math.MaxUint64, math.MaxUint64
	checkTransactionRoundTrip(t, tx)
	v := vectors(t)
	for _, field := range []string{"generation", "revision"} {
		t.Run(field, func(t *testing.T) {
			bad := tx
			if field == "generation" {
				bad.Source.Generation = math.MaxUint64
				bad.Target.Generation = 0
			} else {
				bad.Source.Revision = math.MaxUint64
				bad.Target.Revision = 0
			}
			if _, err := SealTransaction(bad, v["dek"], v["target_key"]); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("wrapped counter accepted: %v", err)
			}
		})
	}
}

func TestTransactionItemCountBoundaries(t *testing.T) {
	v := vectors(t)
	for _, side := range []string{"source", "target"} {
		for _, count := range []uint64{MaxEncryptions, MaxEncryptions + 1} {
			t.Run(fmt.Sprintf("%s_%d", side, count), func(t *testing.T) {
				tx := validTransaction(t, OpReencrypt)
				if side == "source" {
					tx.Source.ItemCount = count
				} else {
					tx.Target.ItemCount = count
				}
				if count == MaxEncryptions {
					checkTransactionRoundTrip(t, tx)
					return
				}
				if _, err := SealTransaction(tx, v["dek"], v["target_key"]); !errors.Is(err, ErrCorrupt) {
					t.Fatalf("oversized item count accepted: %v", err)
				}
			})
		}
		// Verify decoder rejection with a valid source MAC, independent of Seal's
		// validation. The last fields are source_count, target_count, cleanup_count.
		t.Run(side+"_authenticated_wire_overflow", func(t *testing.T) {
			tx := validTransaction(t, OpReencrypt)
			p, err := tx.payload()
			if err != nil {
				t.Fatal(err)
			}
			offset := len(p) - 18
			if side == "target" {
				offset += 8
			}
			binary.BigEndian.PutUint64(p[offset:offset+8], MaxEncryptions+1)
			mac, err := transactionMAC(tx.Source, v["dek"], p)
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(stateEnvelope{Payload: base64.StdEncoding.EncodeToString(p), SourceMAC: base64.StdEncoding.EncodeToString(mac)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenTransaction(b, v["dek"], sourceIdentity(), false); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("oversized wire count: %v", err)
			}
		})
	}
}
