package format

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
)

const (
	// MaxStateBytes bounds the complete JSON state envelope.
	MaxStateBytes    = 16 * 1024
	transactionMagic = "XOPSTXNS"
)

// Operation identifies a maintenance operation, not a normal item write.
type Operation byte

const (
	// OpInit creates a new vault.
	OpInit Operation = iota + 1
	// OpRewrap changes wrapping material while retaining the DEK.
	OpRewrap
	// OpReencrypt creates a new DEK.
	OpReencrypt
	// OpRestore restores a trusted backup under a new DEK.
	OpRestore
	// OpClone creates an independent vault.
	OpClone
	// OpPrune cleans explicitly selected obsolete revisions.
	OpPrune
)

// Stage is a recovery hint, never proof of the current durable publication.
type Stage byte

const (
	// Prepared records intent before target construction.
	Prepared Stage = iota + 1
	// Building records incomplete target construction.
	Building
	// Verified records a fully validated and synced target.
	Verified
	// Published records a pointer switch which must still be checked.
	Published
	// Committed records confirmed durable publication.
	Committed
	// CleanupPending records explicitly requested unfinished cleanup.
	CleanupPending
)

// Endpoint identifies one transaction side and its authenticated snapshot.
type Endpoint struct {
	VaultID      [16]byte
	StoreID      string
	Revision     uint64
	Generation   uint64
	MetaHash     [32]byte
	ManifestRoot [32]byte
	ItemCount    uint64
}

func (e Endpoint) validate() error {
	if e.Revision == 0 || e.Generation == 0 || e.ItemCount > MaxEncryptions {
		return ErrCorrupt
	}
	return identifier(e.StoreID)
}

// Transaction contains public state only. Validate current files before recovery actions.
type Transaction struct {
	OperationID      [16]byte
	Operation        Operation
	Stage            Stage
	Source           Endpoint
	Target           Endpoint
	CleanupRevisions []uint64
}

func (t Transaction) validate() error {
	if t.Operation < OpInit || t.Operation > OpPrune || t.Stage < Prepared || t.Stage > CleanupPending {
		return ErrUnsupported
	}
	if t.OperationID == ([16]byte{}) {
		return ErrCorrupt
	}
	if err := t.Target.validate(); err != nil {
		return err
	}
	if t.Operation == OpInit {
		if t.Source != (Endpoint{}) {
			return ErrCorrupt
		}
	} else if err := t.Source.validate(); err != nil {
		return err
	}
	if len(t.CleanupRevisions) > 256 || (len(t.CleanupRevisions) > 0 && t.Operation != OpPrune) {
		return ErrCorrupt
	}
	for at, n := range t.CleanupRevisions {
		if n == 0 || n == t.Target.Revision || (at > 0 && n <= t.CleanupRevisions[at-1]) {
			return ErrCorrupt
		}
	}
	return t.validateRelations()
}

func (t Transaction) validateRelations() error {
	s, d := t.Source, t.Target
	sameVault := s.VaultID == d.VaultID && s.StoreID == d.StoreID
	switch t.Operation {
	case OpRewrap:
		if !sameVault || s.Generation != d.Generation || d.Revision <= s.Revision {
			return ErrCorrupt
		}
	case OpReencrypt, OpRestore:
		if !sameVault || d.Generation <= s.Generation || d.Revision <= s.Revision {
			return ErrCorrupt
		}
	case OpClone:
		if s.VaultID == d.VaultID {
			return ErrCorrupt
		}
	case OpPrune:
		if s != d {
			return ErrCorrupt
		}
	}
	if t.Operation != OpInit && (s.MetaHash == ([32]byte{}) || s.ManifestRoot == ([32]byte{})) {
		return ErrCorrupt
	}
	if t.Stage >= Verified && (d.MetaHash == ([32]byte{}) || d.ManifestRoot == ([32]byte{})) {
		return ErrCorrupt
	}
	return nil
}

func (t Transaction) payload() ([]byte, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	b := append([]byte(transactionMagic), 0, Version)
	b = append(b, t.OperationID[:]...)
	b = append(b, byte(t.Operation), byte(t.Stage))
	b = append(b, t.Source.VaultID[:]...)
	b = append(b, t.Target.VaultID[:]...)
	b = lp(lp(b, t.Source.StoreID), t.Target.StoreID)
	for _, n := range []uint64{t.Source.Revision, t.Target.Revision, t.Source.Generation, t.Target.Generation} {
		b = binary.BigEndian.AppendUint64(b, n)
	}
	b = append(b, t.Source.MetaHash[:]...)
	b = append(b, t.Target.MetaHash[:]...)
	b = append(b, t.Source.ManifestRoot[:]...)
	b = append(b, t.Target.ManifestRoot[:]...)
	b = binary.BigEndian.AppendUint64(b, t.Source.ItemCount)
	b = binary.BigEndian.AppendUint64(b, t.Target.ItemCount)
	b = binary.BigEndian.AppendUint16(b, uint16(len(t.CleanupRevisions)))
	for _, n := range t.CleanupRevisions {
		b = binary.BigEndian.AppendUint64(b, n)
	}
	return b, nil
}

func parseTransactionPayload(b []byte) (Transaction, error) {
	if len(b) < 10 || string(b[:8]) != transactionMagic {
		return Transaction{}, ErrCorrupt
	}
	if binary.BigEndian.Uint16(b[8:10]) != Version {
		return Transaction{}, ErrUnsupported
	}
	d := decoder{b: b[10:]}
	var t Transaction
	copy(t.OperationID[:], d.take(16))
	t.Operation, t.Stage = Operation(d.u8()), Stage(d.u8())
	copy(t.Source.VaultID[:], d.take(16))
	copy(t.Target.VaultID[:], d.take(16))
	t.Source.StoreID, t.Target.StoreID = d.id(), d.id()
	t.Source.Revision, t.Target.Revision = d.u64(), d.u64()
	t.Source.Generation, t.Target.Generation = d.u64(), d.u64()
	copy(t.Source.MetaHash[:], d.take(32))
	copy(t.Target.MetaHash[:], d.take(32))
	copy(t.Source.ManifestRoot[:], d.take(32))
	copy(t.Target.ManifestRoot[:], d.take(32))
	t.Source.ItemCount, t.Target.ItemCount = d.u64(), d.u64()
	count := int(d.u16())
	if count > 256 || count > len(d.b)/8 {
		return Transaction{}, ErrCorrupt
	}
	t.CleanupRevisions = make([]uint64, count)
	for i := range t.CleanupRevisions {
		t.CleanupRevisions[i] = d.u64()
	}
	if err := d.done(); err != nil {
		return Transaction{}, err
	}
	if err := t.validate(); err != nil {
		return Transaction{}, err
	}
	return t, nil
}

type stateEnvelope struct {
	Payload   string `json:"payload"`
	SourceMAC string `json:"source_mac"`
	TargetMAC string `json:"target_mac"`
}

func transactionMAC(endpoint Endpoint, key, payload []byte) ([]byte, error) {
	if err := endpoint.validate(); err != nil {
		return nil, err
	}
	info := lp(nil, "XOps/encrypted-file/v1/transaction-mac")
	info = lp(info, endpoint.StoreID)
	info = binary.BigEndian.AppendUint64(info, endpoint.Generation)
	k, err := derive(key, endpoint.VaultID[:], info)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	m := hmac.New(sha256.New, k)
	if _, err := m.Write(payload); err != nil {
		return nil, err
	}
	return m.Sum(nil), nil
}

// SealTransaction authenticates all state under the supplied source and/or target
// keys. Missing keys produce empty MAC fields; at least one valid key is required.
func SealTransaction(t Transaction, sourceKey, targetKey []byte) ([]byte, error) {
	p, err := t.payload()
	if err != nil {
		return nil, err
	}
	if len(sourceKey) == 0 && len(targetKey) == 0 {
		return nil, ErrCorrupt
	}
	e := stateEnvelope{Payload: base64.StdEncoding.EncodeToString(p)}
	if len(sourceKey) > 0 {
		m, err := transactionMAC(t.Source, sourceKey, p)
		if err != nil {
			return nil, err
		}
		e.SourceMAC = base64.StdEncoding.EncodeToString(m)
	}
	if len(targetKey) > 0 {
		m, err := transactionMAC(t.Target, targetKey, p)
		if err != nil {
			return nil, err
		}
		e.TargetMAC = base64.StdEncoding.EncodeToString(m)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxStateBytes {
		return nil, ErrCorrupt
	}
	return b, nil
}

func parseEnvelope(b []byte) (map[string][]byte, error) {
	if len(b) > MaxStateBytes {
		return nil, ErrCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(b))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrCorrupt
	}
	fields := make(map[string][]byte, 3)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, ErrCorrupt
		}
		name, ok := token.(string)
		if !ok || (name != "payload" && name != "source_mac" && name != "target_mac") {
			return nil, ErrCorrupt
		}
		if _, exists := fields[name]; exists {
			return nil, ErrCorrupt
		}
		decoded, err := decodeStateField(d, name)
		if err != nil {
			return nil, err
		}
		fields[name] = decoded
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrCorrupt
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrCorrupt
	}
	if len(fields) != 3 {
		return nil, ErrCorrupt
	}
	return fields, nil
}

func decodeStateField(d *json.Decoder, name string) ([]byte, error) {
	token, err := d.Token()
	value, ok := token.(string)
	if err != nil || !ok {
		return nil, ErrCorrupt
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, ErrCorrupt
	}
	if name != "payload" && len(decoded) != 0 && len(decoded) != 32 {
		return nil, ErrCorrupt
	}
	return decoded, nil
}

// KeyIdentity identifies a vault key independently of a publication or item.
type KeyIdentity struct {
	VaultID    [16]byte
	Generation uint64
	StoreID    string
}

// OpenTransaction verifies the selected side against a trusted expected key
// identity. It does not assert that the other side or any file is recoverable.
func OpenTransaction(data, key []byte, expected KeyIdentity, target bool) (Transaction, error) {
	if expected.Generation == 0 || identifier(expected.StoreID) != nil {
		return Transaction{}, ErrIdentity
	}
	fields, err := parseEnvelope(data)
	if err != nil {
		return Transaction{}, err
	}
	t, err := parseTransactionPayload(fields["payload"])
	if err != nil {
		return Transaction{}, err
	}
	e, macName := t.Source, "source_mac"
	if target {
		e, macName = t.Target, "target_mac"
	}
	if e.VaultID != expected.VaultID || e.Generation != expected.Generation || e.StoreID != expected.StoreID {
		return Transaction{}, ErrIdentity
	}
	m, err := transactionMAC(e, key, fields["payload"])
	if err != nil {
		return Transaction{}, err
	}
	if !hmac.Equal(m, fields[macName]) {
		return Transaction{}, ErrCorrupt
	}
	return t, nil
}
