package ssh

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"slices"
	"strings"
)

// HopDigest is a 32-byte Merkle SHA-256 identity binding a hop's complete
// ClientConfig behavioral state and its upstream parent hop's HopDigest.
type HopDigest [32]byte

// ZeroHopDigest is the parent digest for a direct (non-proxied) root hop.
var ZeroHopDigest HopDigest

var (
	// ErrInvalidHopDigest indicates a malformed textual HopDigest.
	ErrInvalidHopDigest = errors.New("invalid hop digest")
	// ErrDigestTagIncomplete indicates a struct field missing a valid digest:"include"
	// or digest:"exclude,reason=..." tag.
	ErrDigestTagIncomplete = errors.New("incomplete digest struct tags")
)

const hopDigestDomain = "xops.ssh.hop_digest.v1\x00"

var (
	clientConfigReflectType     = reflect.TypeFor[ClientConfig]()
	connectionConfigReflectType = reflect.TypeFor[ConnectionConfig]()
	optionsReflectType          = reflect.TypeFor[Options]()
	controlConfigReflectType    = reflect.TypeFor[ControlConfig]()
)

// IsZero reports whether d is the all-zero ZeroHopDigest.
func (d HopDigest) IsZero() bool { return d == ZeroHopDigest }

// Equal reports whether d and other contain identical digest bytes.
func (d HopDigest) Equal(other HopDigest) bool { return d == other }

// String returns the canonical 64-character lowercase hexadecimal encoding of d.
func (d HopDigest) String() string { return hex.EncodeToString(d[:]) }

// ParseHopDigest parses a 64-character hexadecimal SHA-256 string into a HopDigest.
func ParseHopDigest(raw string) (HopDigest, error) {
	if hasControlOrLineSepChar(raw) {
		return HopDigest{}, fmt.Errorf("%w: contains control character", ErrInvalidHopDigest)
	}
	if len(raw) != 64 {
		return HopDigest{}, fmt.Errorf("%w: expected 64 hex characters, got %d", ErrInvalidHopDigest, len(raw))
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return HopDigest{}, fmt.Errorf("%w: invalid hex encoding", ErrInvalidHopDigest)
	}
	var out HopDigest
	copy(out[:], decoded)
	return out, nil
}

// DigestClientConfig computes the Merkle SHA-256 HopDigest of cfg chained with
// parent by reflecting over every field of ClientConfig and its nested structs.
//
// Every struct field visited must carry either `digest:"include"` or
// `digest:"exclude,reason=..."`. Missing or malformed digest tags panic
// (fail-closed programming error caught by ValidateDigestTags in CI).
// Options are serialized canonically in optionRegistry order, including all
// OptionClassMux (Control*) options.
func DigestClientConfig(cfg *ClientConfig, parent HopDigest) HopDigest {
	digest, err := digestClientConfigStrict(cfg, parent)
	if err != nil {
		panic(fmt.Sprintf("DigestClientConfig: %v", err))
	}
	return digest
}

func digestClientConfigStrict(cfg *ClientConfig, parent HopDigest) (HopDigest, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(hopDigestDomain))
	_, _ = h.Write([]byte{'P'})
	_, _ = h.Write(parent[:])
	if cfg == nil {
		_, _ = h.Write([]byte("N;"))
		var out HopDigest
		h.Sum(out[:0])
		return out, nil
	}
	_, _ = h.Write([]byte("C;"))
	if err := digestStructValue(h, reflect.ValueOf(cfg).Elem()); err != nil {
		return HopDigest{}, err
	}
	var out HopDigest
	h.Sum(out[:0])
	return out, nil
}

// ValidateDigestTags recursively verifies that t (and every included nested
// struct type reachable through pointers, slices, arrays, or maps) annotates
// every exported and unexported field with either `digest:"include"` or
// `digest:"exclude,reason=<non-empty>"`.
func ValidateDigestTags(t reflect.Type) error {
	if t == nil {
		return fmt.Errorf("%w: nil type", ErrDigestTagIncomplete)
	}
	visited := make(map[reflect.Type]bool)
	return validateDigestType(t, visited)
}

func validateDigestType(t reflect.Type, visited map[reflect.Type]bool) error {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() == reflect.Map {
		if err := validateDigestType(t.Key(), visited); err != nil {
			return err
		}
		return validateDigestType(t.Elem(), visited)
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	if visited[t] {
		return nil
	}
	visited[t] = true

	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		include, err := parseDigestTag(t, sf)
		if err != nil {
			return err
		}
		if !include {
			continue
		}
		if err := validateDigestType(sf.Type, visited); err != nil {
			return err
		}
	}
	return nil
}

func parseDigestTag(structType reflect.Type, sf reflect.StructField) (bool, error) {
	raw, ok := sf.Tag.Lookup("digest")
	if !ok || raw == "" {
		return false, fmt.Errorf("%w: %s.%s missing digest struct tag", ErrDigestTagIncomplete, structType.Name(), sf.Name)
	}
	if raw == "include" {
		return true, nil
	}
	if reason, ok := strings.CutPrefix(raw, "exclude,reason="); ok {
		if strings.TrimSpace(reason) == "" {
			return false, fmt.Errorf("%w: %s.%s digest exclude tag requires non-empty reason", ErrDigestTagIncomplete, structType.Name(), sf.Name)
		}
		return false, nil
	}
	return false, fmt.Errorf("%w: %s.%s has invalid digest tag %q (want \"include\" or \"exclude,reason=...\")", ErrDigestTagIncomplete, structType.Name(), sf.Name, raw)
}

func digestStructValue(h hash.Hash, v reflect.Value) error {
	t := v.Type()
	if t == optionsReflectType {
		return digestOptionsValue(h, v)
	}
	isConfig := t == clientConfigReflectType || t == connectionConfigReflectType
	writeDigestTag(h, 'S', t.Name())
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		include, err := parseDigestTag(t, sf)
		if err != nil {
			return err
		}
		if !include {
			continue
		}
		writeDigestTag(h, 'F', sf.Name)
		fv := v.Field(i)
		if isConfig {
			if handled, err := digestNormalizedConfigField(h, sf.Name, fv); handled {
				if err != nil {
					return err
				}
				continue
			}
		}
		if err := digestReflectValue(h, fv); err != nil {
			return fmt.Errorf("%s.%s: %w", t.Name(), sf.Name, err)
		}
	}
	_, _ = h.Write([]byte{'}'})
	return nil
}

func digestNormalizedConfigField(h hash.Hash, fieldName string, fv reflect.Value) (bool, error) {
	switch fieldName {
	case "Address", "BaseHost":
		writeDigestString(h, canonicalDigestHost(fv.String()))
		return true, nil
	case "Port":
		port := fv.Int()
		if port == 0 {
			port = int64(DefaultSSHPort)
		}
		writeDigestInt64(h, port)
		return true, nil
	case "AuthType":
		writeDigestString(h, normalizeAuthType(fv.String()))
		return true, nil
	case "OriginalHost", "CanonicalHost":
		writeDigestString(h, strings.TrimSpace(fv.String()))
		return true, nil
	case "Options":
		if fv.Kind() == reflect.Pointer && fv.Type().Elem() == optionsReflectType {
			return true, digestOptionsPointer(h, fv)
		}
	case "Control":
		if fv.Kind() == reflect.Pointer && fv.Type().Elem() == controlConfigReflectType {
			return true, digestControlPointer(h, fv)
		}
	}
	return false, nil
}

func digestControlPointer(h hash.Hash, ptr reflect.Value) error {
	if err := ValidateDigestTags(controlConfigReflectType); err != nil {
		return err
	}
	if ptr.IsNil() {
		_, _ = h.Write([]byte("C0;"))
		return nil
	}
	ctrl, _ := ptr.Interface().(*ControlConfig)
	norm := normalizeControlConfig(ctrl)
	if norm == nil {
		_, _ = h.Write([]byte("C0;"))
		return nil
	}
	_, _ = h.Write([]byte("C1;"))
	return digestStructValue(h, reflect.ValueOf(*norm))
}

func canonicalDigestHost(raw string) string {
	if raw == "" {
		return ""
	}
	if ep, err := NewEndpoint(raw, int(DefaultSSHPort)); err == nil {
		return ep.Host()
	}
	return cleanHostLiteral(raw)
}

func digestOptionsPointer(h hash.Hash, ptr reflect.Value) error {
	if err := ValidateDigestTags(optionsReflectType); err != nil {
		return err
	}
	if ptr.IsNil() {
		_, _ = h.Write([]byte("O0;"))
		return nil
	}
	return digestOptionsValue(h, ptr.Elem())
}

func digestOptionsValue(h hash.Hash, v reflect.Value) error {
	t := v.Type()
	valuesField := v.FieldByName("values")
	allExtraZero := true
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		include, err := parseDigestTag(t, sf)
		if err != nil {
			return err
		}
		if !include || sf.Name == "values" {
			continue
		}
		if !v.Field(i).IsZero() {
			allExtraZero = false
		}
	}
	if valuesField.Len() == 0 && allExtraZero {
		_, _ = h.Write([]byte("O0;"))
		return nil
	}
	_, _ = h.Write([]byte("O1;"))
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		include, err := parseDigestTag(t, sf)
		if err != nil {
			return err
		}
		if !include || sf.Name == "values" {
			continue
		}
		writeDigestTag(h, 'F', sf.Name)
		if err := digestReflectValue(h, v.Field(i)); err != nil {
			return fmt.Errorf("%s.%s: %w", t.Name(), sf.Name, err)
		}
	}
	digestOptionsValuesMap(h, valuesField)
	_, _ = h.Write([]byte{'}'})
	return nil
}

func digestOptionsValuesMap(h hash.Hash, valuesField reflect.Value) {
	// Serialize options canonically in optionRegistry order (including Control*
	// / OptionClassMux and all other classes).
	seen := make(map[string]struct{}, valuesField.Len())
	for _, spec := range optionRegistry {
		mv := valuesField.MapIndex(reflect.ValueOf(spec.CanonicalKey))
		if !mv.IsValid() {
			continue
		}
		val := mv.String()
		if val == "" {
			continue
		}
		writeDigestTag(h, 'K', spec.CanonicalKey)
		writeDigestString(h, val)
		seen[spec.CanonicalKey] = struct{}{}
	}
	// Fail-closed: deterministically hash any non-registry key still present in values.
	if len(seen) < valuesField.Len() {
		var extras []string
		iter := valuesField.MapRange()
		for iter.Next() {
			k := iter.Key().String()
			if _, ok := seen[k]; !ok && iter.Value().String() != "" {
				extras = append(extras, k)
			}
		}
		slices.Sort(extras)
		for _, k := range extras {
			writeDigestTag(h, 'X', k)
			writeDigestString(h, valuesField.MapIndex(reflect.ValueOf(k)).String())
		}
	}
}

func digestReflectValue(h hash.Hash, v reflect.Value) error {
	switch v.Kind() {
	case reflect.Bool:
		writeDigestBool(h, v.Bool())
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		writeDigestInt64(h, v.Int())
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		writeDigestUint64(h, v.Uint())
		return nil
	case reflect.String:
		writeDigestString(h, v.String())
		return nil
	case reflect.Pointer:
		if v.IsNil() {
			_, _ = h.Write([]byte("p0;"))
			return nil
		}
		_, _ = h.Write([]byte("p1;"))
		return digestReflectValue(h, v.Elem())
	case reflect.Slice, reflect.Array:
		return digestSequenceValue(h, v)
	case reflect.Map:
		return digestMapValue(h, v)
	case reflect.Struct:
		return digestStructValue(h, v)
	default:
		return fmt.Errorf("%w: unsupported reflected kind %s", ErrDigestTagIncomplete, v.Kind())
	}
}

func digestSequenceValue(h hash.Hash, v reflect.Value) error {
	n := v.Len()
	writeDigestUint64(h, uint64(n))
	_, _ = h.Write([]byte{'['})
	if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
		buf := make([]byte, n)
		for i := 0; i < n; i++ {
			buf[i] = byte(v.Index(i).Uint())
		}
		_, _ = h.Write(buf)
		_, _ = h.Write([]byte{']', ';'})
		return nil
	}
	for i := 0; i < n; i++ {
		if err := digestReflectValue(h, v.Index(i)); err != nil {
			return err
		}
	}
	_, _ = h.Write([]byte{']', ';'})
	return nil
}

func digestMapValue(h hash.Hash, v reflect.Value) error {
	if v.Type().Key().Kind() != reflect.String {
		return fmt.Errorf("%w: unsupported map key kind %s", ErrDigestTagIncomplete, v.Type().Key().Kind())
	}
	keys := make([]string, 0, v.Len())
	iter := v.MapRange()
	for iter.Next() {
		keys = append(keys, iter.Key().String())
	}
	slices.Sort(keys)
	writeDigestUint64(h, uint64(len(keys)))
	_, _ = h.Write([]byte{'{'})
	for _, k := range keys {
		writeDigestString(h, k)
		if err := digestReflectValue(h, v.MapIndex(reflect.ValueOf(k))); err != nil {
			return err
		}
	}
	_, _ = h.Write([]byte{'}', ';'})
	return nil
}

func writeDigestTag(h hash.Hash, tag byte, label string) {
	_, _ = h.Write([]byte{tag})
	writeDigestString(h, label)
}

func writeDigestString(h hash.Hash, s string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
	_, _ = h.Write([]byte{'s'})
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{';'})
}

func writeDigestBool(h hash.Hash, v bool) {
	if v {
		_, _ = h.Write([]byte{'b', '1', ';'})
	} else {
		_, _ = h.Write([]byte{'b', '0', ';'})
	}
}

func writeDigestInt64(h hash.Hash, v int64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	_, _ = h.Write([]byte{'i'})
	_, _ = h.Write(buf[:])
	_, _ = h.Write([]byte{';'})
}

func writeDigestUint64(h hash.Hash, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	_, _ = h.Write([]byte{'u'})
	_, _ = h.Write(buf[:])
	_, _ = h.Write([]byte{';'})
}
