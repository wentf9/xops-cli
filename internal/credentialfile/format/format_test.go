package format

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/crypto/argon2"
)

func vectors(t testing.TB) map[string][]byte {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]byte, len(raw))
	for k, v := range raw {
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		out[k] = b
	}
	return out
}

func identity() ItemIdentity {
	var vault [16]byte
	for i := range vault {
		vault[i] = byte(i)
	}
	return ItemIdentity{VaultID: vault, Generation: 1, Ref: credential.Ref{StoreID: "offline", ItemID: "0123456789abcdef0123456789abcdef"}}
}

func TestIndependentVectors(t *testing.T) {
	v := vectors(t)
	t.Run("argon2_reference_library", func(t *testing.T) {
		key := argon2.IDKey(v["password"], v["salt"], 3, 65536, 1, 32)
		defer clear(key)
		if !bytes.Equal(key, v["password_key"]) {
			t.Fatal("Argon2id differs from libargon2")
		}
	})
}

func TestIndependentMetaVectors(t *testing.T) {
	v := vectors(t)
	for _, tc := range []struct{ name, key string }{{"meta_password", "password_key"}, {"meta_file", "wrapping_key"}} {
		t.Run(tc.name, func(t *testing.T) {
			m, dek, err := OpenMeta(v[tc.name], v[tc.key], "offline")
			if err != nil {
				t.Fatal(err)
			}
			defer clear(dek)
			if !bytes.Equal(dek, v["dek"]) {
				t.Fatal("DEK differs")
			}
			got, err := SealMeta(m, v[tc.key], dek)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, v[tc.name]) {
				t.Fatal("meta bytes differ from independent vector")
			}
			if m.Suite == WrapKeyFile {
				key, err := KeyFileWrappingKey(m, v["file_key"])
				if err != nil {
					t.Fatal(err)
				}
				defer clear(key)
				if !bytes.Equal(key, v["wrapping_key"]) {
					t.Fatal("HKDF differs")
				}
			}
		})
	}
}

func TestIndependentItemVectors(t *testing.T) {
	v := vectors(t)
	i := identity()
	for _, name := range []string{"item", "item_expiry"} {
		t.Run(name, func(t *testing.T) {
			s, err := OpenItem(v[name], v["dek"], i)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Zero()
			if !bytes.Equal(s.Value, v["secret"]) {
				t.Fatal("secret differs")
			}
			if name == "item_expiry" && (s.ExpiresAt == nil || s.ExpiresAt.UnixNano() != 1800000000123456789) {
				t.Fatal("expiry lost")
			}
			var nonce [12]byte
			copy(nonce[:], v["nonce"])
			got, err := SealItem(i, nonce, v["dek"], s)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, v[name]) {
				t.Fatal("item bytes differ")
			}
		})
	}
}

func TestIndependentControlVectors(t *testing.T) {
	v := vectors(t)
	i := identity()
	t.Run("budget", func(t *testing.T) {
		b, err := OpenBudget(v["budget"], v["dek"], i.VaultID, 1, "offline")
		if err != nil {
			t.Fatal(err)
		}
		if b.Consumed != 3 || b.Sequence != 4 {
			t.Fatal("budget differs")
		}
		got, err := SealBudget(b, v["dek"])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, v["budget"]) {
			t.Fatal("MAC bytes differ")
		}
	})
	t.Run("current", func(t *testing.T) {
		c, err := ParseCurrent(v["current"])
		if err != nil {
			t.Fatal(err)
		}
		m, err := ParseMeta(v["meta_file"])
		if err != nil {
			t.Fatal(err)
		}
		if !c.Matches(v["meta_file"], m) || c.Matches(v["meta_password"], m) {
			t.Fatal("pointer binding failed")
		}
		got, err := c.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, v["current"]) {
			t.Fatal("CURRENT differs")
		}
	})
}

func TestAuthenticatedContainersRejectEveryByteMutation(t *testing.T) {
	v := vectors(t)
	i := identity()
	for _, name := range []string{"meta_file", "item_expiry", "budget"} {
		t.Run(name, func(t *testing.T) {
			open := func(data []byte) error {
				switch name {
				case "meta_file":
					_, key, err := OpenMeta(data, v["wrapping_key"], "offline")
					clear(key)
					return err
				case "item_expiry":
					s, err := OpenItem(data, v["dek"], i)
					s.Zero()
					return err
				default:
					_, err := OpenBudget(data, v["dek"], i.VaultID, 1, "offline")
					return err
				}
			}
			for at := range v[name] {
				bad := bytes.Clone(v[name])
				bad[at] ^= 1
				if err := open(bad); err == nil {
					t.Fatalf("accepted changed byte %d", at)
				}
				if err := open(v[name][:at]); err == nil {
					t.Fatalf("accepted truncation at %d", at)
				}
			}
			if err := open(append(bytes.Clone(v[name]), 0)); err == nil {
				t.Fatal("accepted trailing byte")
			}
		})
	}
}

func TestExpectedIdentityAndAuthenticationErrors(t *testing.T) {
	v := vectors(t)
	i := identity()
	for _, tc := range []struct {
		name   string
		change func(*ItemIdentity)
	}{
		{"vault", func(i *ItemIdentity) { i.VaultID[0] ^= 1 }},
		{"generation", func(i *ItemIdentity) { i.Generation++ }},
		{"store", func(i *ItemIdentity) { i.Ref.StoreID = "another" }},
		{"item", func(i *ItemIdentity) { i.Ref.ItemID = "another" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrong := i
			tc.change(&wrong)
			s, err := OpenItem(v["item"], v["dek"], wrong)
			defer s.Zero()
			if !errors.Is(err, ErrIdentity) || len(s.Value) != 0 {
				t.Fatal("identity accepted or secret returned")
			}
		})
	}
	_, dek, err := OpenMeta(v["meta_file"], make([]byte, 32), "offline")
	defer clear(dek)
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("wrong key: %v", err)
	}
	_, dek, err = OpenMeta(v["meta_file"], v["wrapping_key"], "other")
	clear(dek)
	if !errors.Is(err, ErrIdentity) {
		t.Fatalf("wrong store: %v", err)
	}
	_, err = OpenBudget(v["budget"], v["dek"], i.VaultID, 2, "offline")
	if !errors.Is(err, ErrIdentity) {
		t.Fatalf("wrong budget generation: %v", err)
	}
}

func TestBoundsAndOwnedResults(t *testing.T) {
	v := vectors(t)
	i := identity()
	for _, size := range []int{0, MaxSecretBytes, MaxSecretBytes + 1} {
		s := credential.NewSecret(make([]byte, size))
		data, err := SealItem(i, [12]byte{}, v["dek"], s)
		s.Zero()
		if (err == nil) != (size == MaxSecretBytes) {
			t.Fatalf("size %d: %v", size, err)
		}
		if err == nil {
			sec, err := OpenItem(data, v["dek"], i)
			if err != nil {
				t.Fatal(err)
			}
			sec.Zero()
		}
	}
	exp := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := SealItem(i, [12]byte{}, v["dek"], credential.NewSecretWithExpiry([]byte("x"), exp))
	if err == nil {
		t.Fatal("accepted overflowing timestamp")
	}
	for _, name := range []string{"..", "CON", strings.Repeat("a", MaxIDBytes)} {
		file, err := ItemFilename(name)
		if err != nil {
			t.Fatal(err)
		}
		if len(file) != 68 || strings.ContainsAny(file, "/\\") {
			t.Fatal("unsafe filename")
		}
	}
	if _, err := ItemFilename(strings.Repeat("a", MaxIDBytes+1)); err == nil {
		t.Fatal("oversized ID accepted")
	}
	data := bytes.Clone(v["meta_file"])
	m, err := ParseMeta(data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	if !bytes.Equal(m.Salt, v["file_salt"]) {
		t.Fatal("metadata aliases input")
	}
	bad := bytes.Clone(v["meta_password"])
	binary.BigEndian.PutUint32(bad[52:56], ^uint32(0))
	if _, err := ParseMeta(bad); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("KDF parameters accepted: %v", err)
	}
	b := Budget{VaultID: i.VaultID, Generation: 1, Sequence: 1, StoreID: "offline", Consumed: MaxEncryptions}
	if _, err := SealBudget(b, v["dek"]); err != nil {
		t.Fatal(err)
	}
	b.Consumed++
	if _, err := SealBudget(b, v["dek"]); err == nil {
		t.Fatal("budget overflow accepted")
	}
}

func TestMissingSuiteFieldsAreCorruption(t *testing.T) {
	v := vectors(t)
	i := identity()
	for _, name := range []string{"meta_file", "item", "budget"} {
		t.Run(name, func(t *testing.T) {
			original := v[name]
			h := int(binary.BigEndian.Uint16(original[10:12]))
			data := append(bytes.Clone(original[:prefixLen]), original[h:]...)
			binary.BigEndian.PutUint16(data[10:12], prefixLen)
			var err error
			switch name {
			case "meta_file":
				_, err = ParseMeta(data)
			case "item":
				var secret credential.Secret
				secret, err = OpenItem(data, v["dek"], i)
				secret.Zero()
			case "budget":
				_, err = OpenBudget(data, v["dek"], i.VaultID, 1, "offline")
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("missing field error = %v", err)
			}
		})
	}
}

func FuzzContainers(f *testing.F) {
	v := vectors(f)
	for _, name := range []string{"meta_file", "meta_password", "item", "item_expiry", "budget", "current"} {
		f.Add(v[name])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxItemBytes+1 {
			return
		}
		i := identity()
		_, key, err := OpenMeta(data, v["wrapping_key"], "offline")
		clear(key)
		if err == nil {
			if _, err := ParseMeta(data); err != nil {
				t.Fatal(err)
			}
		}
		s, err := OpenItem(data, v["dek"], i)
		defer s.Zero()
		if err == nil && len(s.Value) == 0 {
			t.Fatal("empty authenticated secret")
		}
		if _, err := OpenBudget(data, v["dek"], i.VaultID, 1, "offline"); err == nil && len(data) > 60+MaxIDBytes+32 {
			t.Fatal("oversized budget")
		}
		if c, err := ParseCurrent(data); err == nil {
			encoded, err := c.MarshalBinary()
			if err != nil || !bytes.Equal(encoded, data) {
				t.Fatal("noncanonical pointer accepted")
			}
		}
	})
}
