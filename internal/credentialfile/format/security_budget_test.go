package format

import (
	"encoding/binary"
	"math/big"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func powerOfTwo(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }

func inversePower(n uint) *big.Rat { return new(big.Rat).SetFrac(big.NewInt(1), powerOfTwo(n)) }

// TestEngineeringSecurityBudget makes the documented conditional model
// reproducible. Passing this test is not a proof of the model's assumptions.
func TestEngineeringSecurityBudget(t *testing.T) {
	i := identity()
	i.Ref.StoreID, i.Ref.ItemID = strings.Repeat("s", MaxIDBytes), strings.Repeat("i", MaxIDBytes)
	secret := credential.NewSecret(make([]byte, MaxSecretBytes))
	defer secret.Zero()
	data, err := SealItem(i, [12]byte{}, make([]byte, 32), secret)
	if err != nil {
		t.Fatal(err)
	}
	headerBytes := uint64(binary.BigEndian.Uint16(data[10:12]))
	blocks := (headerBytes+15)/16 + (MaxSecretBytes+15)/16 + 1
	if blocks != 4230 {
		t.Fatalf("security assessment must be updated for L=%d", blocks)
	}
	q := uint64(MaxEncryptions)
	nonce := new(big.Rat).SetFrac(new(big.Int).SetUint64(q*(q-1)), powerOfTwo(97))
	ql := new(big.Int).SetUint64(q * blocks)
	confNumerator := new(big.Int).Mul(ql, ql)
	confNumerator.Mul(confNumerator, big.NewInt(2))
	conf := new(big.Rat).SetFrac(confNumerator, powerOfTwo(128))
	if nonce.Cmp(inversePower(57)) >= 0 || conf.Cmp(inversePower(62)) >= 0 {
		t.Fatal("documented per-key budget changed")
	}
	t.Logf("AAD=%d L=%d qL=%d nonce=%s confidentiality_main=%s", headerBytes, blocks, q*blocks, nonce.FloatString(30), conf.FloatString(30))
	for _, attempts := range []uint64{1, MaxEncryptions, 1 << 32} {
		sigma := new(big.Int).SetUint64((q+attempts)*blocks + 1)
		switchNumerator := new(big.Int).Mul(sigma, sigma)
		switchNumerator.Mul(switchNumerator, big.NewInt(2))
		switching := new(big.Rat).SetFrac(switchNumerator, powerOfTwo(128))
		vl := new(big.Int).SetUint64(attempts * blocks)
		poly := new(big.Rat).SetFrac(vl, new(big.Int).Sub(powerOfTwo(128), vl))
		total := new(big.Rat).Add(nonce, switching)
		total.Add(total, poly)
		if attempts <= q && total.Cmp(inversePower(56)) >= 0 {
			t.Fatal("conditional engineering envelope changed")
		}
		t.Logf("v=%d sigma=%s polynomial=%s engineering_envelope=%s", attempts, sigma.String(), poly.FloatString(45), total.FloatString(30))
	}
}
