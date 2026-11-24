package option

import (
	"crypto/sha1"

	"golang.org/x/text/unicode/norm"
)

func HashToken(s string) [20]byte {
	return sha1.Sum([]byte(norm.NFC.String(s)))
}
