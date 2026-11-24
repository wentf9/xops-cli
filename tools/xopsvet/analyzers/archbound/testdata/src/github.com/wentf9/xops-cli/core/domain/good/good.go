package good

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"hash"
	"io"
	"iter"
	"maps"
	"math"
	"math/bits"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

func UseAllAllowedStdlibs() int {
	var (
		_ bytes.Buffer
		_ = cmp.Compare(1, 2)
		_ = sha256.Sum256(nil)
		_ = subtle.ConstantTimeCompare(nil, nil)
		_ encoding.TextMarshaler
		_ = base64.StdEncoding
		_ = binary.BigEndian
		_ = hex.EncodedLen(0)
		_ jsontext.Encoder
		_ = jsonv2.Deterministic(true)
		_ = errors.New("x")
		_ = fmt.Sprint("x")
		_ hash.Hash
		_ io.Reader
		_ iter.Seq[int]
		_ = maps.Clone(map[string]int{})
		_ = math.Abs(-1)
		_ = bits.OnesCount(1)
		_ = netip.Addr{}
		_ = path.Clean("/")
		_ = regexp.MustCompile("a")
		_ = slices.Clone([]int{1})
		_ = sort.IntsAreSorted(nil)
		_ = strconv.Itoa(1)
		_ = strings.TrimSpace("x")
		_ = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		_ = unicode.IsLetter('a')
		_ = utf16.Encode(nil)
		_ = utf8.RuneCountInString("a")
	)
	return int(time.Second)
}
