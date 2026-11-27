package hostkey

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/ports"
)

// entryMarker 标识 known_hosts 单行的可选标记前缀（普通、@revoked 或 @cert-authority）。
type entryMarker uint8

const (
	markerRegular entryMarker = iota
	markerRevoked
	markerCertAuthority
)

// parsedEntry 表示从 known_hosts 单行解析出的已校验主机密钥条目。
type parsedEntry struct {
	marker       entryMarker
	hostField    string
	isHashed     bool
	hashedSalt   []byte
	hashedDigest []byte
	algorithm    string
	wireBlob     []byte
	fingerprint  inventory.KeyFingerprint
}

// parseKnownHostsSnapshot 解析整份 known_hosts 字节快照，返回全部格式合法的条目。
// 为对齐 OpenSSH 容错行为，空行、注释行与无法识别的畸形行安全跳过，绝不凭残缺条目授予信任。
func parseKnownHostsSnapshot(raw []byte) []parsedEntry {
	if len(raw) == 0 {
		return nil
	}
	var out []parsedEntry
	for line := range strings.SplitSeq(string(raw), "\n") {
		if entry, err := parseKnownHostsLine(line); err == nil {
			out = append(out, entry)
		}
	}
	return out
}

func parseKnownHostsLine(rawLine string) (parsedEntry, error) {
	line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
	if line == "" || line[0] == '#' {
		return parsedEntry{}, io.EOF
	}
	marker, rest, ok := cutEntryMarker(line)
	if !ok {
		return parsedEntry{}, domi18n.E(domi18n.KeyHostKeyLineMalformed, domi18n.Str("reason", "invalid marker"))
	}
	hostField, rest, ok := cutSpaceField(rest)
	if !ok {
		return parsedEntry{}, domi18n.E(domi18n.KeyHostKeyLineMalformed, domi18n.Str("reason", "missing host field"))
	}
	algo, rest, ok := cutSpaceField(rest)
	if !ok {
		return parsedEntry{}, domi18n.E(domi18n.KeyHostKeyLineMalformed, domi18n.Str("reason", "missing algorithm field"))
	}
	keyB64, _, ok := cutSpaceField(rest)
	if !ok {
		return parsedEntry{}, domi18n.E(domi18n.KeyHostKeyLineMalformed, domi18n.Str("reason", "missing public key field"))
	}
	blob, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(blob) == 0 {
		return parsedEntry{}, domi18n.E(domi18n.KeyHostKeyLineMalformed, domi18n.Str("reason", "invalid base64 public key"))
	}
	entry := parsedEntry{
		marker:      marker,
		hostField:   hostField,
		algorithm:   algo,
		wireBlob:    blob,
		fingerprint: inventory.KeyFingerprintFromSHA256(sha256.Sum256(blob)),
	}
	if strings.HasPrefix(hostField, "|1|") {
		salt, digest, hErr := decodeHashedHostField(hostField)
		if hErr != nil {
			return parsedEntry{}, hErr
		}
		entry.isHashed = true
		entry.hashedSalt = salt
		entry.hashedDigest = digest
	}
	return entry, nil
}

func decodeHashedHostField(field string) (salt, digest []byte, err error) {
	rest := strings.TrimPrefix(field, "|1|")
	saltB64, hashB64, ok := strings.Cut(rest, "|")
	if !ok || saltB64 == "" || hashB64 == "" || strings.ContainsRune(hashB64, '|') {
		return nil, nil, domi18n.E(domi18n.KeyHostKeyLineMalformed, domi18n.Str("reason", "malformed hashed host field"))
	}
	salt, err = base64.StdEncoding.DecodeString(saltB64)
	if err != nil || len(salt) == 0 {
		return nil, nil, domi18n.E(domi18n.KeyHostKeyLineMalformed, domi18n.Str("reason", "invalid hashed host salt"))
	}
	digest, err = base64.StdEncoding.DecodeString(hashB64)
	if err != nil || len(digest) != sha1.Size {
		return nil, nil, domi18n.E(domi18n.KeyHostKeyLineMalformed, domi18n.Str("reason", "invalid hashed host digest"))
	}
	return salt, digest, nil
}

func cutEntryMarker(line string) (entryMarker, string, bool) {
	if line[0] != '@' {
		return markerRegular, line, true
	}
	token, rest, ok := cutSpaceField(line)
	if !ok || rest == "" {
		return markerRegular, "", false
	}
	switch token {
	case "@revoked":
		return markerRevoked, rest, true
	case "@cert-authority":
		return markerCertAuthority, rest, true
	default:
		return markerRegular, "", false
	}
}

func cutSpaceField(s string) (field, rest string, ok bool) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", "", false
	}
	idx := strings.IndexAny(s, " \t")
	if idx < 0 {
		return s, "", true
	}
	return s[:idx], strings.TrimLeft(s[idx+1:], " \t"), true
}

// matchesEndpoint 严格依据 OpenSSH known_hosts 规则与 INV-E2 端口隔离不变量判断条目是否命中目标端点。
// 端口 22 匹配无方括号规范主机与显式 "[<host>]:22"；非 22 端口仅匹配 "[<host>]:<port>"。
func (e parsedEntry) matchesEndpoint(ep netaddr.Endpoint) bool {
	if !ep.IsValid() || e.hostField == "" {
		return false
	}
	candidates := endpointMatchCandidates(ep)
	if e.isHashed {
		return matchHashedHostEntry(e.hashedSalt, e.hashedDigest, candidates)
	}
	return matchPatternHostList(e.hostField, candidates)
}

func endpointMatchCandidates(ep netaddr.Endpoint) []string {
	primary := ep.KnownHostsKey()
	if ep.Port() == netaddr.DefaultSSHPort {
		return []string{primary, "[" + ep.Host().String() + "]:22"}
	}
	return []string{primary}
}

// matchHashedHostEntry 验证已预解码的 OpenSSH HashKnownHosts HMAC-SHA1 摘要。
func matchHashedHostEntry(salt, want []byte, candidates []string) bool {
	if len(salt) == 0 || len(want) != sha1.Size {
		return false
	}
	for _, cand := range candidates {
		if subtle.ConstantTimeCompare(computeHostHMACSHA1(salt, cand), want) == 1 {
			return true
		}
	}
	return false
}

func computeHostHMACSHA1(salt []byte, candidate string) []byte {
	mac := hmac.New(sha1.New, salt)
	_, _ = mac.Write([]byte(candidate))
	return mac.Sum(nil)
}

// matchPatternHostList 按 OpenSSH 逗号分隔主机列表执行正向/否定通配匹配；命中任意 !pattern 即整体否定。
func matchPatternHostList(field string, candidates []string) bool {
	matchedPositive := false
	for pat := range strings.SplitSeq(field, ",") {
		if pat == "" {
			continue
		}
		if neg, isNeg := strings.CutPrefix(pat, "!"); isNeg {
			if matchAnyCandidate(neg, candidates) {
				return false
			}
			continue
		}
		if matchAnyCandidate(pat, candidates) {
			matchedPositive = true
		}
	}
	return matchedPositive
}

func matchAnyCandidate(pattern string, candidates []string) bool {
	lowPat := strings.ToLower(pattern)
	for _, cand := range candidates {
		if matchWildcard(lowPat, strings.ToLower(cand)) {
			return true
		}
	}
	return false
}

// matchWildcard 执行线性时间、零回溯爆炸风险的 '*' / '?' 通配符匹配。
func matchWildcard(pattern, text string) bool {
	pi, ti := 0, 0
	starIdx, matchIdx := -1, 0
	for ti < len(text) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == text[ti]):
			pi++
			ti++
		case pi < len(pattern) && pattern[pi] == '*':
			starIdx = pi
			matchIdx = ti
			pi++
		case starIdx >= 0:
			pi = starIdx + 1
			matchIdx++
			ti = matchIdx
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// formatHostField 按明文或 OpenSSH |1|<salt>|<hmac-sha1> 哈希格式生成写入 known_hosts 的主机字段。
func formatHostField(ep netaddr.Endpoint, hashHost bool, entropy io.Reader) (string, error) {
	key := ep.KnownHostsKey()
	if !hashHost {
		return key, nil
	}
	if entropy == nil {
		return "", domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonMissingDep, domi18n.Str("component", "Entropy"))
	}
	var salt [sshHashSaltBytes]byte
	if _, err := io.ReadFull(entropy, salt[:]); err != nil {
		return "", domi18n.WrapSentinel(ports.ErrEntropyShortRead, err)
	}
	mac := hmac.New(sha1.New, salt[:])
	_, _ = mac.Write([]byte(key))
	sum := mac.Sum(nil)
	return "|1|" + base64.StdEncoding.EncodeToString(salt[:]) + "|" + base64.StdEncoding.EncodeToString(sum), nil
}

// formatKnownHostsRecord 格式化单条可落盘的 OpenSSH known_hosts 记录（不含尾部换行）。
func formatKnownHostsRecord(hostField string, key ports.PublicKeyInfo) string {
	b64 := base64.StdEncoding.EncodeToString(key.WireBlob())
	comment := strings.TrimSpace(key.Comment())
	if comment == "" {
		return hostField + " " + key.Algorithm() + " " + b64
	}
	return hostField + " " + key.Algorithm() + " " + b64 + " " + comment
}

func keyBlobEqual(a, b []byte) bool {
	return len(a) > 0 && len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
