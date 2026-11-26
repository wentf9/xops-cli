package hostkey

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/ports"
)

type sshfpVerdict uint8

const (
	sshfpNone sshfpVerdict = iota
	sshfpMatched
	sshfpMismatch
)

// verifyViaSSHFP 协作 ports.SSHFPLookupPort 校验 DNSSEC 已认证（Authenticated==true）的 SSHFP 记录：
//   - IP 字面量不执行 DNS SSHFP 查询（遵循 RFC 4255）；
//   - 未认证记录（AD=0）绝不授予信任，维持 sshfpNone（Fail-Closed）；
//   - 当存在 DNSSEC 已认证 SHA-256 记录时优先按 SHA-256 严格比对，拒绝以 SHA-1 覆盖 SHA-256 冲突；
//   - 若存在任意 DNSSEC 已认证 SSHFP 记录但服务端呈递密钥不匹配或发生算法降级，严格返回 sshfpMismatch。
func (db *KnownHostsDB) verifyViaSSHFP(ctx context.Context, host netaddr.CanonicalHost, key ports.PublicKeyInfo) (sshfpVerdict, error) {
	if host.IsIP() {
		return sshfpNone, nil
	}
	recs, err := db.sshfpLookup.LookupSSHFP(ctx, host)
	if err != nil {
		if errors.Is(err, ports.ErrNotFound) {
			return sshfpNone, nil
		}
		return sshfpNone, err
	}
	return evaluateSSHFPRecords(recs, key), nil
}

func evaluateSSHFPRecords(recs []ports.SSHFPRecord, key ports.PublicKeyInfo) sshfpVerdict {
	var hasAuthSHA256, hasAuthSHA1 bool
	for _, r := range recs {
		if !r.IsValid() || !r.Authenticated() {
			continue
		}
		if r.FingerprintType() == 2 {
			hasAuthSHA256 = true
		} else if r.FingerprintType() == 1 {
			hasAuthSHA1 = true
		}
	}
	if !hasAuthSHA256 && !hasAuthSHA1 {
		return sshfpNone
	}
	algoNum, algoOK := sshfpAlgorithmNumber(key.Algorithm())
	if !algoOK {
		return sshfpMismatch
	}
	blob := key.WireBlob()
	if hasAuthSHA256 {
		sum256 := sha256.Sum256(blob)
		if matchAuthSSHFPDigest(recs, algoNum, 2, sum256[:]) {
			return sshfpMatched
		}
		return sshfpMismatch
	}
	sum1 := sha1.Sum(blob)
	if matchAuthSSHFPDigest(recs, algoNum, 1, sum1[:]) {
		return sshfpMatched
	}
	return sshfpMismatch
}

func matchAuthSSHFPDigest(recs []ports.SSHFPRecord, algoNum, fpType uint8, want []byte) bool {
	for _, r := range recs {
		if !r.IsValid() || !r.Authenticated() || r.Algorithm() != algoNum || r.FingerprintType() != fpType {
			continue
		}
		if subtle.ConstantTimeCompare(r.Digest(), want) == 1 {
			return true
		}
	}
	return false
}

func sshfpAlgorithmNumber(algo string) (uint8, bool) {
	switch algo {
	case "ssh-rsa":
		return 1, true
	case "ssh-dss":
		return 2, true
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		return 3, true
	case "ssh-ed25519":
		return 4, true
	default:
		return 0, false
	}
}
