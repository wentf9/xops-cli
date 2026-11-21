package ssh

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"strings"
	"sync/atomic"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

const (
	sshfpFingerprintSHA256 = 2
	sshfpLookupTimeout     = 5 * time.Second
)

// sshfpAlgorithmForKey maps a host key to its RFC 4255/6594/7479 SSHFP algorithm number.
func sshfpAlgorithmForKey(key cryptoSSH.PublicKey) (uint8, bool) {
	if key == nil {
		return 0, false
	}
	switch key.Type() {
	case cryptoSSH.KeyAlgoRSA:
		return 1, true
	case "ssh-dss": // DSA, still defined by RFC 4255 for SSHFP.
		return 2, true
	case cryptoSSH.KeyAlgoECDSA256, cryptoSSH.KeyAlgoECDSA384, cryptoSSH.KeyAlgoECDSA521:
		return 3, true
	case cryptoSSH.KeyAlgoED25519:
		return 4, true
	default:
		return 0, false
	}
}

// EvaluateSSHFP compares DNS SSHFP records against key. Only SHA-256
// (fingerprint type 2, 32 bytes, non-zero algorithm) records are considered;
// SHA-1 records are ignored entirely. When the DNS answer is DNSSEC-authenticated
// (AD=1) and contains valid SHA-256 SSHFP records for another algorithm (or when
// the presented key type has no SSHFP algorithm mapping), EvaluateSSHFP fails
// closed with SSHFPStatusMismatch to prevent algorithm-downgrade MITM attacks.
func EvaluateSSHFP(result SSHFPResult, key cryptoSSH.PublicKey) SSHFPVerifyStatus {
	if key == nil {
		return SSHFPStatusNone
	}
	algo, algoOK := sshfpAlgorithmForKey(key)
	var digest [sha256.Size]byte
	if algoOK {
		digest = sha256.Sum256(key.Marshal())
	}
	consideredSameAlgo := false
	anyValidSHA256 := false
	matched := false
	for _, record := range result.Records {
		if record.FingerprintType != sshfpFingerprintSHA256 || len(record.Fingerprint) != sha256.Size || record.Algorithm == 0 {
			continue
		}
		anyValidSHA256 = true
		if !algoOK || record.Algorithm != algo {
			continue
		}
		consideredSameAlgo = true
		if subtle.ConstantTimeCompare(record.Fingerprint, digest[:]) == 1 {
			matched = true
		}
	}
	switch {
	case matched && result.Authenticated:
		return SSHFPStatusMatchedVerified
	case matched:
		return SSHFPStatusMatchedUnverified
	case consideredSameAlgo || (result.Authenticated && anyValidSHA256):
		return SSHFPStatusMismatch
	default:
		return SSHFPStatusNone
	}
}

// sshfpLookupHost returns the DNS name to query, or "" for IP literals and empty hosts.
func sshfpLookupHost(address string) string {
	host := strings.TrimSpace(address)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if host == "" {
		return ""
	}
	if zone := strings.IndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// lookupSSHFPStatus queries SSHFP only when VerifyHostKeyDNS is yes/ask and a
// resolver is injected. Lookup failures degrade to SSHFPStatusNone, which never
// grants trust.
//
// The lookup is parented to the handshake coordinator during the initial
// handshake and falls back to ctx on post-handshake transport rekeys, bounded
// by min(handshake/ConnectTimeout, 5s).
func (c *Connector) lookupSSHFPStatus(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig, key cryptoSSH.PublicKey, initialHandshakeDone ...*atomic.Bool) SSHFPVerifyStatus {
	if cfg == nil || cfg.Options == nil || c.environment.LookupSSHFP == nil {
		return SSHFPStatusNone
	}
	switch cfg.Options.VerifyHostKeyDNS() {
	case VerifyHostKeyDNSYes, VerifyHostKeyDNSAsk:
	default:
		return SSHFPStatusNone
	}
	host := sshfpLookupHost(cfg.Address)
	if host == "" {
		return SSHFPStatusNone
	}
	parent := ctx
	if parent == nil {
		parent = c.lifecycleCtx
	}
	var handshakeDone *atomic.Bool
	if len(initialHandshakeDone) > 0 {
		handshakeDone = initialHandshakeDone[0]
	}
	if coordinator != nil && (handshakeDone == nil || !handshakeDone.Load()) {
		parent = coordinator.Context()
	}
	timeout := sshfpLookupTimeout
	if handshake := c.getNodeHandshakeTimeout(cfg); handshake > 0 && handshake < timeout {
		timeout = handshake
	}
	lookupCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	result, err := c.environment.LookupSSHFP(lookupCtx, host)
	if err != nil {
		c.getLogger().Debugf("SSHFP lookup for %s failed: %v", host, err)
		return SSHFPStatusNone
	}
	status := EvaluateSSHFP(result, key)
	c.getLogger().Debugf("SSHFP lookup for %s: %d records, authenticated=%v, status=%q", host, len(result.Records), result.Authenticated, status)
	return status
}
