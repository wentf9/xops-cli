package ssh

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"strings"
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
// (fingerprint type 2, 32 bytes) records for the key's algorithm are considered;
// SHA-1 records are ignored entirely.
func EvaluateSSHFP(result SSHFPResult, key cryptoSSH.PublicKey) SSHFPVerifyStatus {
	algo, ok := sshfpAlgorithmForKey(key)
	if !ok {
		return SSHFPStatusNone
	}
	digest := sha256.Sum256(key.Marshal())
	considered := false
	matched := false
	for _, record := range result.Records {
		if record.Algorithm != algo || record.FingerprintType != sshfpFingerprintSHA256 || len(record.Fingerprint) != sha256.Size {
			continue
		}
		considered = true
		if subtle.ConstantTimeCompare(record.Fingerprint, digest[:]) == 1 {
			matched = true
		}
	}
	switch {
	case matched && result.Authenticated:
		return SSHFPStatusMatchedVerified
	case matched:
		return SSHFPStatusMatchedUnverified
	case considered:
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
// The lookup is parented to the handshake coordinator (when present) and bounded
// by min(handshake/ConnectTimeout, 5s).
func (c *Connector) lookupSSHFPStatus(ctx context.Context, coordinator *handshakeCoordinator, cfg *ClientConfig, key cryptoSSH.PublicKey) SSHFPVerifyStatus {
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
	if coordinator != nil {
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
