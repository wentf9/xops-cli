package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TOTPConfig encapsulates parameters for RFC 6238 / RFC 4226 Time-based One-Time Passwords.
type TOTPConfig struct {
	Secret    []byte
	Algorithm string // "SHA1", "SHA256", "SHA512" (defaults to "SHA1")
	Digits    int    // Number of OTP digits, usually 6, 7, or 8 (defaults to 6)
	Period    int    // Time step in seconds (defaults to 30)
}

// ParseTOTPSecret parses an otpauth URI or a raw Base32 secret string into a TOTPConfig.
// It is tolerant of whitespace, hyphens, lowercase letters, and missing Base32 padding.
func ParseTOTPSecret(raw string) (TOTPConfig, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return TOTPConfig{}, errors.New("empty TOTP secret")
	}

	if strings.HasPrefix(strings.ToLower(trimmed), "otpauth://") {
		return parseOTPAuthURI(trimmed)
	}

	secretBytes, err := decodeBase32Secret(trimmed)
	if err != nil {
		return TOTPConfig{}, err
	}

	return TOTPConfig{
		Secret:    secretBytes,
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
	}, nil
}

func parseOTPAuthURI(uriStr string) (TOTPConfig, error) {
	u, err := url.Parse(uriStr)
	if err != nil {
		if urlErr, ok := errors.AsType[*url.Error](err); ok && urlErr.Err != nil {
			return TOTPConfig{}, fmt.Errorf("invalid otpauth URI: %w", urlErr.Err)
		}
		return TOTPConfig{}, errors.New("invalid otpauth URI")
	}

	if !strings.EqualFold(u.Scheme, "otpauth") {
		return TOTPConfig{}, fmt.Errorf("invalid scheme: %q, expected 'otpauth'", u.Scheme)
	}

	if !strings.EqualFold(u.Host, "totp") {
		return TOTPConfig{}, fmt.Errorf("unsupported OTP type: %q, only 'totp' is supported", u.Host)
	}

	q := u.Query()
	rawSecret := q.Get("secret")
	if rawSecret == "" {
		return TOTPConfig{}, errors.New("missing 'secret' parameter in otpauth URI")
	}

	secretBytes, err := decodeBase32Secret(rawSecret)
	if err != nil {
		return TOTPConfig{}, fmt.Errorf("invalid 'secret' parameter: %w", err)
	}

	algorithm := strings.ToUpper(strings.TrimSpace(q.Get("algorithm")))
	if algorithm == "" {
		algorithm = "SHA1"
	}
	switch algorithm {
	case "SHA1", "SHA256", "SHA512":
	default:
		clear(secretBytes)
		return TOTPConfig{}, fmt.Errorf("unsupported algorithm: %q", algorithm)
	}

	digits := 6
	if digitsStr := q.Get("digits"); digitsStr != "" {
		d, err := strconv.Atoi(digitsStr)
		if err != nil || d < 6 || d > 10 {
			clear(secretBytes)
			return TOTPConfig{}, fmt.Errorf("invalid 'digits' parameter: %q, must be between 6 and 10", digitsStr)
		}
		digits = d
	}

	period := 30
	if periodStr := q.Get("period"); periodStr != "" {
		p, err := strconv.Atoi(periodStr)
		if err != nil || p <= 0 {
			clear(secretBytes)
			return TOTPConfig{}, fmt.Errorf("invalid 'period' parameter: %q, must be positive", periodStr)
		}
		period = p
	}

	return TOTPConfig{
		Secret:    secretBytes,
		Algorithm: algorithm,
		Digits:    digits,
		Period:    period,
	}, nil
}

func decodeBase32Secret(raw string) ([]byte, error) {
	// Remove whitespace (spaces, tabs, newlines) and hyphens
	var sb strings.Builder
	for _, r := range raw {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '-' {
			continue
		}
		sb.WriteRune(r)
	}

	cleaned := strings.ToUpper(sb.String())
	cleaned = strings.TrimRight(cleaned, "=")
	if cleaned == "" {
		return nil, errors.New("empty Base32 secret")
	}

	// Add missing '=' padding to multiple of 8 if unpadded
	if rem := len(cleaned) % 8; rem != 0 {
		cleaned += strings.Repeat("=", 8-rem)
	}

	decoded, err := base32.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base32 secret: %w", err)
	}

	if len(decoded) == 0 {
		return nil, errors.New("decoded Base32 secret is empty")
	}

	return decoded, nil
}

// GenerateTOTP generates a time-based one-time password at the specified time using raw secret.
func GenerateTOTP(rawSecret string, now time.Time) (string, error) {
	cfg, err := ParseTOTPSecret(rawSecret)
	if err != nil {
		return "", err
	}
	defer clear(cfg.Secret)
	return GenerateTOTPWithConfig(cfg, now)
}

// GenerateTOTPWithConfig generates a time-based one-time password at the specified time per RFC 6238 / RFC 4226.
func GenerateTOTPWithConfig(cfg TOTPConfig, now time.Time) (string, error) {
	if len(cfg.Secret) == 0 {
		return "", errors.New("empty secret in TOTPConfig")
	}

	period := cfg.Period
	if period <= 0 {
		period = 30
	}

	digits := cfg.Digits
	if digits <= 0 {
		digits = 6
	}
	if digits < 6 || digits > 10 {
		return "", fmt.Errorf("unsupported digits %d: must be between 6 and 10", digits)
	}

	algo := strings.ToUpper(strings.TrimSpace(cfg.Algorithm))
	if algo == "" {
		algo = "SHA1"
	}

	var hasher func() hash.Hash
	switch algo {
	case "SHA1":
		hasher = sha1.New
	case "SHA256":
		hasher = sha256.New
	case "SHA512":
		hasher = sha512.New
	default:
		return "", fmt.Errorf("unsupported algorithm: %q", algo)
	}

	unixSec := now.Unix()
	if unixSec < 0 {
		return "", errors.New("time before Unix epoch is unsupported")
	}

	counter := uint64(unixSec / int64(period))
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(hasher, cfg.Secret)
	mac.Write(counterBytes[:])
	h := mac.Sum(nil)

	// RFC 4226 Section 5.3 Dynamic Truncation
	offset := h[len(h)-1] & 0x0F
	binCode := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7FFFFFFF

	var mod uint64 = 1
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	otp := uint64(binCode) % mod

	return fmt.Sprintf("%0*d", digits, otp), nil
}
