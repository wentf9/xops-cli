package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
	"time"
)

func TestTOTP_ExtremeTimestamps(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // 20 bytes "12345678901234567890"

	tests := []struct {
		name      string
		now       time.Time
		expectErr bool
	}{
		{
			name:      "Unix epoch zero",
			now:       time.Unix(0, 0),
			expectErr: false,
		},
		{
			name:      "Unix epoch 1 second",
			now:       time.Unix(1, 0),
			expectErr: false,
		},
		{
			name:      "Pre-epoch -1 second",
			now:       time.Unix(-1, 0),
			expectErr: true,
		},
		{
			name:      "Pre-epoch large negative",
			now:       time.Unix(-1000000, 0),
			expectErr: true,
		},
		{
			name:      "Zero time struct (year 0001)",
			now:       time.Time{},
			expectErr: true,
		},
		{
			name:      "Year 2038 MaxInt32",
			now:       time.Unix(math.MaxInt32, 0),
			expectErr: false,
		},
		{
			name:      "Year 2038 MaxInt32 + 1",
			now:       time.Unix(math.MaxInt32+1, 0),
			expectErr: false,
		},
		{
			name:      "MaxInt64 extreme future",
			now:       time.Unix(math.MaxInt64, 0),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otp, err := GenerateTOTP(secret, tt.now)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for timestamp %v, got OTP %q", tt.now, otp)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for timestamp %v: %v", tt.now, err)
				}
				if len(otp) != 6 {
					t.Fatalf("expected 6-digit OTP, got %q (len %d)", otp, len(otp))
				}
			}
		})
	}
}

func TestTOTP_TimeStepBoundaries(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	// Boundary at 30 seconds
	t0 := time.Unix(0, 0)
	t29 := time.Unix(29, 999999999)
	t30 := time.Unix(30, 0)
	t59 := time.Unix(59, 0)
	t60 := time.Unix(60, 0)

	otp0, err := GenerateTOTP(secret, t0)
	if err != nil {
		t.Fatal(err)
	}
	otp29, err := GenerateTOTP(secret, t29)
	if err != nil {
		t.Fatal(err)
	}
	otp30, err := GenerateTOTP(secret, t30)
	if err != nil {
		t.Fatal(err)
	}
	otp59, err := GenerateTOTP(secret, t59)
	if err != nil {
		t.Fatal(err)
	}
	otp60, err := GenerateTOTP(secret, t60)
	if err != nil {
		t.Fatal(err)
	}

	if otp0 != otp29 {
		t.Errorf("OTP at t=0 (%s) should match OTP at t=29 (%s)", otp0, otp29)
	}
	if otp29 == otp30 {
		t.Errorf("OTP at t=29 (%s) should differ from OTP at t=30 (%s)", otp29, otp30)
	}
	if otp30 != otp59 {
		t.Errorf("OTP at t=30 (%s) should match OTP at t=59 (%s)", otp30, otp59)
	}
	if otp59 == otp60 {
		t.Errorf("OTP at t=59 (%s) should differ from OTP at t=60 (%s)", otp59, otp60)
	}
}

func TestTOTP_Base32_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
	}{
		{
			name:      "Valid unpadded 2-char (1 byte)",
			input:     "MY",
			expectErr: false,
		},
		{
			name:      "Invalid unpadded 1-char (5 bits, cannot form byte)",
			input:     "M",
			expectErr: true,
		},
		{
			name:      "Invalid unpadded 3-char (15 bits, 7 unused bits)",
			input:     "MZX",
			expectErr: true,
		},
		{
			name:      "Valid unpadded 4-char (2 bytes)",
			input:     "MZXW",
			expectErr: false,
		},
		{
			name:      "Valid unpadded 5-char (3 bytes)",
			input:     "MZXW6",
			expectErr: false,
		},
		{
			name:      "Invalid unpadded 6-char (30 bits, 6 unused bits)",
			input:     "MZXW6Y",
			expectErr: true,
		},
		{
			name:      "Valid unpadded 7-char (4 bytes)",
			input:     "MZXW6YQ",
			expectErr: false,
		},
		{
			name:      "Valid unpadded 8-char (5 bytes)",
			input:     "MZXW6YTB",
			expectErr: false,
		},
		{
			name:      "Padding in middle",
			input:     "MZX=6YTB",
			expectErr: true,
		},
		{
			name:      "Non-base32 digits 8 and 9",
			input:     "MZXW89TB",
			expectErr: true,
		},
		{
			name:      "Non-base32 punctuation",
			input:     "MZXW!@#$",
			expectErr: true,
		},
		{
			name:      "Non-ASCII unicode",
			input:     "MZXW6YTB日本語",
			expectErr: true,
		},
		{
			name:      "Emoji",
			input:     "MZXW6YTB🔑",
			expectErr: true,
		},
		{
			name:      "Whitespace only",
			input:     "   \t\n\r  -  ",
			expectErr: true,
		},
		{
			name:      "Mixed lowercase with hyphens and spaces",
			input:     "mzxw-6ytb my==",
			expectErr: false,
		},
		{
			name:      "All padding characters only",
			input:     "========",
			expectErr: true,
		},
		{
			name:      "10-byte secret with spurious padding",
			input:     "JBSWY3DPEHPK3PXP==",
			expectErr: false,
		},
		{
			name:      "Padded secret with extra redundant padding",
			input:     "MZXW======",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseTOTPSecret(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got valid config with %d bytes secret", tt.input, len(cfg.Secret))
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for input %q: %v", tt.input, err)
				}
				if len(cfg.Secret) == 0 {
					t.Fatalf("expected non-empty secret for input %q", tt.input)
				}
			}
		})
	}
}

func TestTOTP_URI_SchemeCasing(t *testing.T) {
	// RFC 3986 section 3.1: URI schemes are case-insensitive.
	validSecret := "JBSWY3DPEHPK3PXP"

	casings := []struct {
		name      string
		uri       string
		expectErr bool
	}{
		{
			name:      "lowercase scheme",
			uri:       "otpauth://totp/Test?secret=" + validSecret,
			expectErr: false,
		},
		{
			name:      "UPPERCASE scheme",
			uri:       "OTPAUTH://totp/Test?secret=" + validSecret,
			expectErr: false,
		},
		{
			name:      "Titlecase scheme",
			uri:       "Otpauth://totp/Test?secret=" + validSecret,
			expectErr: false,
		},
		{
			name:      "UPPERCASE host",
			uri:       "otpauth://TOTP/Test?secret=" + validSecret,
			expectErr: false,
		},
		{
			name:      "Titlecase host",
			uri:       "otpauth://Totp/Test?secret=" + validSecret,
			expectErr: false,
		},
	}

	for _, tt := range casings {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseTOTPSecret(tt.uri)
			if tt.expectErr && err == nil {
				t.Fatalf("expected error for %s (%s), got nil", tt.name, tt.uri)
			}
			if !tt.expectErr && err != nil {
				t.Fatalf("unexpected error for %s (%s): %v", tt.name, tt.uri, err)
			}
			if !tt.expectErr && len(cfg.Secret) == 0 {
				t.Fatalf("expected secret bytes for %s", tt.name)
			}
		})
	}
}

func TestTOTP_Digits_Variations(t *testing.T) {
	secretBytes := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)

	// Standard and extended digit variations: 6, 7, 8, 9, 10
	for _, d := range []int{6, 7, 8, 9, 10} {
		t.Run(fmt.Sprintf("Digits_%d", d), func(t *testing.T) {
			cfg := TOTPConfig{
				Secret:    secretBytes,
				Algorithm: "SHA1",
				Digits:    d,
				Period:    30,
			}
			otp, err := GenerateTOTPWithConfig(cfg, now)
			if err != nil {
				t.Fatalf("unexpected error for digits %d: %v", d, err)
			}
			if len(otp) != d {
				t.Fatalf("expected %d digits, got %q (len %d)", d, otp, len(otp))
			}
		})
	}

	// Test rejection of out-of-range digits (< 6 or > 10)
	for _, invalidD := range []int{1, 5, 11, 32} {
		t.Run(fmt.Sprintf("Digits_%d_rejected", invalidD), func(t *testing.T) {
			cfg := TOTPConfig{
				Secret:    secretBytes,
				Algorithm: "SHA1",
				Digits:    invalidD,
				Period:    30,
			}
			_, err := GenerateTOTPWithConfig(cfg, now)
			if err == nil {
				t.Fatalf("expected error for unsupported digits %d, got nil", invalidD)
			}
		})
	}

	// Test default when Digits <= 0
	t.Run("Digits_0_defaults_to_6", func(t *testing.T) {
		cfg := TOTPConfig{
			Secret:    secretBytes,
			Algorithm: "SHA1",
			Digits:    0,
			Period:    30,
		}
		otp, err := GenerateTOTPWithConfig(cfg, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(otp) != 6 {
			t.Fatalf("expected 6 digits for Digits=0, got %q", otp)
		}
	})

	t.Run("Digits_Negative_defaults_to_6", func(t *testing.T) {
		cfg := TOTPConfig{
			Secret:    secretBytes,
			Algorithm: "SHA1",
			Digits:    -5,
			Period:    30,
		}
		otp, err := GenerateTOTPWithConfig(cfg, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(otp) != 6 {
			t.Fatalf("expected 6 digits for Digits=-5, got %q", otp)
		}
	})
}

// TestTOTP_Bug_Digits_10_ArithmeticCorruption reproduces the 32-bit overflow when digits == 10
func TestTOTP_Bug_Digits_10_ArithmeticCorruption(t *testing.T) {
	secretBytes := []byte("12345678901234567890")
	// At sec = 90, counter = 3, binCode = 1726969429 (> 1410065408 = 10^10 mod 2^32)
	now := time.Unix(90, 0)

	cfg := TOTPConfig{
		Secret:    secretBytes,
		Algorithm: "SHA1",
		Digits:    10,
		Period:    30,
	}
	otp, err := GenerateTOTPWithConfig(cfg, now)
	if err != nil {
		t.Fatal(err)
	}

	// Calculate expected RFC 4226 10-digit OTP:
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], uint64(90/30))
	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(counterBytes[:])
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0x0F
	binCode := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7FFFFFFF

	expectedOTP := fmt.Sprintf("%010d", uint64(binCode)%10000000000)
	if otp != expectedOTP {
		t.Errorf("BUG CONFIRMED: uint32 mod overflow for Digits=10: generated %q, expected %q (binCode=%d)", otp, expectedOTP, binCode)
	}
}

// TestTOTP_Bug_Digits_32_DivideByZeroPanic reproduces the panic when Digits >= 32
func TestTOTP_Bug_Digits_32_DivideByZeroPanic(t *testing.T) {
	secretBytes := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)

	cfg := TOTPConfig{
		Secret:    secretBytes,
		Algorithm: "SHA1",
		Digits:    32,
		Period:    30,
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("BUG CONFIRMED: runtime panic with Digits=32: %v", r)
		}
	}()

	_, _ = GenerateTOTPWithConfig(cfg, now)
}

func TestTOTP_URI_Malformed_And_EdgeParameters(t *testing.T) {
	validSecret := "JBSWY3DPEHPK3PXP"

	tests := []struct {
		name      string
		uri       string
		expectErr bool
	}{
		{
			name:      "Missing secret",
			uri:       "otpauth://totp/Test",
			expectErr: true,
		},
		{
			name:      "Empty secret parameter",
			uri:       "otpauth://totp/Test?secret=",
			expectErr: true,
		},
		{
			name:      "Secret with percent-encoded padding",
			uri:       "otpauth://totp/Test?secret=MZXW%3D%3D%3D%3D", // 2 bytes = 4 chars + 4 '='
			expectErr: false,
		},
		{
			name:      "Secret with percent-encoded padding on 10-byte unpadded secret",
			uri:       "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP%3D%3D",
			expectErr: false,
		},
		{
			name:      "Secret with redundant percent-encoded padding",
			uri:       "otpauth://totp/Test?secret=MZXW%3D%3D%3D%3D%3D%3D",
			expectErr: false,
		},
		{
			name:      "Secret with spaces in query",
			uri:       "otpauth://totp/Test?secret=JBSW+Y3DP+EHPK+3PXP",
			expectErr: false,
		},
		{
			name:      "Repeated secret parameter (q.Get takes first)",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&secret=INVALID",
			expectErr: false,
		},
		{
			name:      "Digits non-numeric string",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&digits=eight",
			expectErr: true,
		},
		{
			name:      "Digits float",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&digits=6.5",
			expectErr: true,
		},
		{
			name:      "Digits out of range 5",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&digits=5",
			expectErr: true,
		},
		{
			name:      "Digits out of range 11",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&digits=11",
			expectErr: true,
		},
		{
			name:      "Period non-numeric string",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&period=sixty",
			expectErr: true,
		},
		{
			name:      "Period zero",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&period=0",
			expectErr: true,
		},
		{
			name:      "Period negative",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&period=-30",
			expectErr: true,
		},
		{
			name:      "Period overflow int",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&period=9999999999999999999999999999",
			expectErr: true,
		},
		{
			name:      "Unsupported algorithm MD5",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&algorithm=MD5",
			expectErr: true,
		},
		{
			name:      "Unsupported algorithm SHA384",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&algorithm=SHA384",
			expectErr: true,
		},
		{
			name:      "Algorithm casing sha256",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&algorithm=sha256",
			expectErr: false,
		},
		{
			name:      "Algorithm casing ShA512",
			uri:       "otpauth://totp/Test?secret=" + validSecret + "&algorithm=ShA512",
			expectErr: false,
		},
		{
			name:      "Invalid URI percent encoding",
			uri:       "otpauth://totp/Test?secret=%zz",
			expectErr: true,
		},
		{
			name:      "Invalid scheme https",
			uri:       "https://totp/Test?secret=" + validSecret,
			expectErr: true,
		},
		{
			name:      "Invalid host hotp",
			uri:       "otpauth://hotp/Test?secret=" + validSecret,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseTOTPSecret(tt.uri)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for URI %q, got config: %+v", tt.uri, cfg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for URI %q: %v", tt.uri, err)
				}
			}
		})
	}
}

func TestTOTP_AlgorithmDistinctness(t *testing.T) {
	secretBytes := []byte("12345678901234567890")
	now := time.Unix(1234567890, 0)

	cfgSHA1 := TOTPConfig{Secret: secretBytes, Algorithm: "SHA1", Digits: 6, Period: 30}
	cfgSHA256 := TOTPConfig{Secret: secretBytes, Algorithm: "SHA256", Digits: 6, Period: 30}
	cfgSHA512 := TOTPConfig{Secret: secretBytes, Algorithm: "SHA512", Digits: 6, Period: 30}

	otp1, err := GenerateTOTPWithConfig(cfgSHA1, now)
	if err != nil {
		t.Fatal(err)
	}
	otp256, err := GenerateTOTPWithConfig(cfgSHA256, now)
	if err != nil {
		t.Fatal(err)
	}
	otp512, err := GenerateTOTPWithConfig(cfgSHA512, now)
	if err != nil {
		t.Fatal(err)
	}

	if otp1 == otp256 {
		t.Errorf("SHA1 and SHA256 produced identical OTP: %s", otp1)
	}
	if otp256 == otp512 {
		t.Errorf("SHA256 and SHA512 produced identical OTP: %s", otp256)
	}
	if otp1 == otp512 {
		t.Errorf("SHA1 and SHA512 produced identical OTP: %s", otp1)
	}
}
