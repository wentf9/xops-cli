package auth

import (
	"strings"
	"testing"
	"time"
)

func TestParseTOTPSecret_RawBase32(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		expectedLen int
		wantErr     bool
	}{
		{
			name:        "Standard Base32 padded",
			raw:         "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			expectedLen: 20,
			wantErr:     false,
		},
		{
			name:        "Lowercase Base32",
			raw:         "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
			expectedLen: 20,
			wantErr:     false,
		},
		{
			name:        "With spaces and tabs",
			raw:         "  GEZD GNBV\tGY3T QOJQ GEZD GNBV GY3T QOJQ  ",
			expectedLen: 20,
			wantErr:     false,
		},
		{
			name:        "With hyphens",
			raw:         "GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
			expectedLen: 20,
			wantErr:     false,
		},
		{
			name:        "Unpadded Base32 (10 bytes = 16 chars)",
			raw:         "JBSWY3DPEHPK3PXP",
			expectedLen: 10,
			wantErr:     false,
		},
		{
			name:        "Unpadded Base32 with spaces and hyphens",
			raw:         "jbsw-y3dp ehpk-3pxp",
			expectedLen: 10,
			wantErr:     false,
		},
		{
			name:    "Empty input",
			raw:     "   ",
			wantErr: true,
		},
		{
			name:    "Invalid Base32 character",
			raw:     "GEZDGNBVGY3TQOJQ1890", // '1', '8', '9', '0' are invalid in standard base32
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseTOTPSecret(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTOTPSecret(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if !tt.wantErr {
				if len(cfg.Secret) != tt.expectedLen {
					t.Errorf("len(cfg.Secret) = %d, want %d", len(cfg.Secret), tt.expectedLen)
				}
				if cfg.Algorithm != "SHA1" {
					t.Errorf("cfg.Algorithm = %q, want 'SHA1'", cfg.Algorithm)
				}
				if cfg.Digits != 6 {
					t.Errorf("cfg.Digits = %d, want 6", cfg.Digits)
				}
				if cfg.Period != 30 {
					t.Errorf("cfg.Period = %d, want 30", cfg.Period)
				}
			}
		})
	}
}

func TestParseTOTPSecret_OTPAuthURI(t *testing.T) {
	tests := []struct {
		name          string
		uri           string
		wantAlgo      string
		wantDigits    int
		wantPeriod    int
		wantSecretLen int
		wantErr       bool
	}{
		{
			name:          "Basic otpauth URI",
			uri:           "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			wantAlgo:      "SHA1",
			wantDigits:    6,
			wantPeriod:    30,
			wantSecretLen: 10,
			wantErr:       false,
		},
		{
			name:          "Custom params SHA256 8 digits 60s period",
			uri:           "otpauth://totp/ACME:user@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60",
			wantAlgo:      "SHA256",
			wantDigits:    8,
			wantPeriod:    60,
			wantSecretLen: 20,
			wantErr:       false,
		},
		{
			name:          "SHA512 lowercase params",
			uri:           "otpauth://totp/Test?secret=gezd-gnbv-gy3t-qojq&algorithm=sha512&digits=7&period=15",
			wantAlgo:      "SHA512",
			wantDigits:    7,
			wantPeriod:    15,
			wantSecretLen: 10,
			wantErr:       false,
		},
		{
			name:    "Missing secret parameter",
			uri:     "otpauth://totp/Test?algorithm=SHA1&digits=6",
			wantErr: true,
		},
		{
			name:    "Invalid scheme",
			uri:     "https://totp/Test?secret=JBSWY3DPEHPK3PXP",
			wantErr: true,
		},
		{
			name:    "Unsupported type hotp",
			uri:     "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=1",
			wantErr: true,
		},
		{
			name:    "Unsupported algorithm",
			uri:     "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
			wantErr: true,
		},
		{
			name:    "Invalid digits < 6",
			uri:     "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=4",
			wantErr: true,
		},
		{
			name:    "Invalid digits > 10",
			uri:     "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=12",
			wantErr: true,
		},
		{
			name:    "Invalid period <= 0",
			uri:     "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0",
			wantErr: true,
		},
		{
			name:    "Malformed URI",
			uri:     "otpauth://totp/::invalid-uri",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseTOTPSecret(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTOTPSecret(%q) error = %v, wantErr %v", tt.uri, err, tt.wantErr)
			}
			if !tt.wantErr {
				if cfg.Algorithm != tt.wantAlgo {
					t.Errorf("cfg.Algorithm = %q, want %q", cfg.Algorithm, tt.wantAlgo)
				}
				if cfg.Digits != tt.wantDigits {
					t.Errorf("cfg.Digits = %d, want %d", cfg.Digits, tt.wantDigits)
				}
				if cfg.Period != tt.wantPeriod {
					t.Errorf("cfg.Period = %d, want %d", cfg.Period, tt.wantPeriod)
				}
				if len(cfg.Secret) != tt.wantSecretLen {
					t.Errorf("len(cfg.Secret) = %d, want %d", len(cfg.Secret), tt.wantSecretLen)
				}
			}
		})
	}
}

// RFC 6238 Appendix B test vectors
func TestGenerateTOTP_RFC6238AppendixB(t *testing.T) {
	// RFC 6238 Appendix B test secrets:
	// SHA1 seed:   "12345678901234567890" (20 bytes)
	// SHA256 seed: "12345678901234567890123456789012" (32 bytes)
	// SHA512 seed: "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
	sha1Secret := []byte("12345678901234567890")
	sha256Secret := []byte("12345678901234567890123456789012")
	sha512Secret := []byte("1234567890123456789012345678901234567890123456789012345678901234")

	type testVector struct {
		timeSec    int64
		wantSHA1   string
		wantSHA256 string
		wantSHA512 string
	}

	vectors := []testVector{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}

	for _, v := range vectors {
		tm := time.Unix(v.timeSec, 0).UTC()

		// Test SHA1
		cfg1 := TOTPConfig{Secret: sha1Secret, Algorithm: "SHA1", Digits: 8, Period: 30}
		gotSHA1, err := GenerateTOTPWithConfig(cfg1, tm)
		if err != nil {
			t.Fatalf("time %d SHA1 error: %v", v.timeSec, err)
		}
		if gotSHA1 != v.wantSHA1 {
			t.Errorf("time %d SHA1 = %q, want %q", v.timeSec, gotSHA1, v.wantSHA1)
		}

		// Test SHA256
		cfg256 := TOTPConfig{Secret: sha256Secret, Algorithm: "SHA256", Digits: 8, Period: 30}
		gotSHA256, err := GenerateTOTPWithConfig(cfg256, tm)
		if err != nil {
			t.Fatalf("time %d SHA256 error: %v", v.timeSec, err)
		}
		if gotSHA256 != v.wantSHA256 {
			t.Errorf("time %d SHA256 = %q, want %q", v.timeSec, gotSHA256, v.wantSHA256)
		}

		// Test SHA512
		cfg512 := TOTPConfig{Secret: sha512Secret, Algorithm: "SHA512", Digits: 8, Period: 30}
		gotSHA512, err := GenerateTOTPWithConfig(cfg512, tm)
		if err != nil {
			t.Fatalf("time %d SHA512 error: %v", v.timeSec, err)
		}
		if gotSHA512 != v.wantSHA512 {
			t.Errorf("time %d SHA512 = %q, want %q", v.timeSec, gotSHA512, v.wantSHA512)
		}
	}
}

// RFC 4226 test vectors (using HOTP mapped to TOTP with period 30)
func TestGenerateTOTP_RFC4226(t *testing.T) {
	secret := []byte("12345678901234567890")
	expected := []string{
		"755224", // count 0
		"287082", // count 1
		"359152", // count 2
		"969429", // count 3
		"338314", // count 4
		"254676", // count 5
		"287922", // count 6
		"162583", // count 7
		"399871", // count 8
		"520489", // count 9
	}

	cfg := TOTPConfig{
		Secret:    secret,
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
	}

	for count, want := range expected {
		tm := time.Unix(int64(count*30), 0).UTC()
		got, err := GenerateTOTPWithConfig(cfg, tm)
		if err != nil {
			t.Fatalf("count %d error: %v", count, err)
		}
		if got != want {
			t.Errorf("count %d = %q, want %q", count, got, want)
		}
	}
}

func TestGenerateTOTP_FromRawString(t *testing.T) {
	// "12345678901234567890" in Base32 is "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	rawSecret := "gezd-gnbv-gy3t-qojq-gezd-gnbv-gy3t-qojq"
	tm := time.Unix(59, 0).UTC()

	// Default digits is 6 for raw string: count = 59/30 = 1 -> "287082"
	got, err := GenerateTOTP(rawSecret, tm)
	if err != nil {
		t.Fatalf("GenerateTOTP error: %v", err)
	}
	if got != "287082" {
		t.Errorf("got %q, want '287082'", got)
	}
}

func TestParseTOTPSecret_MalformedURIDoesNotLeakSecretInError(t *testing.T) {
	const rawSeed = "JBSWY3DPEHPK3PXP"
	malformedURI := "otpauth://totp/label\x7f?secret=" + rawSeed
	_, err := ParseTOTPSecret(malformedURI)
	if err == nil {
		t.Fatal("expected error for malformed URI containing control character")
	}
	if strings.Contains(err.Error(), rawSeed) {
		t.Fatalf("error leaked plaintext TOTP secret: %v", err)
	}
}
