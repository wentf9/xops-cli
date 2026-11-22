package remotefile

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/sftp"
)

// TestP7W15a_AB15M1_MixedSeparatorUNCAndCollapsedPrePrefixPaths verifies AB15-M1:
//   - Mixed-separator plain Win32 UNC paths (/\server\share\..., \/server/share/...)
//     and collapsed pre-prefix Win32 device/UNC paths (/tmp/../\.\PhysicalDrive0,
//     /tmp/../\?\C:\Protected\secret.env, //\?\C:\Protected\secret.env,
//     //\localhost\C$\Protected\secret.env, /tmp/../\localhost\C$\...) are
//     rejected fail-closed by ValidateWindowsDrivePath, validateTransferInputPath,
//     and validateResolvedRealPath.
//   - IsRootPath recognizes mixed-separator UNC share roots and collapsed
//     pre-prefix device/UNC roots without misclassifying non-roots or POSIX paths.
//   - Pure forward-slash // POSIX paths (//?/opt/file, //?/secret/key.pem,
//     //./tmp/safe, //opt/file) and POSIX paths containing literal backslashes
//     (/opt/custom-protected/\../drop, /tmp/a\b) have 0 false positives.
func TestP7W15a_AB15M1_MixedSeparatorUNCAndCollapsedPrePrefixPaths(t *testing.T) {
	t.Run("validate_rejects_mixed_unc_and_collapsed_pre_prefix", func(t *testing.T) {
		rejected := []string{
			`/\localhost\C$\Protected\secret.env`,
			`\/localhost/C$/Protected/secret.env`,
			`/\127.0.0.1\C$\Protected\secret.env`,
			`/\fileserver\secrets\prod.key`,
			`\/fileserver/secrets/prod.key`,
			`/tmp/../\.\PhysicalDrive0`,
			`//\.\PhysicalDrive0`,
			`/tmp/../\?\C:\Protected\secret.env`,
			`//\?\C:\Protected\secret.env`,
			`/./\?\C:\Protected\secret.env`,
			`//\localhost\C$\Protected\secret.env`,
			`/tmp/../\localhost\C$\Protected\secret.env`,
			`/tmp/../\fileserver\secrets\prod.key`,
			`/tmp/../\?\UNC\localhost\C$\Protected\secret.env`,
			`/tmp/../\C:\Protected\secret.env`,
			`/tmp/../\localhost\..\C:\Protected\secret.env`,
		}
		for _, p := range rejected {
			if err := ValidateWindowsDrivePath(p); !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Errorf("ValidateWindowsDrivePath(%q) = %v, want ErrInvalidRemotePath", p, err)
			}
			if got, err := validateTransferInputPath(p); err == nil {
				t.Errorf("validateTransferInputPath(%q) = %q, nil; want error", p, got)
			}
			if got, err := validateResolvedRealPath(p); !errors.Is(err, sftp.ErrInvalidRemotePath) {
				t.Errorf("validateResolvedRealPath(%q) = (%q, %v), want ErrInvalidRemotePath", p, got, err)
			}
		}
	})

	t.Run("isRootPath_mixed_unc_and_collapsed_pre_prefix_roots", func(t *testing.T) {
		roots := []string{
			`/\localhost\C$`,
			`/\localhost\C$\`,
			`/\localhost\C$\ `,
			`\/localhost/C$`,
			`\/localhost/C$/`,
			`/\fileserver\secrets`,
			`\/fileserver/secrets/`,
			`/tmp/../\?\C:\`,
			`//\?\C:\ `,
			`/tmp/../\localhost\C$\`,
			`//\localhost\C$\`,
			`/tmp/../\?\UNC\server\share\`,
			`/tmp/../\C:\`,
			`/\C:\`,
		}
		for _, r := range roots {
			if !IsRootPath(r) {
				t.Errorf("IsRootPath(%q) = false, want true", r)
			}
		}

		nonRoots := []string{
			`/\localhost\C$\Protected\secret.env`,
			`\/localhost/C$/Protected/secret.env`,
			`/\fileserver\secrets\prod.key`,
			`/tmp/../\?\C:\Protected\secret.env`,
			`//\?\C:\Protected\secret.env`,
			`/\C:\Protected\secret.env`,
			`//?/opt/file`,
			`//?/secret/key.pem`,
			`//./tmp/safe`,
			`//opt/file`,
			`/opt/custom-protected/\../drop`,
			`/tmp/a\b`,
		}
		for _, p := range nonRoots {
			if IsRootPath(p) {
				t.Errorf("IsRootPath(%q) = true, want false", p)
			}
		}
	})

	t.Run("posix_zero_false_positives_and_normalization", func(t *testing.T) {
		posixPaths := []struct {
			in       string
			wantNorm string
		}{
			{`//?/opt/file`, `/?/opt/file`},
			{`//?/secret/key.pem`, `/?/secret/key.pem`},
			{`//./tmp/safe`, `/tmp/safe`},
			{`//opt/file`, `/opt/file`},
			{`/opt/custom-protected/\../drop`, `/opt/custom-protected/\../drop`},
			{`/tmp/a\b`, `/tmp/a\b`},
		}
		for _, tc := range posixPaths {
			if err := ValidateWindowsDrivePath(tc.in); err != nil {
				t.Errorf("ValidateWindowsDrivePath(%q) unexpected error: %v", tc.in, err)
			}
			if got := NormalizeSFTPPath(tc.in); got != tc.wantNorm {
				t.Errorf("NormalizeSFTPPath(%q) = %q, want %q", tc.in, got, tc.wantNorm)
			}
			if got, err := validateTransferInputPath(tc.in); err != nil || got != tc.wantNorm {
				t.Errorf("validateTransferInputPath(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.wantNorm)
			}
		}

		// Collapsed UNC path carrying "..\C:" must not be mis-normalized into /C:.
		if got := NormalizeSFTPPath(`/tmp/../\localhost\..\C:\foo`); got != `/\localhost\..\C:\foo` {
			t.Errorf("NormalizeSFTPPath(collapsed UNC) = %q, want `/\\localhost\\..\\C:\\foo`", got)
		}
	})
}
