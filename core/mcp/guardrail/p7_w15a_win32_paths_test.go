package guardrail

import (
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/policy"
)

// TestP7W15a_AB15M1_MixedSeparatorUNCAndCollapsedPrePrefixPaths verifies AB15-M1:
//   - Mixed-separator plain Win32 UNC paths (/\server\share\..., \/server/share/...)
//     are recognized by isWin32PlainUNC, canonicalUNCPath, canonicalDrivePath
//     (including loopback admin shares such as /\localhost\C$\... and
//     \/localhost/C$/...), matchesUnder, and AnalyzePaths (Dangerous).
//   - Pre-prefix ".." / "//" collapsed Win32 device/UNC paths (e.g.
//     "/tmp/../\.\PhysicalDrive0", "/tmp/../\?\C:\Protected\secret.env",
//     "//\?\C:\Protected\secret.env", "//\localhost\C$\Protected\secret.env")
//     rate Dangerous in AnalyzePaths and match ProtectedPaths in both directions.
//   - Pure forward-slash POSIX paths (//?/opt/file, //?/secret/key.pem,
//     //./tmp/safe, //opt/file) remain untouched as POSIX (0 false positives),
//     and POSIX-first matching keeps "/opt/custom-protected/\../drop" and
//     POSIX-configured "/\protected" matching cleanly.
func TestP7W15a_AB15M1_MixedSeparatorUNCAndCollapsedPrePrefixPaths(t *testing.T) {
	t.Run("matchesUnder_mixed_separator_unc_and_collapsed_pre_prefix", func(t *testing.T) {
		matches := []struct {
			name      string
			target    string
			protected string
		}{
			// Mixed-separator loopback admin shares vs drive ProtectedPaths
			{"slash_backslash_localhost_admin_vs_drive", `/\localhost\C$\Protected\secret.env`, `C:\Protected`},
			{"slash_backslash_localhost_admin_ads_vs_file", `/\localhost\C$\Protected.\secret.env:$DATA`, `C:\Protected\secret.env`},
			{"backslash_slash_localhost_admin_vs_drive", `\/localhost/C$/Protected/secret.env`, `C:\Protected`},
			{"backslash_slash_localhost_admin_vs_sftp_drive", `\/localhost/c$/Protected./secret.env:$DATA`, `/C:/Protected/secret.env`},
			{"slash_backslash_ipv4_loopback_admin_vs_drive", `/\127.0.0.1\C$\Protected\secret.env`, `C:\Protected`},
			{"backslash_slash_ipv6_loopback_admin_vs_drive", `\/[::1]/C$/Protected/secret.env`, `C:\Protected`},
			{"drive_target_vs_mixed_sep_localhost_protected", `C:\Protected\secret.env`, `/\localhost\C$\Protected`},
			{"drive_target_vs_backslash_slash_localhost_protected", `/C:/Protected/secret.env`, `\/localhost/C$/Protected`},

			// Mixed-separator remote UNC vs plain/extended UNC ProtectedPaths
			{"slash_backslash_unc_vs_plain_unc", `/\fileserver\secrets\prod.key`, `\\fileserver\secrets`},
			{"backslash_slash_unc_vs_plain_unc", `\/fileserver/secrets/prod.key`, `\\fileserver\secrets`},
			{"slash_backslash_unc_ads_vs_extended_unc", `/\FILESERVER\SECRETS\prod.key:$DATA`, `\\?\UNC\fileserver\secrets\prod.key`},
			{"plain_unc_vs_mixed_sep_unc_protected", `\\fileserver\secrets\prod.key`, `/\fileserver\secrets`},
			{"slash_backslash_unc_vs_posix_root", `/\fileserver\secrets\prod.key`, `/`},
			{"backslash_slash_unc_vs_posix_root", `\/fileserver/secrets/prod.key`, `/`},

			// Mixed-separator drive prefix /\C:\... still matches C:\Protected
			{"slash_backslash_drive_vs_drive_protected", `/\C:\Protected.\secret.env:$DATA`, `C:\Protected`},
			{"slash_backslash_drive_vs_localhost_admin_protected", `/\C:\Protected\secret.env`, `\\localhost\C$\Protected`},

			// Collapsed pre-prefix ".." and "//" Win32 device/UNC paths
			{"dotdot_collapsed_extended_drive_vs_drive", `/tmp/../\?\C:\Protected\secret.env`, `C:\Protected`},
			{"dotdot_collapsed_extended_drive_ads_vs_file", `/tmp/../\?\C:\Protected.\secret.env:$DATA`, `C:\Protected\secret.env`},
			{"doubleslash_collapsed_extended_drive_vs_drive", `//\?\C:\Protected\secret.env`, `C:\Protected`},
			{"dot_collapsed_extended_drive_vs_drive", `/./\?\C:\Protected\secret.env`, `C:\Protected`},
			{"dotdot_collapsed_device_physicaldrive_vs_device", `/tmp/../\.\PhysicalDrive0`, `\\.\PhysicalDrive0`},
			{"doubleslash_collapsed_device_physicaldrive_vs_device", `//\.\PhysicalDrive0`, `\\.\PhysicalDrive0`},
			{"dotdot_collapsed_localhost_unc_vs_drive", `/tmp/../\localhost\C$\Protected\secret.env`, `C:\Protected`},
			{"doubleslash_collapsed_localhost_unc_vs_drive", `//\localhost\C$\Protected\secret.env`, `C:\Protected`},
			{"dotdot_collapsed_fileserver_unc_vs_unc", `/tmp/../\fileserver\secrets\prod.key`, `\\fileserver\secrets`},
			{"doubleslash_collapsed_fileserver_unc_vs_unc", `//\fileserver\secrets\prod.key`, `\\fileserver\secrets`},
			{"dotdot_collapsed_extended_unc_localhost_vs_drive", `/tmp/../\?\UNC\localhost\C$\Protected\secret.env`, `C:\Protected`},
			{"dotdot_collapsed_volume_guid_vs_volume", `/tmp/../\?\Volume{12345678-1234-1234-1234-1234567890ab}\Protected\secret.env`, `\\?\Volume{12345678-1234-1234-1234-1234567890AB}\Protected`},
			{"plain_drive_vs_dotdot_collapsed_extended_protected", `C:\Protected\secret.env`, `/tmp/../\?\C:\Protected`},
			{"plain_drive_vs_doubleslash_collapsed_localhost_protected", `C:\Protected\secret.env`, `//\localhost\C$\Protected`},
			{"mixed_backslash_target_vs_collapsed_extended_protected", `/tmp/..\C:\Protected\secret.env`, `/tmp/../\?\C:\Protected`},

			// CRITICAL POSIX Guard: POSIX-first evaluation preserves literal POSIX matches
			{"posix_backslash_dotdot_spoof", `/opt/custom-protected/\../drop`, `/opt/custom-protected`},
			{"posix_configured_leading_backslash_dir_slash_child", `/\protected/secret`, `/\protected`},
			{"posix_configured_leading_backslash_dir_backslash_child", `/\protected\secret`, `/\protected`},
			{"posix_configured_leading_backslash_nested_spoof", `/\protected/share/sub/\../drop`, `/\protected/share/sub`},
			{"posix_dotdot_into_leading_backslash_dir", `/tmp/../\protected/secret`, `/\protected`},
			{"posix_double_slash_question_dir", `//?/secret/key.pem`, `/?/secret`},
			{"posix_double_slash_opt", `//opt/file`, `/opt`},
		}
		for _, tc := range matches {
			t.Run(tc.name, func(t *testing.T) {
				if !matchesUnder(tc.target, tc.protected) {
					t.Errorf("matchesUnder(%q, %q) = false, want true", tc.target, tc.protected)
				}
			})
		}

		nonMatches := []struct {
			name      string
			target    string
			protected string
		}{
			{"mixed_sep_remote_admin_share_not_local_drive", `/\fileserver\C$\Protected\secret.env`, `C:\Protected`},
			{"mixed_sep_loopback_other_drive", `\/localhost/D$/Protected/secret.env`, `C:\Protected`},
			{"mixed_sep_unc_sibling_share", `/\fileserver\secrets2\prod.key`, `\\fileserver\secrets`},
			{"mixed_sep_unc_not_posix_prefix", `/\fileserver\secrets\prod.key`, `/fileserver/secrets`},
			{"collapsed_unc_not_posix_prefix", `/tmp/../\localhost\C$\Protected\secret.env`, `/localhost/C$/Protected`},
			{"collapsed_extended_other_drive", `/tmp/../\?\D:\Protected\secret.env`, `C:\Protected`},
			{"collapsed_extended_sibling_dir", `//\?\C:\Protected2\secret.env`, `C:\Protected`},
			{"posix_double_slash_question_not_opt", `//?/opt/file`, `/opt`},
			{"posix_double_slash_dot_not_etc", `//./tmp/safe`, `/etc`},
		}
		for _, tc := range nonMatches {
			t.Run(tc.name, func(t *testing.T) {
				if matchesUnder(tc.target, tc.protected) {
					t.Errorf("matchesUnder(%q, %q) = true, want false", tc.target, tc.protected)
				}
			})
		}
	})

	t.Run("analyzePaths_rates_mixed_unc_and_collapsed_pre_prefix_dangerous_with_zero_posix_fp", func(t *testing.T) {
		dangerous := []string{
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
			`/\C:\Users\admin\a.txt`,
		}
		for _, p := range dangerous {
			if got := AnalyzePaths([]string{p}); got != Dangerous {
				t.Errorf("AnalyzePaths(%q) = %v, want Dangerous", p, got)
			}
		}

		// Zero POSIX false positives on pure forward-slash // and POSIX backslash spoofs.
		for _, posixSafe := range []string{
			`//?/opt/file`,
			`//?/secret/key.pem`,
			`//./tmp/safe`,
			`//opt/file`,
			`/opt/custom-protected/\../drop`,
			`/tmp/a\b`,
		} {
			if got := AnalyzePaths([]string{posixSafe}); got != Safe {
				t.Errorf("AnalyzePaths(%q) = %v, want Safe", posixSafe, got)
			}
		}
	})

	t.Run("policy_evaluate_protected_paths_enforced_at_safe_risk", func(t *testing.T) {
		p := NewPolicy(&policy.Config{
			ApprovalThreshold: "moderate",
			NoElicitFallback:  FallbackDeny,
			ProtectedPaths: []string{
				`C:\Protected`,
				`\\fileserver\secrets`,
				`\\.\PhysicalDrive0`,
				`/\protected`,
				`/opt/custom-protected`,
			},
		})
		for _, target := range []string{
			`/\localhost\C$\Protected\secret.env`,
			`\/localhost/C$/Protected/secret.env`,
			`/\fileserver\secrets\prod.key`,
			`\/fileserver/secrets/prod.key`,
			`/tmp/../\.\PhysicalDrive0`,
			`/tmp/../\?\C:\Protected\secret.env`,
			`//\?\C:\Protected\secret.env`,
			`//\localhost\C$\Protected\secret.env`,
			`/tmp/../\localhost\C$\Protected\secret.env`,
			`/\protected\secret`,
			`/\protected/secret`,
			`/opt/custom-protected/\../drop`,
		} {
			in := RiskInput{ToolName: "file", Action: "read", NodeID: "node-1", Paths: []string{target}}
			if got := p.Evaluate(Safe, in); got != NeedApproval {
				t.Errorf("Evaluate(Safe, %q) = %v, want NeedApproval", target, got)
			}
		}
	})
}
