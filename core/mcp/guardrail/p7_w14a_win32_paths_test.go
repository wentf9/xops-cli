package guardrail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/policy"
)

// TestP7W14a_AB14M1_Win32DeviceExtendedAndUNCProtectedPaths verifies AB14-M1:
//   - Win32 extended/device prefixes (\\?\, \\.\, \??\, //?/, //./C:...,
//     \\?\GLOBALROOT\??\...) strip cleanly before drive/component canonicalization
//     so ProtectedPaths match in both directions (prefixed policy vs plain target,
//     and plain policy vs prefixed/ADS/trailing-dot target).
//   - Win32 UNC paths (\\server\share\..., \\?\UNC\..., \\.\UNC\..., \??\UNC\...)
//     canonicalize case-insensitively with Win32 component canonicalization.
//   - Loopback administrative drive shares (\\localhost\C$\..., \\127.0.0.1\C$\...,
//     \\[::1]\C$\..., \\?\UNC\localhost\C$\...) match drive ProtectedPaths (C:\...).
//   - AnalyzePaths classifies all \\... / \??\... / Win32 device & UNC paths as
//     Dangerous without altering POSIX paths.
func TestP7W14a_AB14M1_Win32DeviceExtendedAndUNCProtectedPaths(t *testing.T) {
	t.Run("matchesUnder_win32_extended_device_and_unc", func(t *testing.T) {
		matches := []struct {
			name      string
			target    string
			protected string
		}{
			// Extended/device prefix on ProtectedPaths vs plain target
			{"extended_prefix_protected_vs_plain_target", `C:\Protected\secret.env`, `\\?\C:\Protected`},
			{"extended_prefix_protected_vs_sftp_target", `/C:/Protected/secret.env`, `\\?\C:\Protected`},
			{"device_prefix_protected_vs_plain_target", `c:\protected\secret.env`, `\\.\C:\Protected`},
			{"nt_prefix_protected_vs_plain_target", `C:\Protected\secret.env`, `\??\C:\Protected`},
			{"extended_prefix_protected_vs_mixed_backslash_target", `/tmp/..\C:\Protected.\secret.env:$DATA`, `\\?\C:\Protected`},

			// Plain ProtectedPaths vs extended/device target with Win32 component anomalies
			{"extended_target_ads_dot_vs_file_protected", `\\?\C:\Protected.\secret.env:$DATA`, `C:\Protected\secret.env`},
			{"device_target_ads_dot_vs_file_protected", `\\.\C:\Protected.\secret.env::$DATA`, `C:\Protected\secret.env`},
			{"nt_target_ads_dot_vs_file_protected", `\??\C:\Protected.\secret.env.`, `/C:/Protected/secret.env`},
			{"forward_extended_target_vs_file_protected", `//?/C:/Protected./secret.env:$DATA`, `C:\Protected\secret.env`},
			{"forward_device_target_vs_file_protected", `//./C:/Protected./secret.env `, `C:\Protected\secret.env`},
			{"globalroot_nt_target_vs_file_protected", `\\?\GLOBALROOT\??\C:\Protected.\secret.env:$DATA`, `C:\Protected\secret.env`},
			{"extended_target_vs_dir_protected", `\\?\c:\protected \sub\file.txt`, `C:\Protected`},

			// UNC paths (plain and device-prefixed) with case folding and Win32 component canonicalization
			{"unc_plain_case_and_ads_dot", `\\SERVER\SHARE\Protected.\secret.env:$DATA`, `\\server\share\Protected\secret.env`},
			{"unc_extended_vs_plain_protected", `\\?\UNC\server\share\Protected.\secret.env::$DATA`, `\\server\share\Protected\secret.env`},
			{"unc_device_vs_plain_protected", `\\.\UNC\Server\Share\Protected \SECRET.ENV.`, `\\server\share\Protected\secret.env`},
			{"unc_nt_vs_extended_protected", `\??\UNC\server\share\Protected.\secret.env`, `\\?\UNC\SERVER\SHARE\Protected`},
			{"unc_forward_extended_vs_plain_protected", `//?/UNC/server/share/Protected./secret.env:$DATA`, `\\server\share\Protected`},
			{"unc_plain_vs_share_root_protected", `\\server\share\any\file.txt`, `\\server\share`},
			{"unc_extended_vs_server_root_protected", `\\?\UNC\server\share\file.txt`, `\\server`},
			{"unc_vs_posix_root_protected", `\\server\share\file.txt`, `/`},

			// Loopback administrative drive shares vs drive ProtectedPaths
			{"localhost_admin_share_vs_drive_file", `\\localhost\C$\Protected.\secret.env:$DATA`, `C:\Protected\secret.env`},
			{"ipv4_loopback_admin_share_vs_drive_dir", `\\127.0.0.1\c$\Protected\secret.env`, `/C:/Protected`},
			{"ipv6_loopback_admin_share_vs_drive_dir", `\\[::1]\C$\Protected\secret.env`, `C:\Protected`},
			{"extended_unc_localhost_admin_share_vs_drive", `\\?\UNC\localhost\C$\Protected.\secret.env:$DATA`, `\\?\C:\Protected`},
			{"device_unc_loopback_admin_share_vs_drive", `\\.\UNC\127.0.0.1\C$\Protected\secret.env`, `C:\Protected`},
			{"nt_unc_localhost_admin_share_vs_drive", `\??\UNC\localhost\C$\Protected\secret.env`, `C:\Protected`},
			{"localhost_vs_127_admin_share_cross_match", `\\localhost\C$\Protected\secret.env`, `\\127.0.0.1\C$\Protected`},
			{"drive_target_vs_localhost_admin_share_protected", `C:\Protected\secret.env`, `\\localhost\C$\Protected`},
			{"mixed_backslash_target_vs_localhost_admin_share_protected", `/tmp/..\C:\Protected\secret.env`, `\\localhost\C$\Protected`},

			// Volume GUID device namespace
			{"volume_guid_case_and_ads_dot", `\\?\Volume{12345678-1234-1234-1234-1234567890ab}\Protected.\secret.env:$DATA`, `\\?\Volume{12345678-1234-1234-1234-1234567890AB}\Protected`},
			{"forward_volume_guid_matches_extended_volume", `//?/Volume{12345678-1234-1234-1234-1234567890ab}/Protected./secret.env:$DATA`, `\\?\Volume{12345678-1234-1234-1234-1234567890AB}\Protected`},

			// POSIX double-slash paths under literal '?' directory match POSIX ProtectedPaths
			{"posix_double_slash_question_dir_matches_protected", `//?/secret/key.pem`, `/?/secret`},
			{"posix_double_slash_question_dir_matches_parent", `//?/secret/key.pem`, `/?`},

			// POSIX backslash spoofing ending in drive segment still matches POSIX ProtectedPaths
			{"posix_backslash_spoof_with_drive_tail_matches_posix", `/opt/\../C:/foo`, `/opt`},
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
			{"unc_sibling_share", `\\server\share2\Protected\secret.env`, `\\server\share`},
			{"unc_different_server", `\\remote\share\Protected\secret.env`, `\\server\share\Protected`},
			{"unc_sibling_dir", `\\server\share\Protected2\secret.env`, `\\server\share\Protected`},
			{"unc_does_not_match_posix_prefix", `\\server\share\secret.env`, `/server/share`},
			{"remote_admin_share_does_not_match_local_drive", `\\fileserver\C$\Protected\secret.env`, `C:\Protected`},
			{"loopback_other_drive_does_not_match_c", `\\localhost\D$\Protected\secret.env`, `C:\Protected`},
			{"extended_other_drive_does_not_match_c", `\\?\D:\Protected\secret.env`, `C:\Protected`},
			{"volume_guid_different_volume", `\\?\Volume{aaaa}\Protected\secret.env`, `\\?\Volume{bbbb}\Protected`},
		}
		for _, tc := range nonMatches {
			t.Run(tc.name, func(t *testing.T) {
				if matchesUnder(tc.target, tc.protected) {
					t.Errorf("matchesUnder(%q, %q) = true, want false", tc.target, tc.protected)
				}
			})
		}
	})

	t.Run("analyzePaths_rates_all_win32_device_unc_and_mixed_anomalies_dangerous", func(t *testing.T) {
		dangerous := []string{
			`\\?\C:\Users\ops\app.log`,
			`\\?\C:\Protected.\secret.env:$DATA`,
			`\\.\C:\Users\ops\app.log`,
			`\??\C:\Users\ops\app.log`,
			`\\?\UNC\server\share\file.txt`,
			`\\.\UNC\server\share\file.txt`,
			`\??\UNC\server\share\file.txt`,
			`\\?\Volume{00000000-0000-0000-0000-000000000000}\file.txt`,
			`\\?\GLOBALROOT\??\C:\Users\ops\app.log`,
			`\\server\share\file.txt`,
			`\\localhost\C$\Users\ops\app.log`,
			`\\127.0.0.1\C$\Protected\secret.env`,
			`\\.\pipe\openssh-ssh-agent`,
			`//?/C:/Users/ops/app.log`,
			`//./C:/Users/ops/app.log`,
			`//?/UNC/server/share/file.txt`,
			`//./UNC/server/share/file.txt`,
			`//?/Volume{00000000-0000-0000-0000-000000000000}/file.txt`,
			`\\?\opt\file`,
			`/tmp/..\C:\Protected.\secret.env:$DATA`,
			`/\C:\Protected.\secret.env:$DATA`,
			`/tmp/..\C:\ `,
			`/\C:\`,
		}
		for _, p := range dangerous {
			if got := AnalyzePaths([]string{p}); got != Dangerous {
				t.Errorf("AnalyzePaths(%q) = %v, want Dangerous", p, got)
			}
		}

		// POSIX paths remain unaffected (including double-slash paths under literal '?' or '.').
		for _, posixSafe := range []string{
			`/opt/custom-protected/\../drop`,
			`//./tmp/safe`,
			`//?/opt/file`,
			`//?/etc/passwd`,
		} {
			if got := AnalyzePaths([]string{posixSafe}); got != Safe {
				t.Errorf("AnalyzePaths(%q) = %v, want Safe", posixSafe, got)
			}
		}
		if got := AnalyzePaths([]string{`//./etc/passwd`}); got != Moderate {
			t.Errorf("AnalyzePaths(//./etc/passwd) = %v, want Moderate", got)
		}
	})

	t.Run("policy_evaluate_protected_paths_with_extended_and_unc", func(t *testing.T) {
		p := NewPolicy(&policy.Config{
			ApprovalThreshold: "moderate",
			NoElicitFallback:  FallbackDeny,
			ProtectedPaths: []string{
				`\\?\C:\Protected`,
				`\\fileserver\secrets`,
			},
		})
		for _, target := range []string{
			`C:\Protected\secret.env`,
			`\\?\C:\Protected.\secret.env:$DATA`,
			`\\localhost\C$\Protected\secret.env`,
			`\\127.0.0.1\C$\Protected.\secret.env:$DATA`,
			`\\FILESERVER\SECRETS\prod.key`,
			`\\?\UNC\fileserver\secrets\prod.key:$DATA`,
		} {
			in := RiskInput{ToolName: "file", Action: "read", NodeID: "win-1", Paths: []string{target}}
			if got := p.Evaluate(Safe, in); got != NeedApproval {
				t.Errorf("Evaluate(Safe, %q) = %v, want NeedApproval", target, got)
			}
		}
	})
}

// TestP7W14a_AB14L1_AuditLoggerRejectsBareAndBackslashTilde verifies AB14-L1:
// AuditLogger.Log rejects unexpanded "~", "~/...", and "~\..." paths without
// creating a literal "./~" file or directory in the working directory.
func TestP7W14a_AB14L1_AuditLoggerRejectsBareAndBackslashTilde(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)

	for _, raw := range []string{"~", "~/audit.log", `~\audit.log`, `~\.xops\audit.log`} {
		err := NewAuditLogger(raw).Log(AuditEntry{OperationID: "op-tilde", Tool: "nodes", Outcome: "intent"})
		if err == nil || !strings.Contains(err.Error(), "must be expanded by the host") {
			t.Errorf("NewAuditLogger(%q).Log() = %v, want host-expansion error", raw, err)
		}
	}

	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("AuditLogger created unexpected entries in cwd %q: %v", workDir, entries)
	}

	// Regular expanded path with '~' inside filename still works.
	okPath := filepath.Join(workDir, "audit~1.jsonl")
	if err := NewAuditLogger(okPath).Log(AuditEntry{OperationID: "op-ok", Tool: "nodes", Outcome: "intent"}); err != nil {
		t.Fatalf("NewAuditLogger(%q).Log() unexpected error: %v", okPath, err)
	}
}
