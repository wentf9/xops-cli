package guardrail

import (
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/policy"
)

// TestP7W13a_AB13M1_ProtectedPathsWin32Canonicalization verifies AB13-M1:
//   - Windows drive paths with Win32-stripped trailing ASCII '.' / ' ' or NTFS
//     alternate/default data streams (:stream, :$DATA, ::$DATA) on any component
//     canonicalize to the underlying target and match both file-level and
//     directory-level ProtectedPaths (and sensitiveWindowsPaths).
//   - Non-drive POSIX paths (e.g. "/opt/file.", "/tmp/a:b") are NEVER altered.
func TestP7W13a_AB13M1_ProtectedPathsWin32Canonicalization(t *testing.T) {
	fileVariants := []string{
		`C:\Protected\secret.env.`,
		`C:\Protected\secret.env `,
		`C:\Protected\secret.env.. `,
		`C:\Protected\secret.env:$DATA`,
		`C:\Protected\secret.env::$DATA`,
		`C:\Protected\secret.env.:$DATA`,
		`C:\Protected\secret.env :$DATA`,
		`C:\Protected.\secret.env`,
		`C:\Protected \secret.env`,
		`C:\Protected:stream\secret.env`,
		`C:\Protected.\secret.env.:$DATA`,
		`c:\protected.\SECRET.ENV::$DATA`,
		`/C:/Protected/secret.env.`,
		`/C:/Protected/secret.env `,
		`/C:/Protected/secret.env:$DATA`,
		`/C:/Protected/secret.env::$DATA`,
		`//C:/Protected/secret.env.`,
		`//c:\Protected.\secret.env:$DATA`,
		`/tmp/../C:/Protected/secret.env.`,
		`/tmp/../c:\Protected\secret.env::$DATA`,
		`/tmp/..\C:\Protected.\secret.env.`,
		`C:\Protected\secret.env\::$DATA`,
		`C:\Protected\secret.env\ `,
	}

	dirOnlyVariants := []string{
		`C:\Protected.`,
		`C:\Protected `,
		`C:\Protected.. `,
		`C:\Protected:$DATA`,
		`C:\Protected::$DATA`,
		`C:\Protected\ `,
		`C:\Protected\...`,
		`C:\Protected\::$DATA`,
		`/C:/Protected.`,
		`//C:/Protected `,
		`/tmp/../C:/Protected.`,
	}

	t.Run("matches_file_level_protected_path", func(t *testing.T) {
		for _, protected := range []string{`C:\Protected\secret.env`, `/C:/Protected/secret.env`} {
			for _, target := range fileVariants {
				if !matchesUnder(target, protected) {
					t.Errorf("matchesUnder(%q, %q) = false, want true", target, protected)
				}
			}
		}
	})

	t.Run("matches_directory_level_protected_path", func(t *testing.T) {
		allUnderDir := append(append([]string(nil), fileVariants...), dirOnlyVariants...)
		for _, protected := range []string{`C:\Protected`, `/C:/Protected`, `C:\Protected\`} {
			for _, target := range allUnderDir {
				if !matchesUnder(target, protected) {
					t.Errorf("matchesUnder(%q, %q) = false, want true", target, protected)
				}
			}
		}
	})

	t.Run("matches_sensitive_windows_paths_after_canonicalization", func(t *testing.T) {
		sensitiveVariants := []string{
			`C:\Windows\System32\config.`,
			`C:\Windows\System32\config `,
			`C:\Windows\System32\config:$DATA`,
			`C:\Windows\System32\config::$DATA`,
			`C:\Windows\System32\config.\SAM`,
			`C:\Windows\System32\config\SAM:$DATA`,
			`C:\Windows.\System32\config\SAM`,
			`/C:/Windows/System32/config.`,
			`//C:/Windows/System32/config.\SAM::$DATA`,
			`/tmp/../C:/Windows/System32/config.`,
		}
		for _, target := range sensitiveVariants {
			_, cleanRest, ambiguous, ok := canonicalDrivePath(target)
			if !ok {
				t.Fatalf("canonicalDrivePath(%q) ok = false, want true", target)
			}
			if !ambiguous {
				t.Errorf("canonicalDrivePath(%q) ambiguous = false, want true", target)
			}
			if !hasSensitivePrefix(cleanRest) {
				t.Errorf("hasSensitivePrefix(%q) (from %q) = false, want true", cleanRest, target)
			}
		}
	})

	t.Run("no_false_positives_on_siblings_other_drives_or_posix", func(t *testing.T) {
		nonMatches := []struct {
			target    string
			protected string
		}{
			{`C:\Protected2\secret.env`, `C:\Protected`},
			{`C:\Protected2\secret.env.`, `C:\Protected`},
			{`D:\Protected\secret.env.`, `C:\Protected`},
			{`D:\Protected\secret.env:$DATA`, `C:\Protected\secret.env`},
			{`C:\Protected\other.env.`, `C:\Protected\secret.env`},
			{`/opt/Protected.`, `/opt/Protected`},
			{`/opt/file.`, `/opt/file`},
			{`/tmp/a:b`, `/tmp/a`},
		}
		for _, tc := range nonMatches {
			if matchesUnder(tc.target, tc.protected) {
				t.Errorf("matchesUnder(%q, %q) = true, want false", tc.target, tc.protected)
			}
		}
	})

	t.Run("policy_evaluate_enforces_protected_paths_even_at_safe_risk", func(t *testing.T) {
		pFile := NewPolicy(&policy.Config{
			ApprovalThreshold: "moderate",
			NoElicitFallback:  FallbackDeny,
			ProtectedPaths:    []string{`C:\Protected\secret.env`},
		})
		for _, target := range fileVariants {
			in := RiskInput{ToolName: "file", Action: "read", NodeID: "win-1", Paths: []string{target}}
			if got := pFile.Evaluate(Safe, in); got != NeedApproval {
				t.Errorf("file-level Evaluate(Safe, %q) = %v, want NeedApproval", target, got)
			}
		}

		pDir := NewPolicy(&policy.Config{
			ApprovalThreshold: "moderate",
			NoElicitFallback:  FallbackDeny,
			ProtectedPaths:    []string{`C:\Protected`},
		})
		for _, target := range append(append([]string(nil), fileVariants...), dirOnlyVariants...) {
			in := RiskInput{ToolName: "file", Action: "read", NodeID: "win-1", Paths: []string{target}}
			if got := pDir.Evaluate(Safe, in); got != NeedApproval {
				t.Errorf("dir-level Evaluate(Safe, %q) = %v, want NeedApproval", target, got)
			}
		}
	})
}

// TestP7W13a_AB13M1_AnalyzePathsWin32ComponentSemantics verifies AB13-M1:
//   - Win32-trimmed drive roots ('C:\ ', '/C:/ ', 'C:\.', 'C:\...', 'C:\::$DATA')
//     classify as Dangerous.
//   - Any Windows drive path carrying NTFS ADS (secondary ':') or Win32-stripped
//     trailing '.' / ' ' on a non-'.'/'..' segment (before or after Clean)
//     classifies as Dangerous.
//   - Clean Windows drive paths and valid POSIX paths with trailing '.' / ' ' /
//     ':' remain Safe.
func TestP7W13a_AB13M1_AnalyzePathsWin32ComponentSemantics(t *testing.T) {
	tests := []struct {
		name string
		path string
		want RiskLevel
	}{
		// Win32-trimmed drive roots -> Dangerous
		{"drive root trailing space", `C:\ `, Dangerous},
		{"sftp drive root trailing space", `/C:/ `, Dangerous},
		{"drive root single dot", `C:\.`, Dangerous},
		{"drive root multi dot", `C:\...`, Dangerous},
		{"sftp drive root multi dot", `/C:/...`, Dangerous},
		{"drive root default stream", `C:\::$DATA`, Dangerous},
		{"sftp drive root default stream", `/C:/::$DATA`, Dangerous},
		{"drive root empty stream", `C:\:$DATA`, Dangerous},
		{"double slash drive root space", `//C:/ `, Dangerous},
		{"dotdot drive root space", `/tmp/../C:/ `, Dangerous},
		{"dotdot drive root multi dot", `/tmp/../C:/...`, Dangerous},
		{"dotdot drive root stream", `/tmp/../C:/::$DATA`, Dangerous},
		{"drive root mixed space dot", `C:\ . .`, Dangerous},
		{"drive root dot space", `C:\. `, Dangerous},

		// Windows drive ADS and trailing dot/space anomalies -> Dangerous
		{"trailing dot file", `C:\Protected\secret.env.`, Dangerous},
		{"trailing space file", `C:\Protected\secret.env `, Dangerous},
		{"ads $DATA", `C:\Protected\secret.env:$DATA`, Dangerous},
		{"ads ::$DATA", `C:\Protected\secret.env::$DATA`, Dangerous},
		{"ads custom stream", `C:\Users\ops\app.log:hidden`, Dangerous},
		{"intermediate trailing dot dir", `C:\Protected.\secret.env`, Dangerous},
		{"intermediate trailing space dir", `C:\Protected \secret.env`, Dangerous},
		{"intermediate ads dir", `C:\Protected:stream\secret.env`, Dangerous},
		{"dir trailing dot", `C:\Protected.`, Dangerous},
		{"sensitive config trailing dot", `C:\Windows\System32\config.`, Dangerous},
		{"sensitive config trailing dot child", `C:\Windows\System32\config.\SAM`, Dangerous},
		{"sftp drive trailing dot", `/C:/temp/a.txt.`, Dangerous},
		{"sftp drive trailing space", `/C:/temp/a.txt `, Dangerous},
		{"sftp drive ads", `/C:/temp/a.txt:$DATA`, Dangerous},
		{"dotdot collapsed trailing dot segment", `C:\foo.\..\bar`, Dangerous},
		{"dotdot collapsed ads segment", `C:\foo:$DATA\..\bar`, Dangerous},
		{"dotdot prefix then collapsed trailing dot", `/tmp/../C:/foo./../bar`, Dangerous},
		{"dotdot prefix then collapsed ads", `/tmp/../C:/foo:$DATA/../bar`, Dangerous},
		{"mixed backslash dotdot then trailing dot", `/tmp/..\C:\foo.\..\bar`, Dangerous},
		{"multi dot component in subpath", `C:\Users\ops\...`, Dangerous},
		{"whitespace only component in subpath", `C:\Users\ops\ `, Dangerous},
		{"cross drive secondary colon", `C:\..\D:\foo`, Dangerous},

		// Clean Windows drive paths remain Safe (or Moderate if sensitive)
		{"clean windows user file", `C:\Users\ops\app.log`, Safe},
		{"clean sftp drive file", `/C:/temp/a.txt`, Safe},
		{"clean dotfile under windows", `C:\Users\Alice\.ssh\id_ed25519`, Safe},
		{"clean interior spaces and dots", `/C:/Users/ops/my folder/v1.2.3.log`, Safe},
		{"clean single dot navigation", `C:\Users\ops\.\app.log`, Safe},
		{"clean dotdot navigation", `C:\Users\ops\sub\..\app.log`, Safe},
		{"clean sensitive windows config", `C:\Windows\System32\config\SAM`, Moderate},

		// Valid POSIX paths MUST NOT be altered or rejected by Win32 rules
		{"posix trailing dot", `/opt/file.`, Safe},
		{"posix colon in name", `/tmp/a:b`, Safe},
		{"posix trailing space", `/tmp/file `, Safe},
		{"posix multi dot", `/tmp/...`, Safe},
		{"posix ads-looking name", `/tmp/file:$DATA`, Safe},
		{"posix root multi dot", `/...`, Safe},
		{"posix root space", `/ `, Safe},
		{"posix etc with colon stays moderate", `/etc/passwd:$DATA`, Moderate},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AnalyzePaths([]string{tc.path}); got != tc.want {
				t.Errorf("AnalyzePaths(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
