package guardrail

import (
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/policy"
)

// TestP7W12a_AB12M1_ProtectedPathsPosixBackslashSpoofing verifies AB12-M1:
//   - On POSIX, '\' is a literal filename character, so paths such as
//     "/opt/custom-protected/\../drop" remain inside "/opt/custom-protected"
//     and MUST match ProtectedPaths instead of collapsing to "/opt/drop".
//   - Defense-in-depth OR matching also catches Windows-style backslash
//     separators traversing into a protected path (e.g. "/tmp/\../opt/custom-protected/secret"
//     or `\etc\passwd`) without producing false positives on siblings or
//     genuine POSIX ".." exits.
func TestP7W12a_AB12M1_ProtectedPathsPosixBackslashSpoofing(t *testing.T) {
	t.Run("matchesUnder_posix_backslash_spoofing_and_boundaries", func(t *testing.T) {
		tests := []struct {
			name      string
			target    string
			protected string
			want      bool
		}{
			{
				name:      "posix backslash dotdot spoof stays under custom protected",
				target:    `/opt/custom-protected/\../drop`,
				protected: "/opt/custom-protected",
				want:      true,
			},
			{
				name:      "posix backslash dotdot spoof with trailing slash on prefix",
				target:    `/opt/custom-protected/\../secret`,
				protected: "/opt/custom-protected/",
				want:      true,
			},
			{
				name:      "posix backslash dotdot direct child",
				target:    `/opt/custom-protected/\..`,
				protected: "/opt/custom-protected",
				want:      true,
			},
			{
				name:      "posix nested backslash dotdot plus real dotdot stays under protected",
				target:    `/opt/custom-protected/sub/\../../drop`,
				protected: "/opt/custom-protected",
				want:      true,
			},
			{
				name:      "posix backslash dotdot spoof under default sensitive etc",
				target:    `/etc/\../safe`,
				protected: "/etc",
				want:      true,
			},
			{
				name:      "posix backslash dotdot spoof ending with drive segment still matches posix prefix",
				target:    `/opt/custom-protected/\../C:/foo`,
				protected: "/opt/custom-protected",
				want:      true,
			},
			{
				name:      "defense-in-depth windows separator traversing into protected",
				target:    `/tmp/\../opt/custom-protected/secret`,
				protected: "/opt/custom-protected",
				want:      true,
			},
			{
				name:      "defense-in-depth backslash rooted path into protected",
				target:    `\opt\custom-protected\secret`,
				protected: "/opt/custom-protected",
				want:      true,
			},
			{
				name:      "sibling directory prefix does not match",
				target:    "/opt/custom-protected2/drop",
				protected: "/opt/custom-protected",
				want:      false,
			},
			{
				name:      "genuine posix dotdot outside protected does not match",
				target:    "/opt/custom-protected/../safe/drop",
				protected: "/opt/custom-protected",
				want:      false,
			},
			{
				name:      "ordinary posix filename with backslash outside protected",
				target:    `/tmp/foo\bar`,
				protected: "/opt/custom-protected",
				want:      false,
			},
			{
				name:      "empty target never matches",
				target:    "",
				protected: "/opt/custom-protected",
				want:      false,
			},
			{
				name:      "empty prefix never matches",
				target:    "/opt/custom-protected/secret",
				protected: "",
				want:      false,
			},
			{
				name:      "both empty never match",
				target:    "",
				protected: "",
				want:      false,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := matchesUnder(tc.target, tc.protected); got != tc.want {
					t.Errorf("matchesUnder(%q, %q) = %v, want %v", tc.target, tc.protected, got, tc.want)
				}
			})
		}
	})

	t.Run("policy_evaluate_requires_approval_on_posix_backslash_spoofing", func(t *testing.T) {
		p := NewPolicy(&policy.Config{
			ApprovalThreshold: "moderate",
			NoElicitFallback:  FallbackDeny,
			ProtectedPaths:    []string{"/opt/custom-protected"},
		})

		spoofInputs := []RiskInput{
			{ToolName: "transfer", Action: "pull", NodeID: "node-1", Paths: []string{`/opt/custom-protected/\../drop`, "/tmp/pkg"}},
			{ToolName: "file", Action: "read", NodeID: "node-1", Paths: []string{`/opt/custom-protected/\../secret`}},
			{ToolName: "file", Action: "stat", NodeID: "node-1", Paths: []string{`/opt/custom-protected/\../secret`}},
			{ToolName: "transfer", Action: "prepare_pull", NodeID: "node-1", Paths: []string{`/opt/custom-protected/\../secret`}},
			{ToolName: "file", Action: "read", NodeID: "node-1", Paths: []string{`/etc/\../safe`}},
		}
		for _, in := range spoofInputs {
			risk := Classify(in)
			if got := p.Evaluate(risk, in); got != NeedApproval {
				t.Errorf("Evaluate(%+v) = %v (classified %v), want NeedApproval", in, got, risk)
			}
		}

		safeInputs := []RiskInput{
			{ToolName: "transfer", Action: "pull", NodeID: "node-1", Paths: []string{"/opt/custom-protected2/drop", "/tmp/pkg"}},
			{ToolName: "file", Action: "read", NodeID: "node-1", Paths: []string{"/opt/custom-protected/../safe/file"}},
			{ToolName: "file", Action: "read", NodeID: "node-1", Paths: []string{`/tmp/foo\bar`}},
		}
		for _, in := range safeInputs {
			risk := Classify(in)
			if got := p.Evaluate(risk, in); got != Allow {
				t.Errorf("Evaluate(%+v) = %v (classified %v), want Allow", in, got, risk)
			}
		}
	})
}

// TestP7W12a_AB12M1_ProtectedPathsWindowsDriveMatching verifies AB12-M1:
//   - Windows drive paths match ProtectedPaths regardless of leading slash
//     (C:\..., C:/..., /C:/..., //C:/..., /tmp/../C:/...) and regardless of
//     drive-letter or path-segment casing.
//   - Drive root ProtectedPaths (C:\, C:/, C:, /C:, /C:/) match every path on
//     that drive while never matching other drives or sibling prefixes.
func TestP7W12a_AB12M1_ProtectedPathsWindowsDriveMatching(t *testing.T) {
	t.Run("matchesUnder_windows_drive_variants", func(t *testing.T) {
		tests := []struct {
			name      string
			target    string
			protected string
			want      bool
		}{
			{
				name:      "sftp canonical target vs windows backslash prefix",
				target:    "/C:/ProgramData/ssh/sshd_config",
				protected: `C:\ProgramData\ssh`,
				want:      true,
			},
			{
				name:      "sftp canonical target vs windows forward-slash prefix",
				target:    "/C:/ProgramData/ssh/sshd_config",
				protected: "C:/ProgramData/ssh",
				want:      true,
			},
			{
				name:      "windows lowercase backslash target vs sftp canonical prefix",
				target:    `c:\users\alice\.ssh\authorized_keys`,
				protected: "/C:/Users/Alice/.ssh",
				want:      true,
			},
			{
				name:      "case-insensitive drive and segment exact match",
				target:    `c:\programdata\ssh\`,
				protected: "/C:/ProgramData/SSH",
				want:      true,
			},
			{
				name:      "double slash collapsed drive target",
				target:    `//c:\ProgramData\ssh\sshd_config`,
				protected: `C:\ProgramData\ssh`,
				want:      true,
			},
			{
				name:      "dotdot collapsed drive target",
				target:    "/tmp/../c:/ProgramData/ssh/sshd_config",
				protected: `C:\ProgramData\ssh`,
				want:      true,
			},
			{
				name:      "dotdot collapsed drive target with backslashes",
				target:    `/tmp/../C:\ProgramData\ssh\sshd_config`,
				protected: "C:/ProgramData/ssh",
				want:      true,
			},
			{
				name:      "mixed slash backslash traversal into drive path",
				target:    `/tmp/..\c:\ProgramData\ssh\sshd_config`,
				protected: `C:\ProgramData\ssh`,
				want:      true,
			},
			{
				name:      "protected drive root slash-prefixed matches child on same drive",
				target:    "/C:/Users/Alice/file.txt",
				protected: "/C:/",
				want:      true,
			},
			{
				name:      "protected drive root backslash matches sftp child on same drive",
				target:    "/c:/Users/Alice/file.txt",
				protected: `C:\`,
				want:      true,
			},
			{
				name:      "protected bare drive root matches windows child on same drive",
				target:    `c:\Users\Alice\file.txt`,
				protected: "c:",
				want:      true,
			},
			{
				name:      "protected posix root matches windows drive path",
				target:    `C:\Users\Alice\file.txt`,
				protected: "/",
				want:      true,
			},
			{
				name:      "protected posix root matches sftp drive path",
				target:    "/C:/Users/Alice/file.txt",
				protected: "/",
				want:      true,
			},
			{
				name:      "different drive letter does not match",
				target:    "/D:/ProgramData/ssh/sshd_config",
				protected: `C:\ProgramData\ssh`,
				want:      false,
			},
			{
				name:      "different drive letter does not match drive root",
				target:    "/D:/Users/Alice/file.txt",
				protected: "/C:/",
				want:      false,
			},
			{
				name:      "windows drive sibling prefix does not match",
				target:    "/C:/ProgramData/ssh2/sshd_config",
				protected: `C:\ProgramData\ssh`,
				want:      false,
			},
			{
				name:      "windows drive traversal outside protected does not match",
				target:    `C:\ProgramData\ssh\..\public\file.txt`,
				protected: `C:\ProgramData\ssh`,
				want:      false,
			},
			{
				name:      "drive target does not match unrelated non-root posix prefix",
				target:    "/C:/opt/custom/file.txt",
				protected: "/opt/custom",
				want:      false,
			},
			{
				name:      "posix target does not match drive prefix",
				target:    "/ProgramData/ssh/sshd_config",
				protected: `C:\ProgramData\ssh`,
				want:      false,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := matchesUnder(tc.target, tc.protected); got != tc.want {
					t.Errorf("matchesUnder(%q, %q) = %v, want %v", tc.target, tc.protected, got, tc.want)
				}
			})
		}
	})

	t.Run("policy_evaluate_windows_drive_protected_paths", func(t *testing.T) {
		p := NewPolicy(&policy.Config{
			ApprovalThreshold: "moderate",
			NoElicitFallback:  FallbackDeny,
			ProtectedPaths: []string{
				`C:\ProgramData\ssh`,
				"/C:/Users/Alice/.ssh",
				`E:\`,
			},
		})

		protectedTargets := []string{
			"/C:/ProgramData/ssh/sshd_config",
			`c:\programdata\ssh\sshd_config`,
			`//c:\ProgramData\ssh\sshd_config`,
			"/tmp/../c:/ProgramData/ssh/sshd_config",
			`c:\users\alice\.ssh\authorized_keys`,
			"/C:/USERS/ALICE/.SSH/id_ed25519",
			"/E:/anything/at/all.txt",
			`e:\secret.bin`,
		}
		for _, target := range protectedTargets {
			in := RiskInput{ToolName: "file", Action: "read", NodeID: "win-1", Paths: []string{target}}
			if got := p.Evaluate(Classify(in), in); got != NeedApproval {
				t.Errorf("Evaluate(target=%q) = %v, want NeedApproval", target, got)
			}
		}

		allowedTargets := []string{
			"/C:/ProgramData/ssh2/sshd_config",
			"/D:/ProgramData/ssh/sshd_config",
			`C:\Users\Bob\notes.txt`,
		}
		for _, target := range allowedTargets {
			in := RiskInput{ToolName: "file", Action: "read", NodeID: "win-1", Paths: []string{target}}
			if got := p.Evaluate(Classify(in), in); got != Allow {
				t.Errorf("Evaluate(target=%q) = %v, want Allow", target, got)
			}
		}
	})
}

// TestP7W12a_AB12L1_AnalyzePathsCollapsedWindowsDrivePaths verifies AB12-L1:
//   - AnalyzePaths re-checks Windows drive paths after collapsing leading "//"
//     and ".." segments so "//C:/", "/tmp/../C:/", and "//C:/Windows/System32/config/SAM"
//     are never downgraded to Safe.
func TestP7W12a_AB12L1_AnalyzePathsCollapsedWindowsDrivePaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		want RiskLevel
	}{
		// Collapsed Windows drive roots -> Dangerous
		{"double slash drive root", "//C:/", Dangerous},
		{"triple slash drive root", "///C:/", Dangerous},
		{"double slash lowercase drive backslash root", `//c:\`, Dangerous},
		{"triple slash lowercase drive backslash root", `///c:\`, Dangerous},
		{"double slash bare drive root", "//C:", Dangerous},
		{"dotdot to drive root slash", "/tmp/../C:/", Dangerous},
		{"dotdot to lowercase drive root slash", "/tmp/../c:/", Dangerous},
		{"dotdot to bare drive root", "/tmp/../C:", Dangerous},
		{"dotdot to drive root backslash", `/tmp/../c:\`, Dangerous},
		{"multi dotdot to drive root", "/a/b/../../C:/", Dangerous},
		{"dot segment before drive root", "/./C:/", Dangerous},
		{"double slash drive dotdot to root", "//C:/Users/../..", Dangerous},
		{"dotdot into drive then dotdot to root", "/tmp/../C:/Users/../..", Dangerous},
		{"dotdot into drive backslash dotdot to root", `/tmp/../c:\Users\..\..`, Dangerous},
		{"mixed backslash traversal to drive root", `/tmp/..\C:\`, Dangerous},
		{"mixed backslash traversal to drive root slash", `/tmp/..\C:/`, Dangerous},

		// Collapsed Windows sensitive directories -> Moderate
		{"double slash windows config SAM", "//C:/Windows/System32/config/SAM", Moderate},
		{"triple slash backslash windows config SAM", `///c:\Windows\System32\config\SAM`, Moderate},
		{"dotdot windows config SAM", "/tmp/../C:/Windows/System32/config/SAM", Moderate},
		{"dotdot backslash windows config SAM", `/tmp/../c:\Windows\System32\config\SAM`, Moderate},
		{"multi dotdot windows repair", "/a/b/../../C:/Windows/Repair/backup.hiv", Moderate},
		{"mixed backslash traversal to windows config SAM", `/tmp/..\C:\Windows\System32\config\SAM`, Moderate},
		{"double slash drive sensitive posix subdir", "//C:/etc/passwd", Moderate},
		{"dotdot drive sensitive posix subdir", "/tmp/../C:/etc/passwd", Moderate},

		// POSIX backslash spoofing in AnalyzePaths
		{"posix backslash spoof under etc", `/etc/\../safe`, Moderate},
		{"posix backslash spoof under windows config", `/windows/system32/config/\../safe`, Moderate},
		{"backslash traversal into etc", `/tmp/\../etc/passwd`, Moderate},
		{"backslash traversal to root", `/tmp/\../..`, Dangerous},

		// Relative paths disguised as drive paths must stay Dangerous
		{"dot slash relative drive path", "./C:/Users/admin", Dangerous},
		{"relative dotdot to drive path", "foo/../C:/Users/admin", Dangerous},
		{"drive-relative path", "C:relative.txt", Dangerous},

		// Legitimate non-sensitive paths remain Safe
		{"double slash user file", `//c:\Users\admin\a.txt`, Safe},
		{"dotdot user file", "/tmp/../C:/Users/admin/a.txt", Safe},
		{"posix filename with literal backslash", `/tmp/foo\bar`, Safe},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AnalyzePaths([]string{tc.path}); got != tc.want {
				t.Errorf("AnalyzePaths(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}
