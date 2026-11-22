package transfer

import (
	"errors"
	"strings"
	"testing"
)

// TestP7W15a_AB15L1_NormalizeWindowsLongPath verifies AB15-L1 long-path
// normalization logic used by replaceJournalFile on Windows.
func TestP7W15a_AB15L1_NormalizeWindowsLongPath(t *testing.T) {
	isWinAbs := func(p string) bool {
		if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `//`) {
			return true
		}
		return len(p) >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
	}
	wdShort := `C:\work`
	wdLong := `C:\` + strings.Repeat(`nested\`, 36) + `state`

	longDrive := `C:\` + strings.Repeat(`dirseg\`, 38) + `.pending-0123456789abcdef0123456789abcdef`
	if len(longDrive) <= 260 {
		t.Fatalf("test setup: len(longDrive) = %d, want > 260", len(longDrive))
	}
	longUNC := `\\fileserver\share\` + strings.Repeat(`dirseg\`, 38) + `0123456789abcdef0123456789abcdef.json`
	if len(longUNC) <= 260 {
		t.Fatalf("test setup: len(longUNC) = %d, want > 260", len(longUNC))
	}

	tests := []struct {
		name     string
		in       string
		wd       string
		fullPath func(string) (string, error)
		want     string
	}{
		{
			name: "empty_unchanged",
			in:   "",
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				t.Fatalf("unexpected fullPath(%q)", p)
				return "", nil
			},
			want: "",
		},
		{
			name: "short_absolute_unchanged",
			in:   `C:\Users\ops\transfers\0123456789abcdef0123456789abcdef.json`,
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				t.Fatalf("unexpected fullPath(%q)", p)
				return "", nil
			},
			want: `C:\Users\ops\transfers\0123456789abcdef0123456789abcdef.json`,
		},
		{
			name: "already_extended_unchanged",
			in:   `\\?\` + longDrive,
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				t.Fatalf("unexpected fullPath(%q)", p)
				return "", nil
			},
			want: `\\?\` + longDrive,
		},
		{
			name: "already_device_unchanged",
			in:   `\\.\` + longDrive,
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				t.Fatalf("unexpected fullPath(%q)", p)
				return "", nil
			},
			want: `\\.\` + longDrive,
		},
		{
			name: "already_nt_prefix_unchanged",
			in:   `\??\` + longDrive,
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				t.Fatalf("unexpected fullPath(%q)", p)
				return "", nil
			},
			want: `\??\` + longDrive,
		},
		{
			name: "long_drive_path_gets_extended_prefix",
			in:   longDrive,
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				return p, nil
			},
			want: `\\?\` + longDrive,
		},
		{
			name: "long_drive_path_with_forward_slashes_normalized",
			in:   strings.ReplaceAll(longDrive, `\`, `/`),
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				return strings.ReplaceAll(p, `/`, `\`), nil
			},
			want: `\\?\` + longDrive,
		},
		{
			name: "long_unc_path_gets_extended_unc_prefix",
			in:   longUNC,
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				return p, nil
			},
			want: `\\?\UNC\` + longUNC[2:],
		},
		{
			name: "relative_path_under_long_cwd_gets_extended_prefix",
			in:   `transfers\.pending-0123456789abcdef0123456789abcdef`,
			wd:   wdLong,
			fullPath: func(p string) (string, error) {
				return wdLong + `\` + p, nil
			},
			want: `\\?\` + wdLong + `\transfers\.pending-0123456789abcdef0123456789abcdef`,
		},
		{
			name: "drive_relative_long_path_gets_extended_prefix",
			in:   `C:transfers\.pending-0123456789abcdef0123456789abcdef`,
			wd:   wdLong,
			fullPath: func(p string) (string, error) {
				return wdLong + `\` + strings.TrimPrefix(p, "C:"), nil
			},
			want: `\\?\` + wdLong + `\transfers\.pending-0123456789abcdef0123456789abcdef`,
		},
		{
			name: "drive_relative_short_path_unchanged",
			in:   `C:transfers\record.json`,
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				return wdShort + `\` + strings.TrimPrefix(p, "C:"), nil
			},
			want: `C:transfers\record.json`,
		},
		{
			name: "fullPath_returning_already_extended_not_double_prefixed",
			in:   longDrive,
			wd:   wdShort,
			fullPath: func(p string) (string, error) {
				return `\\?\` + p, nil
			},
			want: `\\?\` + longDrive,
		},
		{
			name: "fullPath_error_falls_back_gracefully",
			in:   longDrive,
			wd:   wdShort,
			fullPath: func(string) (string, error) {
				return "", errors.New("boom")
			},
			want: longDrive,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeWindowsLongPath(
				tc.in,
				isWinAbs,
				func() (string, error) { return tc.wd, nil },
				tc.fullPath,
			)
			if got != tc.want {
				t.Errorf("normalizeWindowsLongPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
