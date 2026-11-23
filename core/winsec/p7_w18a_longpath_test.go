package winsec

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestP7W18a_AB18L2_Win32LongPathNormalization(t *testing.T) {
	t.Run("utf16CodeUnitLen_matches_std_utf16_Encode", func(t *testing.T) {
		samples := []string{
			"",
			`C:\Users\alice\file.txt`,
			`C:\用户\中文目录\文件.txt`,
			"C:\\dir\\\U0001F600\\\U0001F680\\file.txt",
			strings.Repeat("a", 248),
			strings.Repeat("中", 248),
			strings.Repeat("\U0001F600", 124),
		}
		for _, s := range samples {
			want := len(utf16.Encode([]rune(s)))
			if got := utf16CodeUnitLen(s); got != want {
				t.Errorf("utf16CodeUnitLen(%q) = %d, want %d", s, got, want)
			}
		}
	})

	identityFull := func(p string) (string, error) {
		return strings.ReplaceAll(p, "/", `\`), nil
	}
	nopWD := func() (string, error) { return `C:\work`, nil }

	t.Run("dos_drive_boundary_247_vs_248_utf16", func(t *testing.T) {
		short247 := `C:\` + strings.Repeat("a", 244) // 3 + 244 = 247 UTF-16 units
		if got := normalizeWin32LongPathWithResolver(short247, identityFull, nopWD); got != short247 {
			t.Fatalf("len 247 changed: got %q", got)
		}

		exact248 := `C:\` + strings.Repeat("a", 245) // 3 + 245 = 248 UTF-16 units
		want248 := `\\?\` + exact248
		if got := normalizeWin32LongPathWithResolver(exact248, identityFull, nopWD); got != want248 {
			t.Fatalf("len 248 = %q, want %q", got, want248)
		}

		// Forward-slash DOS long path normalizes slashes before prepending \\?\
		fwd248 := `C:/` + strings.Repeat("b", 245)
		wantFwd := `\\?\C:\` + strings.Repeat("b", 245)
		if got := normalizeWin32LongPathWithResolver(fwd248, identityFull, nopWD); got != wantFwd {
			t.Fatalf("forward-slash 248 = %q, want %q", got, wantFwd)
		}
	})

	t.Run("cjk_bmp_and_emoji_surrogate_utf16_counting", func(t *testing.T) {
		// 100 CJK chars = 300 UTF-8 bytes, but only 103 UTF-16 code units (< 248) -> stays unprefixed.
		cjkShort := `C:\` + strings.Repeat("中", 100)
		if len(cjkShort) <= 248 {
			t.Fatalf("test setup: expected UTF-8 byte len > 248, got %d", len(cjkShort))
		}
		if got := normalizeWin32LongPathWithResolver(cjkShort, identityFull, nopWD); got != cjkShort {
			t.Fatalf("CJK 103 UTF-16 units unexpectedly prefixed: %q", got)
		}

		// 245 CJK chars + "C:\" = 248 UTF-16 code units -> prefixed.
		cjkLong := `C:\` + strings.Repeat("中", 245)
		if got := normalizeWin32LongPathWithResolver(cjkLong, identityFull, nopWD); got != `\\?\`+cjkLong {
			t.Fatalf("CJK 248 UTF-16 units = %q, want prefixed", got)
		}

		// Surrogate pairs: each emoji = 2 UTF-16 code units.
		// "C:\" (3) + 122 emoji (244) = 247 -> unprefixed; +1 emoji (249) -> prefixed.
		emoji247 := `C:\` + strings.Repeat("\U0001F600", 122)
		if got := normalizeWin32LongPathWithResolver(emoji247, identityFull, nopWD); got != emoji247 {
			t.Fatalf("emoji 247 UTF-16 units unexpectedly prefixed: %q", got)
		}
		emoji249 := `C:\` + strings.Repeat("\U0001F600", 123)
		if got := normalizeWin32LongPathWithResolver(emoji249, identityFull, nopWD); got != `\\?\`+emoji249 {
			t.Fatalf("emoji 249 UTF-16 units = %q, want prefixed", got)
		}
	})

	t.Run("unc_long_path_uses_extended_unc_prefix", func(t *testing.T) {
		shortUNC := `\\server\share\dir\file.txt`
		if got := normalizeWin32LongPathWithResolver(shortUNC, identityFull, nopWD); got != shortUNC {
			t.Fatalf("short UNC changed: %q", got)
		}

		longUNC := `\\server\share\` + strings.Repeat("x", 240)
		wantUNC := `\\?\UNC\server\share\` + strings.Repeat("x", 240)
		if got := normalizeWin32LongPathWithResolver(longUNC, identityFull, nopWD); got != wantUNC {
			t.Fatalf("long UNC = %q, want %q", got, wantUNC)
		}
	})

	t.Run("already_extended_or_device_paths_unchanged", func(t *testing.T) {
		longTail := strings.Repeat("z", 260)
		cases := []string{
			"",
			`\\?\C:\` + longTail,
			`\\?\UNC\server\share\` + longTail,
			`\\.\pipe\` + longTail,
			`\??\C:\` + longTail,
			`//?/C:/` + longTail,
			`//./C:/` + longTail,
		}
		for _, p := range cases {
			if got := normalizeWin32LongPathWithResolver(p, identityFull, nopWD); got != p {
				t.Errorf("extended/device path %q mutated to %q", p, got)
			}
		}
	})

	t.Run("relative_and_drive_relative_resolution_and_error_fallback", func(t *testing.T) {
		wd := `C:\` + strings.Repeat("d", 230)
		rel := `sub\` + strings.Repeat("f", 20)
		fullResolver := func(p string) (string, error) {
			if strings.HasPrefix(p, "C:") && !strings.HasPrefix(p, `C:\`) {
				return wd + `\` + p[2:], nil
			}
			return wd + `\` + p, nil
		}
		gotRel := normalizeWin32LongPathWithResolver(rel, fullResolver, func() (string, error) { return wd, nil })
		wantRel := `\\?\` + wd + `\` + rel
		if gotRel != wantRel {
			t.Fatalf("relative long path = %q, want %q", gotRel, wantRel)
		}

		driveRel := `C:sub\` + strings.Repeat("f", 20)
		gotDriveRel := normalizeWin32LongPathWithResolver(driveRel, fullResolver, nopWD)
		wantDriveRel := `\\?\` + wd + `\sub\` + strings.Repeat("f", 20)
		if gotDriveRel != wantDriveRel {
			t.Fatalf("drive-relative long path = %q, want %q", gotDriveRel, wantDriveRel)
		}

		// FullPath failure falls back safely to original path.
		failResolver := func(string) (string, error) { return "", errors.New("fullpath failed") }
		longPath := `C:\` + strings.Repeat("e", 250)
		if got := normalizeWin32LongPathWithResolver(longPath, failResolver, nopWD); got != longPath {
			t.Fatalf("error fallback = %q, want original %q", got, longPath)
		}
	})
}
