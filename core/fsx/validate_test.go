package fsx

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestValidateLocalComponent(t *testing.T) {
	invalidCases := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "dot", input: "."},
		{name: "dotdot", input: ".."},
		{name: "posix traversal", input: "../escape"},
		{name: "forward slash", input: "a/b"},
		{name: "leading slash", input: "/etc"},
		{name: "backslash traversal", input: `..\..\evil.txt`},
		{name: "single backslash", input: `a\b`},
		{name: "ntfs ads", input: "foo:ads"},
		{name: "ntfs zone identifier", input: "report.txt:Zone.Identifier"},
		{name: "windows drive prefix", input: "C:evil.txt"},
		{name: "windows drive bare", input: "C:"},
		{name: "unc prefix", input: `\\server\share`},
		{name: "reserved CON", input: "CON"},
		{name: "reserved con lower", input: "con"},
		{name: "reserved CoN mixed", input: "CoN"},
		{name: "reserved CON.txt", input: "CON.txt"},
		{name: "reserved con.tar.gz", input: "con.tar.gz"},
		{name: "reserved CON space dot", input: "CON .txt"},
		{name: "reserved CON multi space dot", input: "CON   .txt"},
		{name: "reserved PRN", input: "PRN"},
		{name: "reserved PRN.log", input: "prn.log"},
		{name: "reserved AUX", input: "AUX"},
		{name: "reserved AUX.bin", input: "aux.bin"},
		{name: "reserved NUL", input: "NUL"},
		{name: "reserved NUL.txt", input: "nul.txt"},
		{name: "reserved COM1", input: "COM1"},
		{name: "reserved COM5.dat", input: "Com5.dat"},
		{name: "reserved COM9.dat", input: "com9.dat"},
		{name: "reserved LPT1", input: "LPT1"},
		{name: "reserved LPT4.out", input: "lPt4.out"},
		{name: "reserved LPT9.out", input: "lpt9.out"},
		{name: "reserved superscript COM1", input: "COM\u00b9"},
		{name: "reserved superscript COM2", input: "COM\u00b2"},
		{name: "reserved superscript COM3", input: "COM\u00b3"},
		{name: "reserved superscript com1 lower", input: "com\u00b9.txt"},
		{name: "reserved superscript cOm2 space dot", input: "cOm\u00b2  .log"},
		{name: "reserved superscript LPT1", input: "LPT\u00b9"},
		{name: "reserved superscript LPT2", input: "LPT\u00b2"},
		{name: "reserved superscript LPT3", input: "LPT\u00b3"},
		{name: "reserved superscript lpt3 ext", input: "lpt\u00b3.tar.gz"},
		{name: "reserved superscript lPt1 space dot", input: "lPt\u00b9 .bak"},
		{name: "nul byte", input: "bad\x00name.txt"},
		{name: "newline", input: "bad\nname.txt"},
		{name: "carriage return", input: "bad\rname.txt"},
		{name: "tab", input: "bad\tname.txt"},
		{name: "escape char", input: "bad\x1bname.txt"},
		{name: "del char", input: "bad\x7fname.txt"},
		{name: "unicode c1 control", input: "bad\u0085name.txt"},
		{name: "unicode c1 control 0x9f", input: "bad\u009fname.txt"},
		{name: "asterisk", input: "bad*name.txt"},
		{name: "question mark", input: "bad?name.txt"},
		{name: "double quote", input: `bad"name.txt`},
		{name: "less than", input: "bad<name.txt"},
		{name: "greater than", input: "bad>name.txt"},
		{name: "pipe", input: "bad|name.txt"},
		{name: "trailing dot", input: "report."},
		{name: "trailing space", input: "report "},
		{name: "only dots", input: "..."},
		{name: "only spaces", input: "   "},
	}

	for _, tc := range invalidCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			err := ValidateLocalComponent(tc.input)
			if err == nil {
				t.Fatalf("ValidateLocalComponent(%q) = nil, want ErrInvalidComponent", tc.input)
			}
			if !errors.Is(err, ErrInvalidComponent) {
				t.Fatalf("ValidateLocalComponent(%q) error = %v, want ErrInvalidComponent", tc.input, err)
			}
		})
	}

	validCases := []string{
		"report.txt",
		".gitignore",
		".env.local",
		"..hidden",
		"my file (1).tar.gz",
		"foo .txt",
		"console.txt",
		"null.txt",
		"COM0",
		"COM0.txt",
		"LPT0",
		"LPT0.txt",
		"COM10.txt",
		"LPT10.log",
		"COM\u00b90.txt",
		"LPT\u00b2a.txt",
		"文档.txt",
		"a.b.c",
	}
	for _, input := range validCases {
		t.Run("allow_"+input, func(t *testing.T) {
			if err := ValidateLocalComponent(input); err != nil {
				t.Fatalf("ValidateLocalComponent(%q) unexpected error: %v", input, err)
			}
		})
	}
}

func FuzzValidateLocalComponent(f *testing.F) {
	seeds := []string{
		"",
		".",
		"..",
		"...",
		"report.txt",
		"CON",
		"con.txt",
		"CON   .tar.gz",
		"PRN",
		"AUX",
		"NUL",
		"COM1",
		"COM9",
		"COM0",
		"COM10",
		"LPT1",
		"LPT9",
		"COM\u00b9",
		"COM\u00b2.txt",
		"COM\u00b3 .log",
		"LPT\u00b9",
		"LPT\u00b2.bak",
		"LPT\u00b3",
		"a/b",
		`a\b`,
		"C:foo",
		"foo:bar",
		"foo.",
		"foo ",
		"bad\x00name",
		"bad\u0085name",
		"文档.txt",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	reservedSet := map[string]struct{}{
		"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
		"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {},
		"COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
		"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {},
		"LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
		"COM\u00b9": {}, "COM\u00b2": {}, "COM\u00b3": {},
		"LPT\u00b9": {}, "LPT\u00b2": {}, "LPT\u00b3": {},
	}

	f.Fuzz(func(t *testing.T, input string) {
		err := ValidateLocalComponent(input)
		if err != nil {
			if !errors.Is(err, ErrInvalidComponent) {
				t.Fatalf("ValidateLocalComponent(%q) returned non-ErrInvalidComponent: %v", input, err)
			}
			return
		}

		// Accepted component MUST uphold every portable safety invariant.
		if input == "" || input == "." || input == ".." {
			t.Fatalf("accepted empty or traversal component %q", input)
		}
		if strings.HasSuffix(input, ".") || strings.HasSuffix(input, " ") {
			t.Fatalf("accepted trailing dot or space in %q", input)
		}
		if strings.ContainsAny(input, `/\:*?"<>|`) {
			t.Fatalf("accepted forbidden character in %q", input)
		}
		for i := 0; i < len(input); i++ {
			if input[i] == 0 || input[i] < 0x20 || input[i] == 0x7f {
				t.Fatalf("accepted control byte 0x%02x in %q", input[i], input)
			}
		}
		for _, r := range input {
			if unicode.IsControl(r) {
				t.Fatalf("accepted Unicode control rune U+%04X in %q", r, input)
			}
		}

		stem := input
		if dot := strings.IndexByte(stem, '.'); dot >= 0 {
			stem = stem[:dot]
		}
		stem = strings.TrimRight(stem, " ")
		if utf8.ValidString(stem) {
			if _, banned := reservedSet[strings.ToUpper(stem)]; banned {
				t.Fatalf("accepted reserved Windows device component %q (stem %q)", input, stem)
			}
		}
	})
}
