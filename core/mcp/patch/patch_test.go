package patch

import (
	"errors"
	"strings"
	"testing"
)

func TestApplyExactAndMultiBlock(t *testing.T) {
	original := "package main\n\nfunc hello() string {\n\treturn \"old\"\n}\n\nfunc world() int {\n\treturn 1\n}\n"
	rawPatch := `<<<<
func hello() string {
	return "old"
}
====
func hello() string {
	return "new"
}
>>>>
<<<<
func world() int {
	return 1
}
====
func world() int {
	return 42
}
>>>>`

	res, err := Apply(original, rawPatch)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if res.Blocks != 2 || res.Fuzzy != 0 {
		t.Fatalf("expected 2 exact blocks applied, got %+v", res)
	}
	got := res.Content
	want := "package main\n\nfunc hello() string {\n\treturn \"new\"\n}\n\nfunc world() int {\n\treturn 42\n}\n"
	if got != want {
		t.Fatalf("unexpected result:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestApplyWhitespaceFallbackAndIndentationAlignment(t *testing.T) {
	// Original uses 2 tabs of indentation; LLM patch uses 2 spaces.
	original := "func outer() {\n\t\tif ready {\n\t\t\trunOld()\n\t\t}\n}\n"
	rawPatch := "<<<<\n  if ready {\n    runOld()\n  }\n====\n  if ready {\n    runNew()\n    logDone()\n  }\n>>>>"

	res, err := Apply(original, rawPatch)
	if err != nil {
		t.Fatalf("Apply fallback failed: %v", err)
	}
	if res.Blocks != 1 || res.Fuzzy != 1 {
		t.Fatalf("expected 1 fuzzy block, got %+v", res)
	}
	got := res.Content
	want := "func outer() {\n\t\tif ready {\n\t\t  runNew()\n\t\t  logDone()\n\t\t}\n}\n"
	if got != want {
		t.Fatalf("unexpected aligned result:\ngot:\n%q\nwant:\n%q", got, want)
	}
}

func TestApplyPreservesCRLF(t *testing.T) {
	original := "line1\r\nline2\r\nline3\r\n"
	rawPatch := "<<<<\nline2\n====\nline2_updated\n>>>>"

	res, err := Apply(original, rawPatch)
	if err != nil {
		t.Fatalf("Apply CRLF failed: %v", err)
	}
	want := "line1\r\nline2_updated\r\nline3\r\n"
	if res.Content != want {
		t.Fatalf("expected CRLF preserved, got %q", res.Content)
	}
}

func TestApplyMixedLineEndingsKeepsUntouchedLines(t *testing.T) {
	original := "a\r\nb\nc\r\n"
	res, err := Apply(original, "<<<<\nb\n====\nB\n>>>>")
	if err != nil {
		t.Fatal(err)
	}
	if want := "a\r\nB\nc\r\n"; res.Content != want {
		t.Fatalf("mixed line endings must be preserved, got %q want %q", res.Content, want)
	}
}

func TestApplyErrorsOnAmbiguousAndNoMatch(t *testing.T) {
	original := "alpha\nbeta\nalpha\n"
	ambiguousPatch := "<<<<\nalpha\n====\ngamma\n>>>>"
	if _, err := Apply(original, ambiguousPatch); !errors.Is(err, ErrAmbiguousMatch) {
		t.Fatalf("expected ErrAmbiguousMatch, got %v", err)
	}

	missingPatch := "<<<<\nnonexistent\n====\ngamma\n>>>>"
	if _, err := Apply(original, missingPatch); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("expected ErrNoMatch, got %v", err)
	}

	invalidPatch := "<<<<\nunclosed"
	if _, err := Apply(original, invalidPatch); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestApplyLeadingTrailingBlankLinesTolerance(t *testing.T) {
	// Case 1: Leading blank lines in search block
	content1 := "package main\nfunc hello() {\n\tprintln(\"hi\")\n}\n"
	patch1 := "<<<<\n\n\nfunc hello() {\n\tprintln(\"hi\")\n}\n====\nfunc helloWorld() {\n\tprintln(\"hello world\")\n}\n>>>>"
	res1, err := Apply(content1, patch1)
	if err != nil {
		t.Fatalf("Case 1 (leading blank lines) failed: %v", err)
	}
	if res1.Blocks != 1 || res1.Fuzzy != 1 {
		t.Fatalf("Case 1 expected 1 block and 1 fuzzy, got blocks=%d fuzzy=%d", res1.Blocks, res1.Fuzzy)
	}
	if !strings.Contains(res1.Content, "func helloWorld()") {
		t.Fatalf("Case 1 expected replaced content, got:\n%s", res1.Content)
	}

	// Case 2: Trailing blank lines in search block
	content2 := "package main\nfunc hello() {\n\tprintln(\"hi\")\n}\n"
	patch2 := "<<<<\nfunc hello() {\n\tprintln(\"hi\")\n}\n\n\n====\nfunc helloWorld() {\n\tprintln(\"hello world\")\n}\n>>>>"
	res2, err := Apply(content2, patch2)
	if err != nil {
		t.Fatalf("Case 2 (trailing blank lines) failed: %v", err)
	}
	if res2.Blocks != 1 || res2.Fuzzy != 1 {
		t.Fatalf("Case 2 expected 1 block and 1 fuzzy, got blocks=%d fuzzy=%d", res2.Blocks, res2.Fuzzy)
	}
	if !strings.Contains(res2.Content, "func helloWorld()") {
		t.Fatalf("Case 2 expected replaced content, got:\n%s", res2.Content)
	}

	// Case 3: Both leading and trailing blank lines with spaces and tabs
	content3 := "package main\nfunc hello() {\n}\n"
	patch3 := "<<<<\n  \n\t\nfunc hello() {\n}\n\t\n  \n====\nfunc helloWorld() {\n}\n>>>>"
	res3, err := Apply(content3, patch3)
	if err != nil {
		t.Fatalf("Case 3 (both leading & trailing with spaces/tabs) failed: %v", err)
	}
	if res3.Blocks != 1 || res3.Fuzzy != 1 {
		t.Fatalf("Case 3 expected 1 block and 1 fuzzy, got blocks=%d fuzzy=%d", res3.Blocks, res3.Fuzzy)
	}

	// Case 4: Target file has fewer lines than total search block lines (due to padding)
	content4 := "line1\nline2\n"
	patch4 := "<<<<\n\n\nline1\nline2\n\n\n====\nnewline1\nnewline2\n>>>>"
	res4, err := Apply(content4, patch4)
	if err != nil {
		t.Fatalf("Case 4 (target file has fewer lines than padded block) failed: %v", err)
	}
	if res4.Blocks != 1 || res4.Fuzzy != 1 {
		t.Fatalf("Case 4 expected 1 block and 1 fuzzy, got blocks=%d fuzzy=%d", res4.Blocks, res4.Fuzzy)
	}
	if want := "newline1\nnewline2\n"; res4.Content != want {
		t.Fatalf("Case 4 content mismatch: got %q, want %q", res4.Content, want)
	}

	// Case 5: Ambiguous match after trimming
	content5 := "dup\ndup\n"
	patch5 := "<<<<\n\n\ndup\n\n\n====\nrep\n>>>>"
	if _, err := Apply(content5, patch5); !errors.Is(err, ErrAmbiguousMatch) {
		t.Fatalf("Case 5 expected ErrAmbiguousMatch, got: %v", err)
	}

	// Case 6: Purely blank search block falls through to ErrNoMatch
	content6 := "line1\nline2\n"
	patch6 := "<<<<\n   \n\t\n====\nrep\n>>>>"
	if _, err := Apply(content6, patch6); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("Case 6 expected ErrNoMatch for all-blank search block, got: %v", err)
	}
}
