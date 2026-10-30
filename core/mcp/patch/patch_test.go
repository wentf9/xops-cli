package patch

import (
	"errors"
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
