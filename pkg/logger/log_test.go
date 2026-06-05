package logger

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const ansiEscape = "\033"

func TestSetColorMode_Never(t *testing.T) {
	SetColorMode("never")
	if ColorEnabled() {
		t.Error("expected ColorEnabled false when mode is never")
	}
}

func TestSetColorMode_Always(t *testing.T) {
	SetColorMode("always")
	if !ColorEnabled() {
		t.Error("expected ColorEnabled true when mode is always")
	}
}

func TestSetColorMode_AutoRespectsNO_COLOR(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	SetColorMode("auto")
	if ColorEnabled() {
		t.Error("expected ColorEnabled false when NO_COLOR is set")
	}
	t.Setenv("NO_COLOR", "")
}

func TestPrintInfo_NoANSIWhenDisabled(t *testing.T) {
	SetColorMode("never")
	defer SetColorMode("auto")

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	PrintInfo("test message")

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	if strings.Contains(out, ansiEscape) {
		t.Errorf("output should not contain ANSI escape when disabled, got %q", out)
	}
	if !strings.Contains(out, "test message") {
		t.Errorf("output should contain message, got %q", out)
	}
}

func TestPrintInfo_ANSIWhenEnabled(t *testing.T) {
	SetColorMode("always")
	defer SetColorMode("auto")

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	PrintInfo("test message")

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	if !strings.Contains(out, ansiEscape) {
		t.Errorf("output should contain ANSI escape when enabled, got %q", out)
	}
	if !strings.Contains(out, "test message") {
		t.Errorf("output should contain message, got %q", out)
	}
}

func TestPrintError_NoANSIWhenDisabled(t *testing.T) {
	SetColorMode("never")
	defer SetColorMode("auto")

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	PrintError("error message")

	_ = w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	if strings.Contains(out, ansiEscape) {
		t.Errorf("stderr should not contain ANSI escape when disabled, got %q", out)
	}
	if !strings.Contains(out, "error message") {
		t.Errorf("output should contain message, got %q", out)
	}
}

func TestColorWrappers(t *testing.T) {
	tests := []struct {
		name string
		f    func(string) string
		code string
	}{
		{"Cyan", Cyan, "\033[36m"},
		{"Blue", Blue, "\033[34m"},
		{"Red", Red, "\033[31m"},
		{"Green", Green, "\033[32m"},
		{"Yellow", Yellow, "\033[33m"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_Enabled", func(t *testing.T) {
			SetColorMode("always")
			res := tt.f("hello")
			if !strings.HasPrefix(res, tt.code) || !strings.HasSuffix(res, "\033[0m") {
				t.Errorf("%s(\"hello\") expected to be wrapped in %q, got %q", tt.name, tt.code, res)
			}
		})

		t.Run(tt.name+"_Disabled", func(t *testing.T) {
			SetColorMode("never")
			res := tt.f("hello")
			if res != "hello" {
				t.Errorf("%s(\"hello\") expected \"hello\", got %q", tt.name, res)
			}
		})
	}
	SetColorMode("auto") // 还原默认
}
