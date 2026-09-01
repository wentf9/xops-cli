package mcpserver

import (
	"testing"
)

func TestEscapePosix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "''"},
		{"abc", "'abc'"},
		{"a'b", "'a'\\''b'"},
		{"'", "''\\'''"},
		{"\n", "'\n'"},
		{"file name", "'file name'"},
	}

	for _, tt := range tests {
		actual := escapePosix(tt.input)
		if actual != tt.expected {
			t.Errorf("escapePosix(%q) = %q, expected %q", tt.input, actual, tt.expected)
		}
	}
}
