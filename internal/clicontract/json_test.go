package clicontract

import (
	"strings"
	"testing"
)

func TestMCPContractJSONFormatting(t *testing.T) {
	const baseline = "[\n  {\"name\": \"probe\", \"description\": \"line one\\nline two\", \"required\": [\"nodeID\", \"command\"]}\n]\n"
	for _, tc := range []struct {
		name, expected, actual string
		equal, invalid         bool
	}{
		{name: "LF", expected: baseline, actual: baseline, equal: true},
		{name: "CRLF checkout", expected: strings.ReplaceAll(baseline, "\n", "\r\n"), actual: baseline, equal: true},
		{name: "indentation", expected: strings.ReplaceAll(baseline, "  {", "\t{"), actual: baseline, equal: true},
		{name: "description whitespace", expected: baseline, actual: strings.ReplaceAll(baseline, "line one", "line  one")},
		{name: "escaped newline", expected: baseline, actual: strings.ReplaceAll(baseline, `\n`, `\r\n`)},
		{name: "schema field", expected: baseline, actual: strings.ReplaceAll(baseline, "nodeID", "nodeId")},
		{name: "array order", expected: baseline, actual: strings.ReplaceAll(baseline, `"nodeID", "command"`, `"command", "nodeID"`)},
		{name: "invalid baseline", expected: "[", actual: baseline, invalid: true},
		{name: "invalid response", expected: baseline, actual: "[", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			equal, err := sameMCPContract([]byte(tc.expected), []byte(tc.actual))
			if (err != nil) != tc.invalid || equal != tc.equal {
				t.Fatalf("comparison = (%v, %v), want equal=%v invalid=%v", equal, err, tc.equal, tc.invalid)
			}
		})
	}
}
