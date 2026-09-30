package ssh

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"testing"
)

func TestPrivilegeSudoRSPromptFragments(t *testing.T) {
	const marker = "[xops-password-test]"
	const prompt = "[sudo: " + marker + "] Password: "
	const feedback = "***\b \b\b \b\b \b\r\r\n"
	for _, tc := range []struct {
		name, input, want string
		prompts           int
	}{
		{"sudo", "banner\n" + marker + "[ready]" + prompt, "banner\n" + prompt, 1},
		{"sudo-rs", "banner\n" + prompt + feedback + "[ready]* command output\n" + prompt, "banner\n* command output\n" + prompt, 1},
		{"no trailing space", "banner\n" + strings.TrimSuffix(prompt, " "), "banner\n", 1},
		{"retry", prompt + feedback + "sudo: Authentication failed, try again.\n" + prompt + "\n[ready]done", "sudo: Authentication failed, try again.\ndone", 2},
		{"partial", "banner\n[sudo: " + marker + "] Pass", "banner\n[sudo: " + marker + "] Pass", 0},
		{"missing colon", "banner\n[sudo: " + marker + "] Password", "banner\n[sudo: " + marker + "] Password", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Include byte-by-byte delivery as well as every two-chunk split.
			for split := -1; split <= len(tc.input); split++ {
				exchange := newPrivilegeExchange(nil, SudoModeSudo, false)
				exchange.readyToken = "[ready]"
				var output bytes.Buffer
				writer := &privilegeFrameWriter{exchange: exchange, target: &output, prompt: regexp.MustCompile(regexp.QuoteMeta(marker))}
				writeSudoPromptChunks(t, writer, tc.input, split)
				if err := writer.flush(); err != nil {
					t.Fatal(err)
				}
				if output.String() != tc.want || len(exchange.prompts) != tc.prompts {
					t.Fatalf("split %d: output=%q prompts=%d", split, output.String(), len(exchange.prompts))
				}
			}
		})
	}
}

func TestPrivilegeProbeSudoRSPromptFragments(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"with feedback", "banner\n[sudo: <marker>] Password: ***\b \b\r\nresult\n[sudo: <marker>] Pass", "banner\nresult\n[sudo: <marker>] Pass"},
		{"no trailing space", "banner\n[sudo: <marker>] Password:", "banner\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for split := -1; split <= len(tc.input); split++ {
				var output bytes.Buffer
				writer := &privilegePromptWriter{marker: []byte("<marker>"), target: &output}
				writeSudoPromptChunks(t, writer, tc.input, split)
				if err := writer.flush(); err != nil {
					t.Fatal(err)
				}
				if !writer.observed || output.String() != tc.want {
					t.Fatalf("split %d: output=%q observed=%v", split, output.String(), writer.observed)
				}
			}
		})
	}
}

func writeSudoPromptChunks(t *testing.T, writer io.Writer, input string, split int) {
	t.Helper()
	parts := []string{}
	if split < 0 {
		for i := range len(input) {
			parts = append(parts, input[i:i+1])
		}
	} else {
		parts = append(parts, input[:split], input[split:])
	}
	for _, part := range parts {
		if n, err := writer.Write([]byte(part)); err != nil || n != len(part) {
			t.Fatalf("write prompt: n=%d err=%v", n, err)
		}
	}
}
