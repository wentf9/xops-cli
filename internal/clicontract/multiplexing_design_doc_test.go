package clicontract

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

var (
	optionClassBulletRe = regexp.MustCompile("`OptionClass([A-Za-z]+)`")
	backtickTokenRe     = regexp.MustCompile("`([a-z][a-z0-9_]*)`")
)

// TestMultiplexingDesignDocOptionRegistryParity enforces 1:1 bidirectional
// parity between core/ssh.RegisteredOptionSpecs() and Section 5.5 of both
// Chinese and English openssh-multiplexing-design.md specifications.
func TestMultiplexingDesignDocOptionRegistryParity(t *testing.T) {
	t.Parallel()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	expectedByClass := map[string][]string{}
	className := map[ssh.OptionClass]string{
		ssh.OptionClassMux:       "Mux",
		ssh.OptionClassTransport: "Transport",
		ssh.OptionClassAuth:      "Auth",
		ssh.OptionClassTrust:     "Trust",
		ssh.OptionClassForward:   "Forward",
		ssh.OptionClassSession:   "Session",
		ssh.OptionClassLocalExec: "LocalExec",
	}
	specs := ssh.RegisteredOptionSpecs()
	for _, spec := range specs {
		cls, ok := className[spec.Class]
		if !ok {
			t.Fatalf("unmapped ssh.OptionClass %v for option %q", spec.Class, spec.CanonicalKey)
		}
		expectedByClass[cls] = append(expectedByClass[cls], spec.CanonicalKey)
	}
	for cls := range expectedByClass {
		slices.Sort(expectedByClass[cls])
	}

	docs := []string{
		filepath.Join(repoRoot, "docs", "development", "openssh-multiplexing-design.md"),
		filepath.Join(repoRoot, "docs", "en", "development", "openssh-multiplexing-design.md"),
	}
	for _, docPath := range docs {
		t.Run(filepath.ToSlash(strings.TrimPrefix(docPath, repoRoot+string(filepath.Separator))), func(t *testing.T) {
			raw, err := os.ReadFile(docPath)
			if err != nil {
				t.Fatalf("read %s: %v", docPath, err)
			}
			parsed := parseDesignDocOptionRegistry(t, string(raw))
			if len(parsed) != len(expectedByClass) {
				t.Fatalf("documented OptionClass count = %d, want %d", len(parsed), len(expectedByClass))
			}
			totalDoc := 0
			for cls, wantKeys := range expectedByClass {
				gotKeys, exists := parsed[cls]
				if !exists {
					t.Fatalf("missing OptionClass%s bullet in Section 5.5", cls)
				}
				totalDoc += len(gotKeys)
				if !slices.Equal(gotKeys, wantKeys) {
					t.Errorf("OptionClass%s mismatch:\n  doc:  %v\n  code: %v", cls, gotKeys, wantKeys)
				}
			}
			if totalDoc != len(specs) {
				t.Fatalf("total documented options = %d, want %d", totalDoc, len(specs))
			}
		})
	}
}

func parseDesignDocOptionRegistry(t *testing.T, content string) map[string][]string {
	t.Helper()
	// Locate Section 5.5 and stop at Section 6.
	startIdx := strings.Index(content, "### 5.5 ")
	if startIdx < 0 {
		t.Fatal("Section 5.5 heading not found")
	}
	section := content[startIdx:]
	if endIdx := strings.Index(section, "\n## 6."); endIdx > 0 {
		section = section[:endIdx]
	}

	// Non-key inline literals in Section 5.5 bullets (e.g. StrictHostKeyChecking values).
	nonOptionLiterals := map[string]struct{}{
		"yes": {}, "ask": {}, "no": {}, "off": {},
	}

	result := make(map[string][]string)
	for line := range strings.SplitSeq(section, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- **") {
			continue
		}
		clsMatch := optionClassBulletRe.FindStringSubmatch(trimmed)
		if len(clsMatch) != 2 {
			continue
		}
		cls := clsMatch[1]
		if _, dup := result[cls]; dup {
			t.Fatalf("duplicate OptionClass%s bullet in Section 5.5", cls)
		}
		colonIdx := strings.Index(trimmed, "：**")
		if colonIdx < 0 {
			colonIdx = strings.Index(trimmed, "**：")
		}
		if colonIdx < 0 {
			colonIdx = strings.Index(trimmed, "**:")
		}
		if colonIdx < 0 {
			t.Fatalf("malformed OptionClass%s bullet line: %q", cls, trimmed)
		}
		body := trimmed[colonIdx:]
		var keys []string
		for _, m := range backtickTokenRe.FindAllStringSubmatch(body, -1) {
			tok := m[1]
			if _, ignored := nonOptionLiterals[tok]; ignored {
				continue
			}
			if slices.Contains(keys, tok) {
				t.Fatalf("duplicate option %q under OptionClass%s", tok, cls)
			}
			keys = append(keys, tok)
		}
		slices.Sort(keys)
		result[cls] = keys
	}
	return result
}
