package ssh

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
)

func promptContextTestWriter(mode SudoMode, pattern string) (*privilegeFrameWriter, *diagnosticRecorder) {
	recorder := &diagnosticRecorder{}
	client := &Client{diagnostics: recorder, sudoPromptFallback: regexp.MustCompile(pattern)}
	exchange := newPrivilegeExchange(client, mode, false)
	primary := regexp.MustCompile(regexp.QuoteMeta(exchange.promptToken))
	if mode == SudoModeSu {
		primary = regexp.MustCompile(pattern)
	}
	return &privilegeFrameWriter{exchange: exchange, target: io.Discard, prompt: primary}, recorder
}

func writePromptContext(t *testing.T, writer *privilegeFrameWriter, data string) {
	t.Helper()
	if n, err := writer.Write([]byte(data)); err != nil || n != len(data) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
}

func TestPrivilegePromptContextLongXtrace(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			writer, recorder := promptContextTestWriter(mode, `(?i)password[^:]*:`)
			first := "+ sudo -S -p '" + writer.exchange.promptToken + "' -- bash -c '" + strings.Repeat("A", 5000) + " Password PRIVATE_INLINE_SECRET:"
			writePromptContext(t, writer, first)
			writePromptContext(t, writer, " more traced command'\n")
			if len(writer.exchange.prompts) != 0 || strings.Contains(fmt.Sprint(recorder.snapshot()), "PRIVATE_INLINE_SECRET") {
				t.Fatal("truncated xtrace queued a password response or leaked user payload")
			}
			// Real prompts following a newline still work, including retries
			// immediately after the preceding prompt without another newline.
			writePromptContext(t, writer, "Password:")
			writePromptContext(t, writer, "Password:")
			if len(writer.exchange.prompts) != 2 {
				t.Fatal("line recovery or recognized-prompt context reset failed")
			}
		})
	}
}

func TestPrivilegePromptContextTruncatedAnchors(t *testing.T) {
	for _, pattern := range []string{`(?m)^Password:[ \t]*$`, `\APassword:[ \t]*$`, `\bPassword:[ \t]*$`} {
		t.Run(pattern, func(t *testing.T) {
			writer, _ := promptContextTestWriter(SudoModeSudo, pattern)
			// Last 4096 bytes start with Password, but the real line starts
			// with INFOx. Trimming must not create a ^, \A or \b boundary.
			banner := "INFOxPassword:" + strings.Repeat(" ", 4096-len("Password:"))
			writePromptContext(t, writer, banner)
			writePromptContext(t, writer, " ")
			if len(writer.exchange.prompts) != 0 {
				t.Fatal("truncated banner manufactured a regexp boundary")
			}
		})
	}
}

func TestPrivilegePromptContextAcrossTrimBoundaries(t *testing.T) {
	for _, size := range []int{127, 4095, 4096, 4097, 8192} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			writer, recorder := promptContextTestWriter(SudoModeSudo, `Password[^:]*:`)
			value := "+ command '" + strings.Repeat("x", 9000) + "Password PRIVATE_PAYLOAD:'\nPassword:"
			for start := 0; start < len(value); start += size {
				writePromptContext(t, writer, value[start:min(start+size, len(value))])
				if len(writer.pending) > 4096 {
					t.Fatal("prompt look-behind grew without bound")
				}
			}
			if len(writer.exchange.prompts) != 1 || strings.Contains(fmt.Sprint(recorder.snapshot()), "PRIVATE_PAYLOAD") {
				t.Fatal("chunk boundaries changed xtrace exclusion or exposed payload")
			}
		})
	}
}

func TestPrivilegePromptContextLeadingPluses(t *testing.T) {
	writer, recorder := promptContextTestWriter(SudoModeSudo, `(?i)password[^:]*:`)
	writePromptContext(t, writer, strings.Repeat("+", 6000))
	writePromptContext(t, writer, " Password PRIVATE_PAYLOAD:")
	writePromptContext(t, writer, "\nPassword:")
	if len(writer.exchange.prompts) != 1 || strings.Contains(fmt.Sprint(recorder.snapshot()), "PRIVATE_PAYLOAD") {
		t.Fatal("a fragmented leading-plus prefix was not retained")
	}
}

func TestPrivilegePromptContextRegexIncludesXtracePrefix(t *testing.T) {
	writer, _ := promptContextTestWriter(SudoModeSudo, `(?i).*Password:`)
	writePromptContext(t, writer, "+ echo Password:")
	if len(writer.exchange.prompts) != 0 {
		t.Fatal("a regexp consuming the xtrace prefix bypassed xtrace exclusion")
	}
}

func TestPrivilegePromptContextMarkerAndEnvelopeAfterTrim(t *testing.T) {
	for _, rs := range []bool{false, true} {
		writer, recorder := promptContextTestWriter(SudoModeSudo, `(?i)password`)
		writePromptContext(t, writer, "+ trace "+strings.Repeat("x", 6000)+"\n")
		prompt := writer.exchange.promptToken
		if rs {
			prompt = "[sudo: " + prompt + "] Password:"
		}
		writeSudoPromptChunks(t, writer, prompt, -1)
		if len(writer.exchange.prompts) != 1 {
			t.Fatal("a fragmented real marker was lost or duplicated after trim")
		}
		requirePrivilegePhase(t, recorder, "password_prompt_fallback", false)
	}
}

func TestPrivilegePromptContextWhitespaceCannotMaskRealPrompt(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		for _, pattern := range []string{`(?m)^\s*Password:`, `\s*Password:`} {
			for _, size := range []int{127, 4096, 8192} {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, pattern, size), func(t *testing.T) {
					writer, _ := promptContextTestWriter(mode, pattern)
					banner := "INFO!" + strings.Repeat(" ", 4096)
					for start := 0; start < len(banner); start += size {
						writePromptContext(t, writer, banner[start:min(start+size, len(banner))])
					}
					if len(writer.exchange.prompts) != 0 {
						t.Fatal("banner queued a password response")
					}
					writePromptContext(t, writer, "\nPassword:")
					if len(writer.exchange.prompts) != 1 {
						t.Fatal("synthetic prefix masked a real newline prompt")
					}
				})
			}
		}
	}
}

func TestPrivilegePromptContextGuardedRegexForms(t *testing.T) {
	for _, tc := range []struct{ pattern, input, want string }{
		{`(?m)^\s*(Password):`, "\nPassword:", "Password:"},
		{`\s*(Password):`, "\nPassword:", "\nPassword:"},
		{`(?mi)^([ \t]*password):`, "\n  pAsSwOrD:", "  pAsSwOrD:"},
		{`(?m)^(?P<label>Pass(word)):`, "\nPassword:", "Password:"},
		{`\QPassword:`, "\nPassword:", "Password:"},
		{`(?m)^密码：`, "\n密码：", "密码："},
		{`\APassword:`, "\nPassword:", ""},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			writer, recorder := promptContextTestWriter(SudoModeSudo, tc.pattern)
			writer.rememberDiscarded([]byte("INFO!"))
			writePromptContext(t, writer, tc.input)
			var got string
			for _, event := range recorder.snapshot() {
				if event.Outcome == "password_prompt_matched" {
					got = event.PrivilegePrompt
				}
			}
			if got != tc.want {
				t.Fatalf("captured prompt=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestPrivilegePromptContextSearchResumesAfterRejectedMatch(t *testing.T) {
	for _, pattern := range []string{`(?m)^.*Password:\s*`, `(?:\A.*Password:|Password:)`} {
		writer, recorder := promptContextTestWriter(SudoModeSudo, pattern)
		writePromptContext(t, writer, "+ trace PRIVATE_PAYLOAD Password:\nPassword:")
		if len(writer.exchange.prompts) != 1 || strings.Contains(fmt.Sprint(recorder.snapshot()), "PRIVATE_PAYLOAD") {
			t.Fatalf("failed to resume safely after xtrace: %s", pattern)
		}
	}
}

func TestPrivilegePromptContextSearchResumesPastUnicodeZeroWidth(t *testing.T) {
	writer, _ := promptContextTestWriter(SudoModeSudo, `\A|Password:`)
	writer.pending = []byte("👋Password:")
	match, _ := writer.findPrompt(writer.exchange.client.sudoPromptFallback, false)
	if len(match) != 2 || match[0] != len("👋") || match[1] != len(writer.pending) {
		t.Fatalf("bad Unicode match offsets: %v", match)
	}
}

func TestPrivilegePromptContextRegexCacheIsStreamOwned(t *testing.T) {
	writer, _ := promptContextTestWriter(SudoModeSudo, `\s*Password:`)
	for range 3 {
		for _, pattern := range []*regexp.Regexp{writer.prompt, writer.exchange.client.sudoPromptFallback} {
			first := writer.contextPattern(pattern)
			if first == nil || writer.contextPattern(pattern) != first {
				t.Fatal("contextual pattern was not cached")
			}
		}
	}
	if len(writer.contextPatterns) != 2 {
		t.Fatal("unexpected contextual pattern cache growth")
	}
}

func TestPrivilegePromptContextNewlineDiscarded(t *testing.T) {
	writer, _ := promptContextTestWriter(SudoModeSudo, `(?m)^Password:`)
	writer.rememberDiscarded([]byte("+ trace\n"))
	writePromptContext(t, writer, "Password:")
	if len(writer.exchange.prompts) != 1 {
		t.Fatal("a real newline at the discard boundary was lost")
	}
}
