package terminal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestConsoleReadLineEchoAndEnter(t *testing.T) {
	for _, tt := range []struct{ name, input, want, output string }{
		{"accept", "yes\r", "yes", "yes\r\n"},
		{"reject", "no\r", "no", "no\r\n"},
		{"backspace", "yex\bs\r", "yes", "yex\b \bs\r\n"},
		{"empty backspace", "\bno\r", "no", "no\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			p := &stdPrompter{stdout: &output}
			input := &ClosablePromptInput{ReadCloser: io.NopCloser(strings.NewReader(tt.input))}
			got, err := p.readLineLoopMode(t.Context(), input, true)
			if err != nil || got != tt.want || output.String() != tt.output {
				t.Fatalf("got %q, output %q, err %v", got, output.String(), err)
			}
		})
	}
}

func TestConsoleReadLineCancel(t *testing.T) {
	p := &stdPrompter{stdout: io.Discard}
	input := &ClosablePromptInput{ReadCloser: io.NopCloser(strings.NewReader("yes\x03"))}
	got, err := p.readLineLoopMode(t.Context(), input, true)
	if got != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestRedirectedReadLineDoesNotEcho(t *testing.T) {
	var output bytes.Buffer
	p := &stdPrompter{stdout: &output}
	input := &ClosablePromptInput{ReadCloser: io.NopCloser(strings.NewReader("yes\r\n"))}
	got, err := p.readLineLoop(t.Context(), input)
	if err != nil || got != "yes" || output.Len() != 0 {
		t.Fatalf("got %q, output %q, err %v", got, output.String(), err)
	}
}
