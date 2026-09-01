package playbook

import (
	"errors"
	"testing"
)

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestReportRenderToReturnsOutputError(t *testing.T) {
	wantErr := errors.New("output unavailable")
	report := &Report{}
	err := report.RenderTo(errorWriter{err: wantErr})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected output error, got %v", err)
	}
}
