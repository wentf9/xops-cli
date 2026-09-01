package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/playbook"
)

type playErrorWriter struct {
	err error
}

func (w playErrorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestPlayOptionsPrintDryRunUsesConfiguredOutput(t *testing.T) {
	playbookPath := filepath.Join(t.TempDir(), "playbook.yaml")
	content := []byte("name: test\ntargets:\n  nodes: [web-1]\nsteps:\n  - name: check\n    shell: 'true'\n")
	if err := os.WriteFile(playbookPath, content, 0o600); err != nil {
		t.Fatalf("write playbook fixture: %v", err)
	}

	var out bytes.Buffer
	cmd := NewCmdPlay()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{playbookPath, "--dry-run"})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatalf("execute play command: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("Playbook : test")) {
		t.Fatalf("configured output did not receive dry-run report: %q", out.String())
	}
}

func TestPlayOptionsPrintDryRunReturnsOutputError(t *testing.T) {
	wantErr := errors.New("output unavailable")
	o := &PlayOptions{Out: playErrorWriter{err: wantErr}}

	if err := o.printDryRun(&playbook.Playbook{}); !errors.Is(err, wantErr) {
		t.Fatalf("printDryRun error = %v, want wrapped output error", err)
	}
}

func TestPlaybookExecutionErrorRejectsAbortedHostWithoutFailedStep(t *testing.T) {
	report := &playbook.Report{Hosts: []playbook.HostReport{{
		NodeID: "web-1",
		Status: playbook.HostStatusAborted,
	}}}

	if err := playbookExecutionError(report); err == nil {
		t.Fatal("playbookExecutionError() error = nil, want aborted host failure")
	}
}
