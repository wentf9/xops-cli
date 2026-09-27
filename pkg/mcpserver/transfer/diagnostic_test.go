package transfer

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDiagnosticJournalSurvivesReload(t *testing.T) {
	for name, tc := range map[string]struct{ input, want string }{
		"Chinese":        {strings.Repeat("界", 1400), strings.Repeat("界", 1365)},
		"emoji boundary": {strings.Repeat("a", 4095) + "🙂", strings.Repeat("a", 4095)},
		"exact limit":    {strings.Repeat("界", 1365) + "a", strings.Repeat("界", 1365) + "a"},
		"ASCII":          {strings.Repeat("a", 4097), strings.Repeat("a", 4096)},
		"invalid UTF-8":  {strings.Repeat("\xffa", 1500), strings.Repeat("�a", 1024)},
	} {
		t.Run(name, func(t *testing.T) {
			for _, reject := range []bool{false, true} {
				label := "failure"
				if reject {
					label = "commit rejection"
				}
				t.Run(label, func(t *testing.T) {
					checkDiagnosticReload(t, tc.input, tc.want, reject)
				})
			}
		})
	}
}

func checkDiagnosticReload(t *testing.T, input, want string, reject bool) {
	t.Helper()
	journal, directory := testJournal(t)
	manager, err := NewManager(t.Context(), journal, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	}()
	p := prepareTestTransfer(t, manager, "diagnostic")
	lease := claimTestTransfer(t, manager, p)
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	if reject {
		verifyTestTransfer(t, lease)
		if _, err := lease.BeginCommit(); err != nil {
			t.Fatal(err)
		}
		if _, err := lease.RejectCommit(errors.New(input)); err != nil {
			t.Fatal(err)
		}
	} else if _, err := lease.Fail(errors.New(input)); err != nil {
		t.Fatal(err)
	}
	if err := manager.Warn(p.Status.ID, input); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := NewManager(t.Context(), reopened, DefaultLimits())
	if err != nil {
		t.Fatalf("reload saved diagnostic: %v", err)
	}
	defer func() {
		if err := recovered.Close(); err != nil {
			t.Error(err)
		}
	}()
	records := recovered.Records()
	if len(records) != 1 {
		t.Fatalf("records: %d", len(records))
	}
	for _, value := range []string{records[0].Error, records[0].Warning} {
		if !utf8.ValidString(value) || len(value) > 4096 || value != want {
			t.Errorf("diagnostic changed or exceeded valid byte bound: %d bytes", len(value))
		}
	}
}
