package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestP1ParseHosts_SkipsCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	hostFile := filepath.Join(dir, "hosts.txt")
	content := "\uFEFF# leading comment\n\n  # indented comment\n10.0.0.1\nalice@10.0.0.2:2222\n   \n# trailing comment\n[2001:db8::1]:2200\n"
	if err := os.WriteFile(hostFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	hosts, err := ParseHosts("", hostFile, "")
	if err != nil {
		t.Fatalf("ParseHosts failed: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d: %+v", len(hosts), hosts)
	}
	if hosts[0].Host != "10.0.0.1" {
		t.Errorf("hosts[0].Host = %q, want 10.0.0.1", hosts[0].Host)
	}
	if hosts[1].User != "alice" || hosts[1].Host != "10.0.0.2" || hosts[1].Port != 2222 {
		t.Errorf("hosts[1] = %+v, want alice@10.0.0.2:2222", hosts[1])
	}
	if hosts[2].Host != "2001:db8::1" || hosts[2].Port != 2200 {
		t.Errorf("hosts[2] = %+v, want 2001:db8::1:2200", hosts[2])
	}
}

func TestP1ParseHosts_RejectsDirectoryNonRegularAndOversized(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ParseHosts("", dir, "")
		if err == nil || !strings.Contains(err.Error(), "directory") {
			t.Fatalf("ParseHosts on directory = %v, want directory error", err)
		}
		_, csvErr := ReadCSVFile(dir)
		if csvErr == nil || !strings.Contains(csvErr.Error(), "directory") {
			t.Fatalf("ReadCSVFile on directory = %v, want directory error", csvErr)
		}
	})

	t.Run("oversized_file", func(t *testing.T) {
		dir := t.TempDir()
		hugePath := filepath.Join(dir, "huge.txt")
		f, err := os.Create(hugePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(maxHostFileBytes + 1); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		_, err = ParseHosts("", hugePath, "")
		if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
			t.Fatalf("ParseHosts on oversized file = %v, want maximum size error", err)
		}
		_, csvErr := ReadCSVFile(hugePath)
		if csvErr == nil || !strings.Contains(csvErr.Error(), "exceeds maximum size") {
			t.Fatalf("ReadCSVFile on oversized file = %v, want maximum size error", csvErr)
		}
	})

	t.Run("fifo_non_regular", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX FIFOs not applicable on Windows")
		}
		mkfifoBin, err := exec.LookPath("mkfifo")
		if err != nil {
			t.Skipf("mkfifo not available: %v", err)
		}
		fifoPath := filepath.Join(t.TempDir(), "hosts.fifo")
		if out, err := exec.Command(mkfifoBin, fifoPath).CombinedOutput(); err != nil {
			t.Fatalf("mkfifo failed: %v (%s)", err, string(out))
		}

		_, err = ParseHosts("", fifoPath, "")
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("ParseHosts on FIFO = %v, want regular file error", err)
		}
		_, csvErr := ReadCSVFile(fifoPath)
		if csvErr == nil || !strings.Contains(csvErr.Error(), "regular file") {
			t.Fatalf("ReadCSVFile on FIFO = %v, want regular file error", csvErr)
		}
	})
}
