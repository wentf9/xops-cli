package mcpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
)

func runTransferClient(t *testing.T, serverURL, operation, filename string, prepared PreparedTransferOutput) map[string]any {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
		if err != nil {
			t.Skip("optional Python client requires Python 3")
		}
	}
	script, err := filepath.Abs("../../scripts/mcp/transfer.py")
	if err != nil {
		t.Fatal(err)
	}
	taskPath := filepath.Join(t.TempDir(), "task.json")
	data, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(taskPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, script, operation, "--server", serverURL, "--task", taskPath, "--file", filename, "--timeout", "15", "--idle-timeout", "5")
	command.Env = append(os.Environ(), "PYTHONUTF8=1")
	out, err := command.CombinedOutput()
	if bytes.Contains(out, []byte(prepared.Headers["Authorization"])) {
		t.Fatal("client output exposed transfer credential")
	}
	if err != nil {
		t.Fatalf("client command failed: %v\n%s", err, out)
	}
	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("client result: %v\n%s", err, out)
	}
	return result
}

func TestLocalCommandForwardsClientFilesThroughHTTPAndSFTP(t *testing.T) {
	_, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler())
	directory := t.TempDir()
	source := filepath.Join(directory, "client source 文件.bin")
	destination := filepath.Join(directory, "client destination 文件.bin")
	data := bytes.Repeat([]byte{0, 255, 127, 10}, 65536)
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	upload := prepareTransferTest(t, client, "xops_prepare_upload", PrepareUploadInput{
		RequestID: "python-upload", NodeID: "files", RemotePath: "/remote.bin", Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:]),
	})
	result := runTransferClient(t, server.URL, "upload", source, upload)
	if result["state"] != string(transfer.Completed) {
		t.Fatalf("upload result: %+v", result)
	}
	download := prepareTransferTest(t, client, "xops_prepare_download", PrepareDownloadInput{RequestID: "python-download", NodeID: "files", RemotePath: "/remote.bin"})
	result = runTransferClient(t, server.URL, "download", destination, download)
	if result["state"] != string(transfer.Streamed) || result["localSaved"] != true {
		t.Fatalf("download result: %+v", result)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("client file differs: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".xops-download-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("client temporary file leaked: %v %v", matches, err)
	}
}
