package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

var w14aAnomalousWin32Paths = []string{
	`/tmp/..\C:\Protected.\secret.env:$DATA`,
	`/\C:\Protected.\secret.env:$DATA`,
	`/tmp/..\C:\ `,
	`/\C:\`,
	`\\?\C:\Protected\secret.env`,
	`\\?\C:\Protected.\secret.env:$DATA`,
	`\\.\C:\Protected\secret.env`,
	`\??\C:\Protected\secret.env`,
	`\\?\UNC\server\share\secret.env`,
	`\\.\UNC\server\share\secret.env`,
	`\??\UNC\server\share\secret.env`,
	`\\?\Volume{00000000-0000-0000-0000-000000000000}\secret.env`,
	`\\server\share\secret.env`,
	`\\localhost\C$\Protected\secret.env`,
	`\\127.0.0.1\C$\Protected.\secret.env:$DATA`,
	`\\.\pipe\openssh-ssh-agent`,
	`//?/C:/Protected/secret.env`,
	`//./C:/Protected/secret.env`,
	`//?/UNC/server/share/secret.env`,
}

// TestP7W14a_AB14M1_GuardrailAuditAndFailClosedHandlers verifies AB14-M1 end-to-end:
//   - Mixed-backslash SFTP drive paths and Win32 extended/device/UNC paths are
//     classified Dangerous by guardrail, preserved raw in AuditEntry.Paths, and
//     elicited/denied before opening SFTP.
//   - Even with guardrail disabled, file, stdio transfer (local & remote), and
//     HTTP transfer handlers reject all of these paths fail-closed while keeping
//     valid POSIX paths with literal backslashes intact.
func TestP7W14a_AB14M1_GuardrailAuditAndFailClosedHandlers(t *testing.T) {
	t.Run("guardrail_and_audit_classify_dangerous", testP7W14aGuardrailAndAudit)
	t.Run("direct_validators_reject_and_preserve_posix", testP7W14aDirectValidators)
	t.Run("handlers_fail_closed_when_guardrail_disabled", testP7W14aHandlersFailClosed)
	t.Run("http_transfer_fail_closed_when_guardrail_disabled", testP7W14aHTTPTransferFailClosed)
}

func testP7W14aGuardrailAndAudit(t *testing.T) {
	var mu sync.Mutex
	var elicited int
	_, client, backend, audit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{`C:\Protected`, `\\server\share`},
	}, func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		mu.Lock()
		elicited++
		mu.Unlock()
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	callAndCheck := func(t *testing.T, label, rawPath string, params *mcp.CallToolParams) {
		t.Helper()
		audit.reset()
		mu.Lock()
		elicited = 0
		mu.Unlock()

		res, err := client.CallTool(t.Context(), params)
		if err == nil && !res.IsError {
			t.Fatalf("%s(%q) bypassed guardrail", label, rawPath)
		}
		mu.Lock()
		got := elicited
		mu.Unlock()
		if got != 1 {
			t.Fatalf("%s(%q) elicited %d times, want 1", label, rawPath, got)
		}
		entries := audit.snapshot()
		if len(entries) == 0 || entries[len(entries)-1].RiskLevel != "dangerous" || entries[len(entries)-1].Outcome != "denied" {
			t.Fatalf("%s(%q) audit = %+v, want risk=dangerous outcome=denied", label, rawPath, entries)
		}
		if !slices.Contains(entries[len(entries)-1].Paths, rawPath) {
			t.Fatalf("%s(%q) audit Paths = %v, want raw %q preserved", label, rawPath, entries[len(entries)-1].Paths, rawPath)
		}
	}

	localFile := filepath.Join(t.TempDir(), "out.bin")
	for _, p := range w14aAnomalousWin32Paths {
		t.Run("file_read_"+p, func(t *testing.T) {
			callAndCheck(t, "file read", p, &mcp.CallToolParams{
				Name:      "file",
				Arguments: FileInput{NodeID: "files", Action: "read", Path: p},
			})
		})
		t.Run("stdio_remote_"+p, func(t *testing.T) {
			callAndCheck(t, "stdio transfer remote", p, &mcp.CallToolParams{
				Name: "transfer",
				Arguments: TransferFileInput{
					NodeID:     "files",
					Direction:  "pull",
					LocalPath:  localFile,
					RemotePath: p,
				},
			})
		})
		t.Run("stdio_local_"+p, func(t *testing.T) {
			callAndCheck(t, "stdio transfer local", p, &mcp.CallToolParams{
				Name: "transfer",
				Arguments: TransferFileInput{
					NodeID:     "files",
					Direction:  "pull",
					LocalPath:  p,
					RemotePath: "/tmp/safe.bin",
				},
			})
		})
	}

	if backend.openFiles.Load() != 0 {
		t.Fatalf("guardrail-denied paths opened SFTP %d times, want 0", backend.openFiles.Load())
	}
}

func testP7W14aDirectValidators(t *testing.T) {
	allBad := append(append([]string(nil), w14aAnomalousWin32Paths...),
		`/tmp/..\C:\Users\admin\a.txt`,
		`/\C:\Users\admin\a.txt`,
	)
	for _, p := range allBad {
		if got, err := validateRemoteFilePath(p); err == nil {
			t.Errorf("validateRemoteFilePath(%q) = %q, nil; want error", p, got)
		}
		if got, err := validateStdioLocalPath(p); err == nil {
			t.Errorf("validateStdioLocalPath(%q) = %q, nil; want error", p, got)
		}
		spec := transfer.Spec{
			RequestID:     "req-w14a",
			NodeID:        "node-1",
			RequestedPath: p,
			RemotePath:    p,
			Direction:     transfer.Download,
		}
		if err := validateTransferRequest(spec); err == nil {
			t.Errorf("validateTransferRequest(%q) = nil, want error", p)
		}
		if got := riskRemotePath(p); got != p {
			t.Errorf("riskRemotePath(%q) = %q, want raw path preserved", p, got)
		}
		if got := riskLocalPath(p); got != p {
			t.Errorf("riskLocalPath(%q) = %q, want raw path preserved", p, got)
		}
	}

	// Non-drive POSIX paths with literal backslashes or literal '?' dirs remain valid.
	for _, tc := range []struct {
		in   string
		want string
	}{
		{`/opt/custom-protected/\../drop`, `/opt/custom-protected/\../drop`},
		{`/tmp/a\b`, `/tmp/a\b`},
		{`//?/opt/file`, `/?/opt/file`},
	} {
		got, err := validateRemoteFilePath(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("validateRemoteFilePath(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
		if goruntime.GOOS != "windows" {
			gotLocal, localErr := validateStdioLocalPath(tc.in)
			if localErr != nil || gotLocal != tc.want {
				t.Errorf("validateStdioLocalPath(%q) = (%q, %v), want (%q, nil)", tc.in, gotLocal, localErr, tc.want)
			}
		}
	}

	if goruntime.GOOS == "windows" {
		for _, winUNC := range []string{`//server/share/file.txt`, `//./foo`, `/\server\share\file.txt`} {
			if got, err := validateStdioLocalPath(winUNC); err == nil {
				t.Errorf("Windows validateStdioLocalPath(%q) = %q, nil; want error", winUNC, got)
			}
			if got := riskLocalPath(winUNC); got != winUNC {
				t.Errorf("Windows riskLocalPath(%q) = %q, want raw preserved", winUNC, got)
			}
		}
	}
}

func testP7W14aHandlersFailClosed(t *testing.T) {
	_, client, backend, _ := startW11aCountingRuntime(t, &policy.Config{Disabled: true}, nil)

	allBad := append(append([]string(nil), w14aAnomalousWin32Paths...),
		`/tmp/..\C:\Users\admin\a.txt`,
		`/\C:\Users\admin\a.txt`,
	)
	for _, action := range []string{"read", "write", "patch", "stat"} {
		for _, p := range allBad {
			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "file",
				Arguments: FileInput{
					NodeID:  "files",
					Action:  action,
					Path:    p,
					Content: "<<<<\na\n====\nb\n>>>>",
				},
			})
			if err == nil && !res.IsError {
				t.Fatalf("file %s accepted rejected Win32 path %q", action, p)
			}
		}
	}

	validLocal := filepath.Join(t.TempDir(), "ok.txt")
	for _, dir := range []string{"push", "pull"} {
		for _, p := range allBad {
			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "transfer",
				Arguments: TransferFileInput{
					NodeID:     "files",
					Direction:  dir,
					LocalPath:  validLocal,
					RemotePath: p,
				},
			})
			if err == nil && !res.IsError {
				t.Fatalf("stdio transfer %s accepted RemotePath %q", dir, p)
			}
			res2, err2 := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "transfer",
				Arguments: TransferFileInput{
					NodeID:     "files",
					Direction:  dir,
					LocalPath:  p,
					RemotePath: "/tmp/ok.bin",
				},
			})
			if err2 == nil && !res2.IsError {
				t.Fatalf("stdio transfer %s accepted LocalPath %q", dir, p)
			}
		}
	}

	if backend.openFiles.Load() != 0 {
		t.Fatalf("handlers opened SFTP %d times for rejected paths, want 0", backend.openFiles.Load())
	}
}

func testP7W14aHTTPTransferFailClosed(t *testing.T) {
	httpRT, httpClient, _ := startW12aHTTPTransferRuntime(t, &policy.Config{Disabled: true}, pkgsftp.InMemHandler(), nil)
	digest := sha256.Sum256([]byte("hi"))
	hexDigest := hex.EncodeToString(digest[:])

	allBad := append(append([]string(nil), w14aAnomalousWin32Paths...),
		`/tmp/..\C:\Users\admin\a.txt`,
		`/\C:\Users\admin\a.txt`,
	)
	for i, p := range allBad {
		pullRes, pullErr := httpClient.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "transfer",
			Arguments: PrepareDownloadInput{
				Action:     "prepare_pull",
				RequestID:  "w14a-pull-" + strings.Repeat("a", i+1),
				NodeID:     "files",
				RemotePath: p,
			},
		})
		if pullErr == nil && !pullRes.IsError {
			t.Fatalf("HTTP prepare_pull accepted path %q", p)
		}

		pushRes, pushErr := httpClient.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "transfer",
			Arguments: PrepareUploadInput{
				Action:     "prepare_push",
				RequestID:  "w14a-push-" + strings.Repeat("b", i+1),
				NodeID:     "files",
				RemotePath: p,
				Size:       2,
				SHA256:     hexDigest,
			},
		})
		if pushErr == nil && !pushRes.IsError {
			t.Fatalf("HTTP prepare_push accepted path %q", p)
		}
	}

	if got := len(httpRT.transfers.Records()); got != 0 {
		t.Fatalf("HTTP transfer persisted %d records for rejected paths, want 0", got)
	}
}
