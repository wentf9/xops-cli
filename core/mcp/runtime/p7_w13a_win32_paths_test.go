package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
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

var w13aAnomalousWin32Paths = []string{
	`C:\Protected\secret.env.`,
	`C:\Protected\secret.env `,
	`C:\Protected\secret.env:$DATA`,
	`C:\Protected\secret.env::$DATA`,
	`C:\Protected.\secret.env`,
	`C:\Protected.`,
	`C:\ `,
	`/C:/ `,
	`C:\...`,
	`/C:/...`,
	`C:\::$DATA`,
	`/C:/::$DATA`,
	`C:\foo.\..\bar`,
	`/tmp/../C:/foo./../bar`,
	`/tmp/../C:/foo:$DATA/../bar`,
	`C:\Windows\System32\config.`,
}

func assertW13aDangerousDeniedAudit(t *testing.T, label, rawPath string, gotElicited int, audit *w11aAuditRecorder) {
	t.Helper()
	if gotElicited != 1 {
		t.Fatalf("%s(%q) elicited %d times, want 1", label, rawPath, gotElicited)
	}
	entries := audit.snapshot()
	if len(entries) == 0 || entries[len(entries)-1].RiskLevel != "dangerous" || entries[len(entries)-1].Outcome != "denied" {
		t.Fatalf("%s(%q) audit = %+v, want risk=dangerous outcome=denied", label, rawPath, entries)
	}
	if !slices.Contains(entries[len(entries)-1].Paths, rawPath) {
		t.Fatalf("%s(%q) audit Paths = %v, want raw %q preserved", label, rawPath, entries[len(entries)-1].Paths, rawPath)
	}
}

// TestP7W13a_AB13M1_GuardrailAndAuditWin32DrivePaths verifies AB13-M1 end-to-end:
//   - Win32 ADS and trailing '.' / ' ' drive paths (including trimmed roots and
//     pre-Clean collapsed anomalies) are classified Dangerous by guardrail,
//     preserved in AuditEntry.Paths, and denied/elicited before opening SFTP.
func TestP7W13a_AB13M1_GuardrailAndAuditWin32DrivePaths(t *testing.T) {
	var mu sync.Mutex
	var elicited int
	_, client, backend, audit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths: []string{
			`C:\Protected\secret.env`,
			`C:\Protected`,
		},
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
		assertW13aDangerousDeniedAudit(t, label, rawPath, got, audit)
	}

	for _, p := range w13aAnomalousWin32Paths {
		t.Run("file_read_"+p, func(t *testing.T) {
			callAndCheck(t, "file read", p, &mcp.CallToolParams{
				Name:      "file",
				Arguments: FileInput{NodeID: "files", Action: "read", Path: p},
			})
		})
		t.Run("stdio_transfer_remote_"+p, func(t *testing.T) {
			callAndCheck(t, "stdio transfer pull remote", p, &mcp.CallToolParams{
				Name: "transfer",
				Arguments: TransferFileInput{
					NodeID:     "files",
					Direction:  "pull",
					LocalPath:  filepath.Join(t.TempDir(), "out.bin"),
					RemotePath: p,
				},
			})
		})
		t.Run("stdio_transfer_local_"+p, func(t *testing.T) {
			callAndCheck(t, "stdio transfer pull local", p, &mcp.CallToolParams{
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
		t.Fatalf("guardrail-denied Win32 paths opened SFTP %d times, want 0", backend.openFiles.Load())
	}
}

// TestP7W13a_AB13M1_HandlersRejectWin32AnomaliesWhenGuardrailDisabled verifies
// that even with guardrail disabled, file, stdio transfer, and HTTP transfer
// handlers fail closed on Win32 ADS, trailing '.' / ' ', and trimmed drive
// roots while preserving valid POSIX paths ('/opt/file.', '/tmp/a:b').
func TestP7W13a_AB13M1_HandlersRejectWin32AnomaliesWhenGuardrailDisabled(t *testing.T) {
	t.Run("direct_validators_and_posix_preservation", testP7W13aDirectValidators)
	t.Run("file_and_stdio_transfer_handlers_reject_before_sftp", testP7W13aHandlersRejectBeforeSFTP)
	t.Run("http_transfer_rejects_win32_anomalies_with_zero_records", testP7W13aHTTPTransferRejectsAnomalies)
}

func testP7W13aDirectValidators(t *testing.T) {
	for _, p := range w13aAnomalousWin32Paths {
		if got, err := validateRemoteFilePath(p); err == nil {
			t.Errorf("validateRemoteFilePath(%q) = %q, nil; want error", p, got)
		}
		if got, err := validateStdioLocalPath(p); err == nil {
			t.Errorf("validateStdioLocalPath(%q) = %q, nil; want error", p, got)
		}
		spec := transfer.Spec{
			RequestID:     "req-1",
			NodeID:        "node-1",
			RequestedPath: p,
			RemotePath:    p,
			Direction:     transfer.Download,
		}
		if err := validateTransferRequest(spec); err == nil {
			t.Errorf("validateTransferRequest(%q) = nil, want error", p)
		}
		if got := riskRemotePath(p); got != p {
			t.Errorf("riskRemotePath(%q) = %q, want raw path preserved for guardrail/audit", p, got)
		}
		if got := riskLocalPath(p); got != p {
			t.Errorf("riskLocalPath(%q) = %q, want raw path preserved for guardrail/audit", p, got)
		}
	}

	validRemote := []struct {
		in   string
		want string
	}{
		{`C:\Users\ops\app.log`, `/C:/Users/ops/app.log`},
		{`/C:/temp/a.txt`, `/C:/temp/a.txt`},
		{`/opt/file.`, `/opt/file.`},
		{`/tmp/a:b`, `/tmp/a:b`},
		{`/tmp/file `, `/tmp/file `},
	}
	for _, tc := range validRemote {
		got, err := validateRemoteFilePath(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("validateRemoteFilePath(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
		}
	}

	if runtime.GOOS != "windows" {
		for _, posixLocal := range []string{"/opt/file.", "/tmp/a:b"} {
			got, err := validateStdioLocalPath(posixLocal)
			if err != nil || got != posixLocal {
				t.Errorf("validateStdioLocalPath(%q) = (%q, %v), want (%q, nil)", posixLocal, got, err, posixLocal)
			}
		}
	}
}

func testP7W13aHandlersRejectBeforeSFTP(t *testing.T) {
	_, client, backend, _ := startW11aCountingRuntime(t, &policy.Config{Disabled: true}, nil)

	for _, action := range []string{"read", "write", "patch", "stat"} {
		for _, p := range w13aAnomalousWin32Paths {
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
				t.Fatalf("file %s accepted Win32-anomalous path %q", action, p)
			}
		}
	}

	validLocal := filepath.Join(t.TempDir(), "ok.txt")
	for _, dir := range []string{"push", "pull"} {
		for _, p := range w13aAnomalousWin32Paths {
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
				t.Fatalf("stdio transfer %s accepted Win32-anomalous RemotePath %q", dir, p)
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
				t.Fatalf("stdio transfer %s accepted Win32-anomalous LocalPath %q", dir, p)
			}
		}
	}

	if backend.openFiles.Load() != 0 {
		t.Fatalf("handlers opened SFTP %d times for rejected Win32 paths, want 0", backend.openFiles.Load())
	}
}

func testP7W13aHTTPTransferRejectsAnomalies(t *testing.T) {
	httpRT, httpClient, _ := startW12aHTTPTransferRuntime(t, &policy.Config{Disabled: true}, pkgsftp.InMemHandler(), nil)
	digest := sha256.Sum256([]byte("hi"))
	hexDigest := hex.EncodeToString(digest[:])

	for i, p := range w13aAnomalousWin32Paths {
		pullRes, pullErr := httpClient.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "transfer",
			Arguments: PrepareDownloadInput{
				Action:     "prepare_pull",
				RequestID:  "w13a-pull-" + strings.Repeat("a", i+1),
				NodeID:     "files",
				RemotePath: p,
			},
		})
		if pullErr == nil && !pullRes.IsError {
			t.Fatalf("HTTP prepare_pull accepted Win32-anomalous path %q", p)
		}

		pushRes, pushErr := httpClient.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "transfer",
			Arguments: PrepareUploadInput{
				Action:     "prepare_push",
				RequestID:  "w13a-push-" + strings.Repeat("b", i+1),
				NodeID:     "files",
				RemotePath: p,
				Size:       2,
				SHA256:     hexDigest,
			},
		})
		if pushErr == nil && !pushRes.IsError {
			t.Fatalf("HTTP prepare_push accepted Win32-anomalous path %q", p)
		}
	}

	if got := len(httpRT.transfers.Records()); got != 0 {
		t.Fatalf("HTTP transfer persisted %d records for rejected Win32 paths, want 0", got)
	}
}
