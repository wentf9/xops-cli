package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
)

type w12aStaticSFTPHandler struct {
	*w10aHostileSFTPHandler
	realPaths map[string]string
	lstats    map[string]os.FileInfo
}

func (h *w12aStaticSFTPHandler) RealPath(p string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if rp, ok := h.realPaths[p]; ok {
		return rp, nil
	}
	return p, nil
}

func (h *w12aStaticSFTPHandler) Lstat(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if fi, ok := h.lstats[r.Filepath]; ok {
		return w10aListerAt{fi}, nil
	}
	if fi, ok := h.stats[r.Filepath]; ok {
		return w10aListerAt{fi}, nil
	}
	return nil, os.ErrNotExist
}

func (h *w12aStaticSFTPHandler) handlers() pkgsftp.Handlers {
	return pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

func startW12aHTTPTransferRuntime(
	t *testing.T,
	guardCfg *policy.Config,
	handlers pkgsftp.Handlers,
	elicitHandler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error),
) (*Runtime, *mcp.ClientSession, *w11aAuditRecorder) {
	t.Helper()
	baseProvider := startTransferSSH(t, handlers)
	cfg := baseProvider.Snapshot()
	cfg.Guardrail = guardCfg
	provider := config.NewProviderWithoutOpenSSH(cfg)

	server := httptest.NewUnstartedServer(nil)
	options := DefaultHTTPOptions()
	options.Token = httpTestToken
	options.PublicURL = "http://" + server.Listener.Addr().String()
	options.StateDir = filepath.Join(t.TempDir(), "tasks")

	r, err := NewRuntime(t.Context(), WithConfigProvider(provider), WithHTTP(options))
	if err != nil {
		server.Close()
		t.Fatalf("NewRuntime: %v", err)
	}
	recorder := &w11aAuditRecorder{}
	r.guardrail.SetAuditWriter(recorder)
	t.Cleanup(func() {
		if closeErr := r.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		server.Close()
	})
	server.Config.Handler, err = r.HTTPHandler()
	if err != nil {
		t.Fatalf("HTTPHandler: %v", err)
	}
	server.Start()

	var clientOpts *mcp.ClientOptions
	if elicitHandler != nil {
		clientOpts = &mcp.ClientOptions{ElicitationHandler: elicitHandler}
	}
	return r, connectHTTPTestClient(t, server, clientOpts), recorder
}

// TestP7W12a_AB12M1_StdioTransferProtectedPathsPosixBackslashAndWindowsDrive
// verifies AB12-M1 through the stdio transfer tool:
//   - POSIX "\.." spoofing in LocalPath or RemotePath (e.g.
//     "/opt/custom-protected/\../drop") still matches ProtectedPaths and
//     triggers Elicitation instead of being allowed silently.
//   - Windows drive ProtectedPaths match case-insensitively and across leading
//     slash / backslash differences for both LocalPath and RemotePath.
func TestP7W12a_AB12M1_StdioTransferProtectedPathsPosixBackslashAndWindowsDrive(t *testing.T) {
	var mu sync.Mutex
	var elicitedMessages []string
	_, client, backend, audit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths: []string{
			"/opt/custom-protected",
			`C:\ProgramData\ssh`,
			"/C:/Users/Alice/.ssh",
		},
	}, func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		mu.Lock()
		elicitedMessages = append(elicitedMessages, req.Params.Message)
		mu.Unlock()
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	cases := []struct {
		name      string
		local     string
		remote    string
		wantAudit string
	}{
		{
			name:      "posix_backslash_spoof_local_path",
			local:     `/opt/custom-protected/\../drop`,
			remote:    "/tmp/pkg",
			wantAudit: `/opt/custom-protected/\../drop`,
		},
		{
			name:      "posix_backslash_spoof_remote_path",
			local:     "/tmp/safe-drop",
			remote:    `/opt/custom-protected/\../secret`,
			wantAudit: `/opt/custom-protected/\../secret`,
		},
		{
			name:      "windows_drive_local_path_lowercase_backslash",
			local:     `c:\users\alice\.ssh\authorized_keys`,
			remote:    "/tmp/pkg",
			wantAudit: `c:\users\alice\.ssh\authorized_keys`,
		},
		{
			name:      "windows_drive_local_path_vs_backslash_prefix",
			local:     `C:\ProgramData\ssh\sshd_config`,
			remote:    "/tmp/pkg",
			wantAudit: `C:\ProgramData\ssh\sshd_config`,
		},
		{
			name:      "windows_drive_remote_path_canonical_vs_backslash_prefix",
			local:     "/tmp/safe-drop",
			remote:    `c:\programdata\ssh\sshd_config`,
			wantAudit: "/C:/programdata/ssh/sshd_config",
		},
		{
			name:      "windows_drive_remote_path_double_slash_collapsed",
			local:     "/tmp/safe-drop",
			remote:    `//c:\ProgramData\ssh\sshd_config`,
			wantAudit: "/C:/ProgramData/ssh/sshd_config",
		},
		{
			name:      "windows_drive_remote_path_dotdot_collapsed",
			local:     "/tmp/safe-drop",
			remote:    "/tmp/../C:/ProgramData/ssh/sshd_config",
			wantAudit: "/C:/ProgramData/ssh/sshd_config",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit.reset()
			mu.Lock()
			elicitedMessages = nil
			mu.Unlock()

			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "transfer",
				Arguments: TransferFileInput{
					NodeID:     "files",
					Direction:  "pull",
					LocalPath:  tc.local,
					RemotePath: tc.remote,
				},
			})
			if err == nil && !res.IsError {
				t.Fatalf("stdio pull (%s) bypassed guardrail approval", tc.name)
			}
			if backend.openFiles.Load() != 0 {
				t.Fatalf("SFTP opened %d times despite declined approval", backend.openFiles.Load())
			}
			mu.Lock()
			msgs := slices.Clone(elicitedMessages)
			mu.Unlock()
			if len(msgs) != 1 {
				t.Fatalf("elicitation calls = %d, want 1", len(msgs))
			}
			entries := audit.snapshot()
			if len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
				t.Fatalf("audit entries = %+v, want final denied entry", entries)
			}
			if !slices.Contains(entries[len(entries)-1].Paths, tc.wantAudit) {
				t.Fatalf("audit Paths = %v, want %q", entries[len(entries)-1].Paths, tc.wantAudit)
			}
		})
	}
}

// TestP7W12a_AB12M1_FileToolProtectedPathsPosixBackslashAndWindowsDrive
// verifies AB12-M1 through the file tool (read and stat).
func TestP7W12a_AB12M1_FileToolProtectedPathsPosixBackslashAndWindowsDrive(t *testing.T) {
	var mu sync.Mutex
	var elicitedMessages []string
	_, client, backend, audit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths: []string{
			"/opt/custom-protected",
			`C:\ProgramData\ssh`,
			"/C:/Users/Alice/.ssh",
		},
	}, func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		mu.Lock()
		elicitedMessages = append(elicitedMessages, req.Params.Message)
		mu.Unlock()
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	protectedPaths := []string{
		`/opt/custom-protected/\../secret`,
		"/C:/ProgramData/ssh/sshd_config",
		`c:\programdata\ssh\sshd_config`,
		`//c:\ProgramData\ssh\sshd_config`,
		"/tmp/../C:/ProgramData/ssh/sshd_config",
		`c:\users\alice\.ssh\authorized_keys`,
	}

	for _, action := range []string{"read", "stat"} {
		for _, p := range protectedPaths {
			t.Run(action+"_"+p, func(t *testing.T) {
				audit.reset()
				mu.Lock()
				elicitedMessages = nil
				mu.Unlock()

				res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
					Name: "file",
					Arguments: FileInput{
						NodeID: "files",
						Action: action,
						Path:   p,
					},
				})
				if err == nil && !res.IsError {
					t.Fatalf("file %s(%q) bypassed guardrail approval", action, p)
				}
				if backend.openFiles.Load() != 0 {
					t.Fatalf("file %s(%q) opened SFTP %d times despite declined approval", action, p, backend.openFiles.Load())
				}
				mu.Lock()
				msgs := slices.Clone(elicitedMessages)
				mu.Unlock()
				if len(msgs) != 1 {
					t.Fatalf("file %s(%q) elicited %d times, want 1", action, p, len(msgs))
				}
				entries := audit.snapshot()
				if len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
					t.Fatalf("audit = %+v, want final denied entry", entries)
				}
			})
		}
	}
}

// TestP7W12a_AB12M1_HTTPPreparePullProtectedPathsPosixBackslashAndWindowsDrive
// verifies AB12-M1 and AB12-L1 end-to-end through HTTP transfer prepare_pull:
//   - Protected POSIX "\.." paths, Windows drive ProtectedPaths (with backslash,
//     case, "//", and "/tmp/.." variants), and collapsed Windows sensitive paths
//     all trigger Elicitation during guardrail.Authorize and persist zero tasks
//     when declined.
//   - An unprotected file on the same runtime prepares cleanly without Elicitation.
func TestP7W12a_AB12M1_HTTPPreparePullProtectedPathsPosixBackslashAndWindowsDrive(t *testing.T) {
	h := &w12aStaticSFTPHandler{
		w10aHostileSFTPHandler: newW10aHostileSFTPHandler(),
		realPaths: map[string]string{
			`/opt/custom-protected/\..`:   `/opt/custom-protected/\..`,
			"/C:/ProgramData/ssh":         "/C:/ProgramData/ssh",
			"/C:/programdata/ssh":         "/c:/programdata/ssh",
			"/C:/Windows/System32/config": "/C:/Windows/System32/config",
			"/tmp":                        "/tmp",
		},
		lstats: map[string]os.FileInfo{
			`/opt/custom-protected/\../secret`: w10aSynthFileInfo{name: "secret", size: 16, mode: 0o600},
			"/C:/ProgramData/ssh/sshd_config":  w10aSynthFileInfo{name: "sshd_config", size: 32, mode: 0o600},
			"/C:/programdata/ssh/sshd_config":  w10aSynthFileInfo{name: "sshd_config", size: 32, mode: 0o600},
			"/c:/programdata/ssh/sshd_config":  w10aSynthFileInfo{name: "sshd_config", size: 32, mode: 0o600},
			"/C:/Windows/System32/config/SAM":  w10aSynthFileInfo{name: "SAM", size: 64, mode: 0o600},
			"/tmp/public.bin":                  w10aSynthFileInfo{name: "public.bin", size: 12, mode: 0o644},
		},
	}
	h.stats[`/opt/custom-protected/\..`] = w10aSynthFileInfo{name: `\..`, mode: os.ModeDir | 0o755}
	h.stats["/C:/ProgramData/ssh"] = w10aSynthFileInfo{name: "ssh", mode: os.ModeDir | 0o755}
	h.stats["/C:/programdata/ssh"] = w10aSynthFileInfo{name: "ssh", mode: os.ModeDir | 0o755}
	h.stats["/c:/programdata/ssh"] = w10aSynthFileInfo{name: "ssh", mode: os.ModeDir | 0o755}
	h.stats["/C:/Windows/System32/config"] = w10aSynthFileInfo{name: "config", mode: os.ModeDir | 0o755}
	h.stats["/tmp"] = w10aSynthFileInfo{name: "tmp", mode: os.ModeDir | 0o755}

	var mu sync.Mutex
	var elicitedMessages []string
	r, client, audit := startW12aHTTPTransferRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths: []string{
			"/opt/custom-protected",
			`C:\ProgramData\ssh`,
		},
	}, h.handlers(), func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		mu.Lock()
		elicitedMessages = append(elicitedMessages, req.Params.Message)
		mu.Unlock()
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	protectedCases := []struct {
		name       string
		remotePath string
	}{
		{"posix_backslash_dotdot_spoof", `/opt/custom-protected/\../secret`},
		{"windows_drive_double_slash_backslash", `//c:\ProgramData\ssh\sshd_config`},
		{"windows_drive_lowercase_backslash", `c:\programdata\ssh\sshd_config`},
		{"windows_drive_dotdot_collapsed", "/tmp/../C:/ProgramData/ssh/sshd_config"},
		{"windows_sensitive_double_slash_sam", "//C:/Windows/System32/config/SAM"},
		{"windows_sensitive_dotdot_sam", "/tmp/../C:/Windows/System32/config/SAM"},
	}

	for _, tc := range protectedCases {
		t.Run(tc.name, func(t *testing.T) {
			audit.reset()
			mu.Lock()
			elicitedMessages = nil
			mu.Unlock()

			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "transfer",
				Arguments: PrepareDownloadInput{
					Action:     "prepare_pull",
					RequestID:  "req-" + tc.name,
					NodeID:     "files",
					RemotePath: tc.remotePath,
				},
			})
			if err == nil && !res.IsError {
				t.Fatalf("HTTP prepare_pull(%q) bypassed guardrail approval: %+v", tc.remotePath, res)
			}
			mu.Lock()
			msgs := slices.Clone(elicitedMessages)
			mu.Unlock()
			if len(msgs) != 1 {
				t.Fatalf("HTTP prepare_pull(%q) elicited %d times, want 1", tc.remotePath, len(msgs))
			}
			if got := len(r.transfers.Records()); got != 0 {
				t.Fatalf("HTTP prepare_pull(%q) persisted %d transfer records, want 0", tc.remotePath, got)
			}
			entries := audit.snapshot()
			if len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
				t.Fatalf("HTTP prepare_pull(%q) audit = %+v, want final denied entry", tc.remotePath, entries)
			}
		})
	}

	t.Run("unprotected_file_prepares_without_elicitation", func(t *testing.T) {
		mu.Lock()
		elicitedMessages = nil
		mu.Unlock()

		out := prepareTransferTest(t, client, "transfer", PrepareDownloadInput{
			Action:     "prepare_pull",
			RequestID:  "req-public-ok",
			NodeID:     "files",
			RemotePath: "/tmp/public.bin",
		})
		if out.Task.RemotePath != "/tmp/public.bin" {
			t.Fatalf("prepared RemotePath = %q, want /tmp/public.bin", out.Task.RemotePath)
		}
		mu.Lock()
		count := len(elicitedMessages)
		mu.Unlock()
		if count != 0 {
			t.Fatalf("unprotected /tmp/public.bin unexpectedly elicited %d times", count)
		}
	})
}

// TestP7W12a_AB12L1_CollapsedWindowsDrivePathsGuardrailAndHandler verifies AB12-L1
// across file, stdio transfer, HTTP transfer, and terminal tools:
//   - Collapsed Windows drive roots ("//C:/", "/tmp/../C:/", "///c:\") and
//     relative-disguised drive paths ("./C:/Users/admin/a.txt") are classified
//     Dangerous by guardrail AND rejected fail-closed by handlers even when
//     guardrail is disabled.
//   - Collapsed Windows sensitive paths ("//C:/Windows/System32/config/SAM",
//     "/tmp/../C:/Windows/System32/config/SAM") are classified Moderate and
//     require approval under a moderate threshold.
func TestP7W12a_AB12L1_CollapsedWindowsDrivePathsGuardrailAndHandler(t *testing.T) {
	t.Run("guardrail_rates_collapsed_drive_roots_dangerous", testP7W12aCollapsedDriveRootsDangerous)
	t.Run("guardrail_rates_collapsed_windows_sensitive_moderate", testP7W12aCollapsedWindowsSensitiveModerate)
	t.Run("handlers_reject_collapsed_drive_roots_before_sftp_when_guardrail_disabled", testP7W12aHandlersRejectCollapsedDriveRoots)
	t.Run("http_transfer_rejects_collapsed_drive_roots_when_guardrail_disabled", testP7W12aHTTPTransferRejectsCollapsedDriveRoots)
}

func testP7W12aCollapsedDriveRootsDangerous(t *testing.T) {
	_, client, backend, audit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDowngrade,
	}, nil)

	dangerousTargets := []string{
		"//C:/",
		"/tmp/../C:/",
		`///c:\`,
		"./C:/Users/admin/a.txt",
	}
	for _, p := range dangerousTargets {
		audit.reset()
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "file",
			Arguments: FileInput{
				NodeID: "files",
				Action: "stat",
				Path:   p,
			},
		})
		if err == nil && !res.IsError {
			t.Fatalf("file stat(%q) must be denied as Dangerous", p)
		}
		entries := audit.snapshot()
		if len(entries) != 1 || entries[0].RiskLevel != "dangerous" || entries[0].Outcome != "denied" {
			t.Fatalf("file stat(%q) audit = %+v, want risk=dangerous outcome=denied", p, entries)
		}

		// terminal Cwd passes raw path straight into guardrail.
		audit.reset()
		termRes, termErr := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "terminal",
			Arguments: TerminalInput{
				NodeID:  "files",
				Session: "once",
				Command: "ls",
				Cwd:     p,
			},
		})
		if termErr == nil && !termRes.IsError {
			t.Fatalf("terminal(cwd=%q) must be denied as Dangerous", p)
		}
		entries = audit.snapshot()
		if len(entries) != 1 || entries[0].RiskLevel != "dangerous" || entries[0].Outcome != "denied" {
			t.Fatalf("terminal(cwd=%q) audit = %+v, want risk=dangerous outcome=denied", p, entries)
		}
	}
	if backend.openFiles.Load() != 0 {
		t.Fatalf("guardrail-denied calls opened SFTP %d times, want 0", backend.openFiles.Load())
	}
}

func testP7W12aCollapsedWindowsSensitiveModerate(t *testing.T) {
	var mu sync.Mutex
	var elicited int
	_, modClient, modBackend, modAudit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
	}, func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		mu.Lock()
		elicited++
		mu.Unlock()
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	for _, p := range []string{
		"//C:/Windows/System32/config/SAM",
		"/tmp/../C:/Windows/System32/config/SAM",
		`///c:\Windows\System32\config\SAM`,
	} {
		modAudit.reset()
		mu.Lock()
		elicited = 0
		mu.Unlock()

		res, err := modClient.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "file",
			Arguments: FileInput{
				NodeID: "files",
				Action: "read",
				Path:   p,
			},
		})
		if err == nil && !res.IsError {
			t.Fatalf("file read(%q) must require approval as Moderate", p)
		}
		mu.Lock()
		gotElicited := elicited
		mu.Unlock()
		if gotElicited != 1 {
			t.Fatalf("file read(%q) elicited %d times, want 1", p, gotElicited)
		}
		entries := modAudit.snapshot()
		if len(entries) == 0 || entries[len(entries)-1].RiskLevel != "moderate" || entries[len(entries)-1].Outcome != "denied" {
			t.Fatalf("file read(%q) audit = %+v, want final risk=moderate outcome=denied", p, entries)
		}
	}
	if modBackend.openFiles.Load() != 0 {
		t.Fatalf("guardrail-denied calls opened SFTP %d times, want 0", modBackend.openFiles.Load())
	}
}

func testP7W12aHandlersRejectCollapsedDriveRoots(t *testing.T) {
	_, client, backend, _ := startW11aCountingRuntime(t, &policy.Config{Disabled: true}, nil)

	badPaths := []string{
		"//C:/",
		"/tmp/../C:/",
		`///c:\`,
		`/tmp/../c:\`,
		"./C:/Users/admin/a.txt",
	}
	for _, action := range []string{"read", "write", "patch"} {
		for _, p := range badPaths {
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
				t.Fatalf("file %s accepted collapsed/invalid path %q", action, p)
			}
		}
	}

	validLocal := filepath.Join(t.TempDir(), "ok.txt")
	for _, dir := range []string{"push", "pull"} {
		for _, p := range badPaths {
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
				t.Fatalf("stdio transfer %s accepted collapsed/invalid RemotePath %q", dir, p)
			}
		}
		for _, lp := range []string{"//C:/", "/tmp/../C:/", `///c:\`, "./C:/Users/admin/a.txt"} {
			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "transfer",
				Arguments: TransferFileInput{
					NodeID:     "files",
					Direction:  dir,
					LocalPath:  lp,
					RemotePath: "/tmp/pkg",
				},
			})
			if err == nil && !res.IsError {
				t.Fatalf("stdio transfer %s accepted collapsed/invalid LocalPath %q", dir, lp)
			}
		}
	}

	if backend.openFiles.Load() != 0 {
		t.Fatalf("handlers opened SFTP %d times for rejected paths, want 0", backend.openFiles.Load())
	}
}

func testP7W12aHTTPTransferRejectsCollapsedDriveRoots(t *testing.T) {
	badPaths := []string{
		"//C:/",
		"/tmp/../C:/",
		`///c:\`,
		`/tmp/../c:\`,
		"./C:/Users/admin/a.txt",
	}
	httpRT, httpClient, _ := startW12aHTTPTransferRuntime(t, &policy.Config{Disabled: true}, pkgsftp.InMemHandler(), nil)
	digest := sha256.Sum256([]byte("hi"))
	hexDigest := hex.EncodeToString(digest[:])
	for i, p := range badPaths {
		pullRes, pullErr := httpClient.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "transfer",
			Arguments: PrepareDownloadInput{
				Action:     "prepare_pull",
				RequestID:  "req-pull-" + strings.Repeat("a", i+1),
				NodeID:     "files",
				RemotePath: p,
			},
		})
		if pullErr == nil && !pullRes.IsError {
			t.Fatalf("HTTP prepare_pull accepted collapsed/invalid path %q", p)
		}

		pushRes, pushErr := httpClient.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "transfer",
			Arguments: PrepareUploadInput{
				Action:     "prepare_push",
				RequestID:  "req-push-" + strings.Repeat("b", i+1),
				NodeID:     "files",
				RemotePath: p,
				Size:       2,
				SHA256:     hexDigest,
			},
		})
		if pushErr == nil && !pushRes.IsError {
			t.Fatalf("HTTP prepare_push accepted collapsed/invalid path %q", p)
		}
	}
	if got := len(httpRT.transfers.Records()); got != 0 {
		t.Fatalf("HTTP transfer persisted %d records for rejected paths, want 0", got)
	}
}
