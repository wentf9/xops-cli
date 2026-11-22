package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/sftp"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
)

type w11aAuditRecorder struct {
	mu      sync.Mutex
	entries []guardrail.AuditEntry
}

func (a *w11aAuditRecorder) Log(entry guardrail.AuditEntry) error {
	a.mu.Lock()
	a.entries = append(a.entries, entry)
	a.mu.Unlock()
	return nil
}

func (a *w11aAuditRecorder) snapshot() []guardrail.AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.entries)
}

func (a *w11aAuditRecorder) reset() {
	a.mu.Lock()
	a.entries = nil
	a.mu.Unlock()
}

type w11aCountingBackend struct {
	ports.Backend
	openFiles atomic.Int32
}

func (b *w11aCountingBackend) OpenFiles(context.Context, ports.Permit, string) (ports.FileSession, error) {
	b.openFiles.Add(1)
	return nil, errors.New("unexpected SFTP session open in w11a test")
}

func (b *w11aCountingBackend) Shutdown(context.Context) error { return nil }

func startW11aCountingRuntime(
	t *testing.T,
	guardCfg *policy.Config,
	elicitHandler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error),
) (*Runtime, *mcp.ClientSession, *w11aCountingBackend, *w11aAuditRecorder) {
	t.Helper()
	cfg := runtimeTestProvider("files").Snapshot()
	cfg.Guardrail = guardCfg
	provider := config.NewProviderWithoutOpenSSH(cfg)
	backend := &w11aCountingBackend{}
	recorder := &w11aAuditRecorder{}
	deps := ports.Dependencies{
		State:      provider,
		Gate:       provider,
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(deps))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	r.guardrail.SetAuditWriter(recorder)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})

	ct, st := mcp.NewInMemoryTransports()
	ss, err := r.server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	var clientOpts *mcp.ClientOptions
	if elicitHandler != nil {
		clientOpts = &mcp.ClientOptions{ElicitationHandler: elicitHandler}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "w11a-test-client", Version: "1"}, clientOpts)
	cs, err := client.Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return r, cs, backend, recorder
}

// TestP7W11a_AB11H1_StdioTransferLocalPathGuardrailAndValidation verifies AB11-H1:
//   - Stdio transfer includes cleaned LocalPath in RiskInput.Paths for BOTH push and pull.
//   - Pull with LocalPath "/" triggers Dangerous guardrail enforcement and audit logging.
//   - Pull with LocalPath under sensitivePaths ("/etc/cron.d/backdoor") or custom
//     ProtectedPaths triggers Moderate/protected guardrail enforcement and Elicitation.
//   - Relative, root, and control-tainted LocalPath/RemotePath values are classified
//     Dangerous by guardrail AND rejected fail-closed by stdioTransferHandler before
//     any SFTP session is opened (even when guardrail is disabled).
//   - Successful stdio push and pull record both LocalPath and RemotePath in AuditEntry.Paths.
func TestP7W11a_AB11H1_StdioTransferLocalPathGuardrailAndValidation(t *testing.T) {
	t.Run("pull_root_local_path_triggers_dangerous_guardrail_and_audit", testP7W11aPullRootLocalPath)
	t.Run("pull_sensitive_and_protected_local_paths_trigger_guardrail_and_elicitation", testP7W11aPullProtectedLocalPaths)
	t.Run("relative_local_paths_classified_dangerous_by_guardrail_on_push_and_pull", testP7W11aRelativeLocalPathsGuardrail)
	t.Run("handler_rejects_relative_root_and_control_paths_before_sftp_even_when_guardrail_disabled", testP7W11aHandlerRejectsBeforeSFTP)
	t.Run("valid_stdio_push_and_pull_record_both_paths_in_audit", testP7W11aValidStdioPushPullAudit)
}

func testP7W11aPullRootLocalPath(t *testing.T) {
	_, client, backend, audit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDowngrade,
		ProtectedPaths:    []string{"/etc", "/boot"},
	}, nil)

	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "files",
			Direction:  "pull",
			LocalPath:  "/",
			RemotePath: "/tmp/pkg",
		},
	})
	if err == nil && !res.IsError {
		t.Fatal("pull with LocalPath='/' must be denied by guardrail, got success")
	}
	if backend.openFiles.Load() != 0 {
		t.Fatalf("SFTP session opened %d times despite guardrail deny", backend.openFiles.Load())
	}
	entries := audit.snapshot()
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d: %+v", len(entries), entries)
	}
	if entries[0].RiskLevel != "dangerous" || entries[0].Outcome != "denied" {
		t.Fatalf("audit entry = %+v, want risk=dangerous outcome=denied", entries[0])
	}
	if !slices.Contains(entries[0].Paths, "/") || !slices.Contains(entries[0].Paths, "/tmp/pkg") {
		t.Fatalf("audit Paths = %v, want both '/' and '/tmp/pkg'", entries[0].Paths)
	}
}

func testP7W11aPullProtectedLocalPaths(t *testing.T) {
	var elicitedMessages []string
	_, client, backend, audit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc", "/opt/custom-protected"},
	}, func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		elicitedMessages = append(elicitedMessages, req.Params.Message)
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	for _, localTarget := range []string{"/etc/cron.d/backdoor", "/opt/custom-protected/secret.conf"} {
		audit.reset()
		elicitedMessages = nil
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "transfer",
			Arguments: TransferFileInput{
				NodeID:     "files",
				Direction:  "pull",
				LocalPath:  localTarget,
				RemotePath: "/tmp/pkg",
			},
		})
		if err == nil && !res.IsError {
			t.Fatalf("pull to protected LocalPath %q must require approval and fail on decline", localTarget)
		}
		if backend.openFiles.Load() != 0 {
			t.Fatalf("SFTP session opened %d times for declined protected LocalPath %q", backend.openFiles.Load(), localTarget)
		}
		if len(elicitedMessages) != 1 {
			t.Fatalf("LocalPath %q elicited %d times, want 1", localTarget, len(elicitedMessages))
		}
		if !strings.Contains(elicitedMessages[0], localTarget) || !strings.Contains(elicitedMessages[0], "/tmp/pkg") {
			t.Fatalf("elicitation message missing both paths for %q:\n%s", localTarget, elicitedMessages[0])
		}
		entries := audit.snapshot()
		if len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
			t.Fatalf("audit for %q = %+v, want final denied entry", localTarget, entries)
		}
		for _, e := range entries {
			if !slices.Contains(e.Paths, localTarget) || !slices.Contains(e.Paths, "/tmp/pkg") {
				t.Fatalf("audit Paths for %q = %v, want both local and remote paths", localTarget, e.Paths)
			}
		}
	}
}

func testP7W11aRelativeLocalPathsGuardrail(t *testing.T) {
	_, client, backend, audit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDeny,
	}, nil)

	cases := []TransferFileInput{
		{NodeID: "files", Direction: "push", LocalPath: "../../etc/shadow", RemotePath: "/tmp/out"},
		{NodeID: "files", Direction: "pull", LocalPath: "../../etc/cron.d/x", RemotePath: "/tmp/pkg"},
		{NodeID: "files", Direction: "pull", LocalPath: "/tmp/bad\n/../good", RemotePath: "/tmp/pkg"},
	}
	for _, tc := range cases {
		audit.reset()
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "transfer", Arguments: tc})
		if err == nil && !res.IsError {
			t.Fatalf("transfer %+v unexpectedly succeeded", tc)
		}
		if backend.openFiles.Load() != 0 {
			t.Fatalf("transfer %+v opened SFTP %d times", tc, backend.openFiles.Load())
		}
		entries := audit.snapshot()
		if len(entries) != 1 || entries[0].RiskLevel != "dangerous" || entries[0].Outcome != "denied" {
			t.Fatalf("audit for %+v = %+v, want risk=dangerous outcome=denied", tc, entries)
		}
		if !slices.Contains(entries[0].Paths, tc.LocalPath) || !slices.Contains(entries[0].Paths, tc.RemotePath) {
			t.Fatalf("audit Paths for %+v = %v, want both %q and %q", tc, entries[0].Paths, tc.LocalPath, tc.RemotePath)
		}
	}
}

func testP7W11aHandlerRejectsBeforeSFTP(t *testing.T) {
	_, client, backend, _ := startW11aCountingRuntime(t, &policy.Config{Disabled: true}, nil)

	badLocalPaths := []string{
		"../../etc/shadow",
		"../../etc/cron.d/x",
		"relative/file.txt",
		".",
		"/",
		"///",
		"/tmp/..",
		"/C:",
		"/tmp/bad\nfile",
		"/tmp/bad\x00file",
		"/tmp/bad\x1b[31mfile",
		"/tmp/bad\x7ffile",
		"/tmp/bad\u009b2Jfile",
		"/tmp/bad\u2028file",
		"/tmp/bad\u2029file",
		"/tmp/bad\n/../good",
	}
	if runtime.GOOS == "windows" {
		if vol := filepath.VolumeName(t.TempDir()); vol != "" {
			badLocalPaths = append(badLocalPaths, vol+`\`, vol+`/`)
		}
	}
	for _, dir := range []string{"push", "pull"} {
		for _, lp := range badLocalPaths {
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
				t.Fatalf("stdio transfer %s accepted invalid LocalPath %q", dir, lp)
			}
		}
	}

	validLocal := filepath.Join(t.TempDir(), "ok.txt")
	badRemotePaths := []string{
		"../../etc/passwd",
		".ssh/authorized_keys",
		"/",
		`C:\`,
		"/tmp/bad\nfile",
		"/tmp/bad\x00file",
		"/tmp/bad\u2028file",
		"/tmp/bad\n/../good",
	}
	for _, dir := range []string{"push", "pull"} {
		for _, rp := range badRemotePaths {
			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "transfer",
				Arguments: TransferFileInput{
					NodeID:     "files",
					Direction:  dir,
					LocalPath:  validLocal,
					RemotePath: rp,
				},
			})
			if err == nil && !res.IsError {
				t.Fatalf("stdio transfer %s accepted invalid RemotePath %q", dir, rp)
			}
		}
	}
	if backend.openFiles.Load() != 0 {
		t.Fatalf("SFTP OpenFiles called %d times for rejected paths, want 0", backend.openFiles.Load())
	}
}

func startW11aGuardedStdioSSHClient(t *testing.T, guardCfg *policy.Config) (*mcp.ClientSession, *w11aAuditRecorder) {
	t.Helper()
	provider := startTransferSSH(t, pkgsftp.InMemHandler())
	cfg := provider.Snapshot()
	cfg.Guardrail = guardCfg
	r, err := NewRuntime(t.Context(), WithConfigProvider(config.NewProviderWithoutOpenSSH(cfg)))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	recorder := &w11aAuditRecorder{}
	r.guardrail.SetAuditWriter(recorder)
	t.Cleanup(func() {
		if closeErr := r.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})

	ct, st := mcp.NewInMemoryTransports()
	ss, err := r.server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "w11a-stdio-valid", Version: "1"}, nil)
	cs, err := client.Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, recorder
}

func assertW11aAuditHasExecutedPaths(t *testing.T, entries []guardrail.AuditEntry, localPath, remotePath string) {
	t.Helper()
	for _, e := range entries {
		if e.Tool == "transfer" && e.Outcome == "executed" &&
			slices.Contains(e.Paths, filepath.Clean(localPath)) &&
			slices.Contains(e.Paths, remotePath) {
			return
		}
	}
	t.Fatalf("audit entries missing executed transfer with paths (%q, %q): %+v", localPath, remotePath, entries)
}

func testP7W11aValidStdioPushPullAudit(t *testing.T) {
	cs, recorder := startW11aGuardedStdioSSHClient(t, &policy.Config{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDowngrade,
		ProtectedPaths:    []string{"/etc"},
	})

	localDir := t.TempDir()
	srcFile := filepath.Join(localDir, "src.txt")
	dstFile := filepath.Join(localDir, "dst.txt")
	if err := os.WriteFile(srcFile, []byte("w11a-payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	pushRes, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "files",
			Direction:  "push",
			LocalPath:  srcFile,
			RemotePath: "/pushed.txt",
		},
	})
	if err != nil || pushRes.IsError {
		t.Fatalf("push failed: err=%v res=%+v", err, pushRes)
	}

	pullRes, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "files",
			Direction:  "pull",
			LocalPath:  dstFile,
			RemotePath: "/pushed.txt",
		},
	})
	if err != nil || pullRes.IsError {
		t.Fatalf("pull failed: err=%v res=%+v", err, pullRes)
	}
	got, err := os.ReadFile(dstFile)
	if err != nil || string(got) != "w11a-payload" {
		t.Fatalf("pulled content = %q err=%v", got, err)
	}

	entries := recorder.snapshot()
	assertW11aAuditHasExecutedPaths(t, entries, srcFile, "/pushed.txt")
	assertW11aAuditHasExecutedPaths(t, entries, dstFile, "/pushed.txt")
}

// TestP7W11a_AB11M1_FileToolRejectsRelativeAndControlPathsBeforeGuardrailOrSFTP
// verifies AB11-M1:
//   - ALL file actions (stat, patch, read, write) reject relative and
//     control/line-separator-tainted paths BEFORE opening any SFTP session.
//   - Guardrail never classifies relative or control-tainted file paths as Safe
//     (preventing stat/read bypass of Moderate/ProtectedPaths approval).
//   - Direct helpers (fileStat, fileRead, filePatch, replaceFile) also fail closed
//     before calling FileSession.Do.
func TestP7W11a_AB11M1_FileToolRejectsRelativeAndControlPathsBeforeGuardrailOrSFTP(t *testing.T) {
	t.Run("all_actions_reject_before_sftp_when_guardrail_disabled", testP7W11aFileActionsRejectBeforeSFTP)
	t.Run("relative_and_control_file_paths_never_classified_safe_by_guardrail", testP7W11aFilePathsNeverSafeInGuardrail)
	t.Run("direct_helpers_reject_before_sftp_do", testP7W11aDirectFileHelpersRejectBeforeDo)
}

func testP7W11aFileActionsRejectBeforeSFTP(t *testing.T) {
	badPaths := []string{
		"../../etc",
		"../../etc/passwd",
		".ssh",
		"relative/file.txt",
		" /etc/passwd",
		"C:relative.txt",
		`\etc\passwd`,
		"/tmp/bad\nline",
		"/tmp/bad\rline",
		"/tmp/bad\x00null",
		"/tmp/bad\x1b[31m",
		"/tmp/bad\x7f",
		"/tmp/bad\u009b2J",
		"/tmp/bad\u2028sep",
		"/tmp/bad\u2029sep",
		"/tmp/bad\n/../good",
	}

	_, client, backend, _ := startW11aCountingRuntime(t, &policy.Config{Disabled: true}, nil)

	for _, action := range []string{"stat", "patch", "read", "write"} {
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
				t.Fatalf("file action=%s accepted invalid path %q", action, p)
			}
		}
	}

	// read/write/patch on root or Windows drive root must also fail before SFTP open.
	for _, action := range []string{"read", "write", "patch"} {
		for _, rootPath := range []string{"/", `C:\`, "/C:"} {
			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "file",
				Arguments: FileInput{
					NodeID:  "files",
					Action:  action,
					Path:    rootPath,
					Content: "<<<<\na\n====\nb\n>>>>",
				},
			})
			if err == nil && !res.IsError {
				t.Fatalf("file action=%s accepted root path %q", action, rootPath)
			}
		}
	}

	if backend.openFiles.Load() != 0 {
		t.Fatalf("fileHandler opened SFTP %d times for rejected paths, want 0", backend.openFiles.Load())
	}
}

func testP7W11aFilePathsNeverSafeInGuardrail(t *testing.T) {
	_, client, backend, audit := startW11aCountingRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc"},
	}, nil)

	cases := []FileInput{
		{NodeID: "files", Action: "stat", Path: "../../etc"},
		{NodeID: "files", Action: "stat", Path: ".ssh"},
		{NodeID: "files", Action: "stat", Path: "/tmp/bad\n/../good"},
		{NodeID: "files", Action: "read", Path: "../../etc/passwd"},
		{NodeID: "files", Action: "patch", Path: "../../etc/passwd", Content: "<<<<\na\n====\nb\n>>>>"},
	}
	for _, tc := range cases {
		audit.reset()
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "file", Arguments: tc})
		if err == nil && !res.IsError {
			t.Fatalf("file %+v must be denied by guardrail", tc)
		}
		entries := audit.snapshot()
		if len(entries) != 1 || entries[0].RiskLevel != "dangerous" || entries[0].Outcome != "denied" {
			t.Fatalf("guardrail audit for %+v = %+v, want risk=dangerous outcome=denied", tc, entries)
		}
	}
	if backend.openFiles.Load() != 0 {
		t.Fatalf("guardrail-denied file calls opened SFTP %d times, want 0", backend.openFiles.Load())
	}
}

func testP7W11aDirectFileHelpersRejectBeforeDo(t *testing.T) {
	var doCalls int
	fakeSession := &w11aNoDoFileSession{onDo: func() { doCalls++ }}
	for _, bad := range []string{"../../etc", ".ssh", "/tmp/bad\n/../good"} {
		if _, err := fileStat(t.Context(), fakeSession, FileInput{Path: bad}); err == nil {
			t.Fatalf("fileStat(%q) succeeded", bad)
		}
		if _, err := fileRead(t.Context(), fakeSession, FileInput{Path: bad}); err == nil {
			t.Fatalf("fileRead(%q) succeeded", bad)
		}
		if _, err := filePatch(t.Context(), fakeSession, FileInput{Path: bad, Content: "<<<<\na\n====\nb\n>>>>"}); err == nil {
			t.Fatalf("filePatch(%q) succeeded", bad)
		}
		if _, err := replaceFile(t.Context(), fakeSession, bad, []byte("x"), nil); err == nil {
			t.Fatalf("replaceFile(%q) succeeded", bad)
		}
	}
	if doCalls != 0 {
		t.Fatalf("direct file helpers invoked FileSession.Do %d times on invalid paths, want 0", doCalls)
	}
}

type w11aNoDoFileSession struct {
	ports.FileSession
	onDo func()
}

func (f *w11aNoDoFileSession) Do(context.Context, func(*pkgsftp.Client) error) error {
	f.onDo()
	return errors.New("FileSession.Do must not be called")
}

func (f *w11aNoDoFileSession) Close() error { return nil }

type w11aHostileRealPathHandler struct {
	*w10aHostileSFTPHandler
	realPath string
	lstats   map[string]os.FileInfo
}

func (h *w11aHostileRealPathHandler) RealPath(string) (string, error) {
	return h.realPath, nil
}

func (h *w11aHostileRealPathHandler) Lstat(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
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

func (h *w11aHostileRealPathHandler) handlers() pkgsftp.Handlers {
	return pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

// TestP7W11a_AB11M2_HTTPTransferRejectsHostileRealPathAndNegativeSizeBeforeAuthorize
// verifies AB11-M2 end-to-end through prepareTransfer:
//   - Hostile SFTP RealPath (containing newline/ESC/U+2028 or relative path) is
//     rejected during inspection BEFORE guardrail.Authorize or transfer journal save.
//   - Negative remote file size (Lstat info.Size() < 0) is rejected with
//     ErrInvalidRemoteSize BEFORE guardrail.Authorize or transfer journal save.
func TestP7W11a_AB11M2_HTTPTransferRejectsHostileRealPathAndNegativeSizeBeforeAuthorize(t *testing.T) {
	cases := []struct {
		name     string
		realPath string
		fileSize int64
	}{
		{name: "hostile_realpath_newline_prompt_spoof", realPath: "/tmp/safe\nPaths: /etc/shadow", fileSize: 16},
		{name: "hostile_realpath_osc_escape", realPath: "/tmp/\x1b]52;c;abc\x07dir", fileSize: 16},
		{name: "hostile_realpath_line_sep", realPath: "/tmp/dir\u2028fake", fileSize: 16},
		{name: "hostile_realpath_relative", realPath: "relative/dir", fileSize: 16},
		{name: "negative_remote_file_size", realPath: "/tmp", fileSize: -1},
		{name: "min_int64_remote_file_size", realPath: "/tmp", fileSize: math.MinInt64},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &w11aHostileRealPathHandler{
				w10aHostileSFTPHandler: newW10aHostileSFTPHandler(),
				realPath:               tc.realPath,
				lstats:                 make(map[string]os.FileInfo),
			}
			h.stats["/tmp"] = w10aSynthFileInfo{name: "tmp", mode: os.ModeDir | 0o755}
			h.stats[tc.realPath] = w10aSynthFileInfo{name: "dir", mode: os.ModeDir | 0o755}
			h.lstats["/tmp/data.bin"] = w10aSynthFileInfo{name: "data.bin", size: tc.fileSize, mode: 0o644}

			recorder := &w11aAuditRecorder{}
			r, _, client := startTransferRuntime(t, nil, h.handlers(), func(rt *Runtime) {
				rt.guardrail.SetAuditWriter(recorder)
			})

			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "transfer",
				Arguments: PrepareDownloadInput{
					Action:     "prepare_pull",
					RequestID:  "req-" + tc.name,
					NodeID:     "files",
					RemotePath: "/tmp/data.bin",
				},
			})
			if err == nil && !res.IsError {
				t.Fatalf("prepare_pull(%s) unexpectedly succeeded: %+v", tc.name, res)
			}
			if got := len(r.transfers.Records()); got != 0 {
				t.Fatalf("prepare_pull(%s) persisted %d transfer records, want 0", tc.name, got)
			}
			if entries := recorder.snapshot(); len(entries) != 0 {
				t.Fatalf("prepare_pull(%s) reached guardrail.Authorize (%d audit entries): %+v", tc.name, len(entries), entries)
			}
		})
	}

	t.Run("prepare_push_rejects_control_char_hidden_by_dotdot", func(t *testing.T) {
		r, _, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler())
		digest := sha256.Sum256([]byte("hi"))
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "transfer",
			Arguments: PrepareUploadInput{
				Action:     "prepare_push",
				RequestID:  "req-ctrl-dotdot",
				NodeID:     "files",
				RemotePath: "/tmp/bad\n/../good.bin",
				Size:       2,
				SHA256:     hex.EncodeToString(digest[:]),
			},
		})
		if err == nil && !res.IsError {
			t.Fatalf("prepare_push accepted control-tainted dotdot path: %+v", res)
		}
		if got := len(r.transfers.Records()); got != 0 {
			t.Fatalf("prepare_push persisted %d records, want 0", got)
		}
	})
}

type w11aCountingReadHandler struct {
	*w10aHostileSFTPHandler
	readCalls atomic.Int32
}

func (h *w11aCountingReadHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	h.readCalls.Add(1)
	return bytes.NewReader([]byte("secret-device-bytes")), nil
}

func newW11aReadClient(t *testing.T, h *w11aCountingReadHandler) (*pkgsftp.Client, *pipeFileSession) {
	t.Helper()
	cConn, sConn := net.Pipe()
	srv := pkgsftp.NewRequestServer(sConn, pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	})
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = sConn.Close()
	})
	client, err := pkgsftp.NewClientPipe(cConn, cConn)
	if err != nil {
		t.Fatalf("NewClientPipe: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = cConn.Close()
	})
	return client, &pipeFileSession{client: client}
}

// TestP7W11a_AB11L1_FileReadAndStatRejectNonRegularAndNegativeSize verifies AB11-L1:
//   - readBounded rejects non-regular files (FIFO, device, char device, socket)
//     and negative file sizes (wrapping sftp.ErrInvalidRemoteSize).
//   - fileStat rejects negative Size() < 0 on files and directories with
//     sftp.ErrInvalidRemoteSize.
//   - buildDirTree rejects negative Size() < 0 on direct and nested entries with
//     sftp.ErrInvalidRemoteSize without emitting partial output.
func TestP7W11a_AB11L1_FileReadAndStatRejectNonRegularAndNegativeSize(t *testing.T) {
	t.Run("readBounded_rejects_non_regular_files", func(t *testing.T) {
		specialModes := []struct {
			name string
			mode os.FileMode
		}{
			{"fifo", os.ModeNamedPipe | 0o600},
			{"block_device", os.ModeDevice | 0o600},
			{"char_device", os.ModeDevice | os.ModeCharDevice | 0o600},
			{"socket", os.ModeSocket | 0o600},
		}
		for _, tc := range specialModes {
			t.Run(tc.name, func(t *testing.T) {
				h := &w11aCountingReadHandler{w10aHostileSFTPHandler: newW10aHostileSFTPHandler()}
				h.stats["/dev/special"] = w10aSynthFileInfo{name: "special", size: 12, mode: tc.mode}
				_, session := newW11aReadClient(t, h)

				data, _, _, err := readBounded(t.Context(), session, "/dev/special")
				if err == nil || !strings.Contains(err.Error(), "not a regular file") {
					t.Fatalf("readBounded(%s) = (%q, %v), want non-regular error", tc.name, data, err)
				}
				if len(data) != 0 {
					t.Fatalf("readBounded(%s) returned %d bytes on non-regular file", tc.name, len(data))
				}

				if _, patchErr := filePatch(t.Context(), session, FileInput{
					Path:    "/dev/special",
					Content: "<<<<\na\n====\nb\n>>>>",
				}); patchErr == nil || !strings.Contains(patchErr.Error(), "not a regular file") {
					t.Fatalf("filePatch(%s) err = %v, want non-regular error", tc.name, patchErr)
				}
			})
		}
	})

	t.Run("readBounded_rejects_negative_size", func(t *testing.T) {
		for _, negSize := range []int64{-1, -4096, math.MinInt64} {
			h := &w11aCountingReadHandler{w10aHostileSFTPHandler: newW10aHostileSFTPHandler()}
			h.stats["/tmp/neg.txt"] = w10aSynthFileInfo{name: "neg.txt", size: negSize, mode: 0o644}
			_, session := newW11aReadClient(t, h)

			data, _, _, err := readBounded(t.Context(), session, "/tmp/neg.txt")
			if !errors.Is(err, sftp.ErrInvalidRemoteSize) {
				t.Fatalf("readBounded(size=%d) err = %v, want ErrInvalidRemoteSize", negSize, err)
			}
			if len(data) != 0 {
				t.Fatalf("readBounded(size=%d) returned %d bytes", negSize, len(data))
			}
		}
	})

	t.Run("fileStat_and_buildDirTree_reject_negative_size", func(t *testing.T) {
		// 1. Negative size on direct file stat.
		hFile := &w11aCountingReadHandler{w10aHostileSFTPHandler: newW10aHostileSFTPHandler()}
		hFile.stats["/tmp/neg.bin"] = w10aSynthFileInfo{name: "neg.bin", size: -5, mode: 0o644}
		_, sessionFile := newW11aReadClient(t, hFile)
		if _, err := fileStat(t.Context(), sessionFile, FileInput{Path: "/tmp/neg.bin"}); !errors.Is(err, sftp.ErrInvalidRemoteSize) {
			t.Fatalf("fileStat(file size=-5) err = %v, want ErrInvalidRemoteSize", err)
		}

		// 2. Negative size on root directory stat itself.
		hDirStat := &w11aCountingReadHandler{w10aHostileSFTPHandler: newW10aHostileSFTPHandler()}
		hDirStat.stats["/tmp/negdir"] = w10aSynthFileInfo{name: "negdir", size: -1, mode: os.ModeDir | 0o755}
		_, sessionDirStat := newW11aReadClient(t, hDirStat)
		if _, err := fileStat(t.Context(), sessionDirStat, FileInput{Path: "/tmp/negdir"}); !errors.Is(err, sftp.ErrInvalidRemoteSize) {
			t.Fatalf("fileStat(dir size=-1) err = %v, want ErrInvalidRemoteSize", err)
		}

		// 3. Negative size on directory entry inside buildDirTree and nested subdir.
		hTree := &w11aCountingReadHandler{w10aHostileSFTPHandler: newW10aHostileSFTPHandler()}
		hTree.stats["/root"] = w10aSynthFileInfo{name: "root", size: 4096, mode: os.ModeDir | 0o755}
		hTree.dirLists["/root"] = []os.FileInfo{
			w10aSynthFileInfo{name: "good.txt", size: 10, mode: 0o644},
			w10aSynthFileInfo{name: "poison.bin", size: -42, mode: 0o644},
		}
		clientTree, sessionTree := newW11aReadClient(t, hTree)
		var b strings.Builder
		count := 0
		if err := buildDirTree(clientTree, "/root", "", 1, &b, &count); !errors.Is(err, sftp.ErrInvalidRemoteSize) {
			t.Fatalf("buildDirTree(entry size=-42) err = %v, want ErrInvalidRemoteSize", err)
		}
		if b.Len() != 0 {
			t.Fatalf("buildDirTree emitted partial output on negative-size entry: %q", b.String())
		}
		if _, err := fileStat(t.Context(), sessionTree, FileInput{Path: "/root"}); !errors.Is(err, sftp.ErrInvalidRemoteSize) {
			t.Fatalf("fileStat(/root with negative child) err = %v, want ErrInvalidRemoteSize", err)
		}

		// 4. Negative size in nested depth-2 subdirectory propagates up.
		hTree.mu.Lock()
		hTree.dirLists["/root"] = []os.FileInfo{
			w10aSynthFileInfo{name: "sub", size: 4096, mode: os.ModeDir | 0o755},
		}
		hTree.dirLists["/root/sub"] = []os.FileInfo{
			w10aSynthFileInfo{name: "deep.bin", size: math.MinInt64, mode: 0o644},
		}
		hTree.mu.Unlock()
		if _, err := fileStat(t.Context(), sessionTree, FileInput{Path: "/root"}); !errors.Is(err, sftp.ErrInvalidRemoteSize) {
			t.Fatalf("fileStat(/root with negative nested child) err = %v, want ErrInvalidRemoteSize", err)
		}
	})
}
