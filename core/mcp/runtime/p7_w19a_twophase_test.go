package runtime

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	goruntime "runtime"
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
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/sftp"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
	"github.com/wentf9/xops-cli/core/testutil/mcphost/models"
)

func assertW19aNoOrphanedAuthorizedAudits(t *testing.T, entries []guardrail.AuditEntry) {
	t.Helper()
	authorized := make(map[string]guardrail.AuditEntry)
	terminal := make(map[string]bool)
	for _, e := range entries {
		switch e.Outcome {
		case "authorized":
			authorized[e.OperationID] = e
		case "executed", "error":
			terminal[e.OperationID] = true
		}
	}
	for opID, e := range authorized {
		if !terminal[opID] {
			t.Fatalf("orphaned Outcome='authorized' audit entry without terminal executed/error record: opID=%q entry=%+v all=%+v", opID, e, entries)
		}
	}
}

func countW19aAuthorizedAudits(entries []guardrail.AuditEntry) int {
	n := 0
	for _, e := range entries {
		if e.Outcome == "authorized" {
			n++
		}
	}
	return n
}

// w19aMultiNodeBackend wraps a real backend while counting OpenFiles / InspectPath
// per node and optionally injecting inspection failures.
type w19aMultiNodeBackend struct {
	ports.Backend
	mu           sync.Mutex
	openByNode   map[string]int
	failNextOpen error
	wrapFiles    func(nodeID string, fs ports.FileSession) ports.FileSession
}

func newW19aMultiNodeBackend(inner ports.Backend) *w19aMultiNodeBackend {
	return &w19aMultiNodeBackend{
		Backend:    inner,
		openByNode: make(map[string]int),
	}
}

func (b *w19aMultiNodeBackend) OpenFiles(ctx context.Context, p ports.Permit, nodeID string) (ports.FileSession, error) {
	b.mu.Lock()
	b.openByNode[nodeID]++
	failErr := b.failNextOpen
	b.failNextOpen = nil
	wrap := b.wrapFiles
	b.mu.Unlock()
	if failErr != nil {
		return nil, failErr
	}
	fs, err := b.Backend.OpenFiles(ctx, p, nodeID)
	if err != nil {
		return nil, err
	}
	if wrap != nil {
		return wrap(nodeID, fs), nil
	}
	return fs, nil
}

func (b *w19aMultiNodeBackend) RunTunnel(ctx context.Context, p ports.Permit, spec tunnel.Spec, ready func(string) bool, report func(error)) error {
	if tb, ok := b.Backend.(ports.TunnelBackend); ok {
		return tb.RunTunnel(ctx, p, spec, ready, report)
	}
	return errors.New("tunnel backend unsupported")
}

func (b *w19aMultiNodeBackend) totalOpens() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	total := 0
	for _, n := range b.openByNode {
		total += n
	}
	return total
}

func (b *w19aMultiNodeBackend) resetOpens() {
	b.mu.Lock()
	b.openByNode = make(map[string]int)
	b.mu.Unlock()
}

func startW19aMultiNodeRuntime(
	t *testing.T,
	guardCfg *policy.Config,
	handlers pkgsftp.Handlers,
	protocol string,
	elicitHandler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error),
	gateOverride ports.ExecutionGate,
) (*Runtime, *mcp.ServerSession, *mcp.ClientSession, *w19aMultiNodeBackend, *w11aAuditRecorder) {
	t.Helper()
	baseProvider := startTransferSSH(t, handlers)
	cfg := baseProvider.Snapshot()
	cfg.Nodes.Set("node-a", models.Node{HostRef: "host", IdentityRef: "identity"})
	cfg.Nodes.Set("restricted-b", models.Node{HostRef: "host", IdentityRef: "identity"})
	cfg.Guardrail = guardCfg
	provider := config.NewProviderWithoutOpenSSH(cfg)

	var spyBackend *w19aMultiNodeBackend
	gate := ports.ExecutionGate(provider)
	if gateOverride != nil {
		gate = gateOverride
	}
	deps := ports.Dependencies{
		State: provider,
		Gate:  gate,
		Audit: ports.NoopAudit{},
		NewBackend: func(ctx context.Context) (ports.Backend, error) {
			inner, err := provider.NewBackend(ctx)
			if err != nil {
				return nil, err
			}
			spyBackend = newW19aMultiNodeBackend(inner)
			return spyBackend, nil
		},
	}
	r, err := NewRuntime(t.Context(), WithDependencies(deps))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	recorder := &w11aAuditRecorder{}
	r.guardrail.SetAuditWriter(recorder)
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	var opts *mcp.ClientOptions
	if elicitHandler != nil {
		opts = &mcp.ClientOptions{ElicitationHandler: elicitHandler}
	}
	ss, cs := connectW17aInMemorySession(t, r, protocol, opts)
	return r, ss, cs, spyBackend, recorder
}

// TestP7W19a_AB19M1_SameSessionCrossEnvelopeReplayAndErrorOracleInvalidation verifies AB19-M1:
//   - A live Round-1 RequestState token from file(write, node-a, "/tmp/a.txt") or
//     tunnel(create) CANNOT be replayed on the same session against a different
//     node, tool, action, path, or content — it is rejected and audited "denied"
//     in authorizeLexicalPrecheck BEFORE any SSH/SFTP dial or local walk.
//   - If inspectRemotePath or inspectStdioTransferScope fails during Round 2,
//     the carried RequestState token is invalidated and audited "error" so it
//     cannot be replayed repeatedly as an SFTP error oracle.
func TestP7W19a_AB19M1_SameSessionCrossEnvelopeReplayAndErrorOracleInvalidation(t *testing.T) {
	t.Run("cross_node_tool_action_path_content_replay_rejected_before_ssh", testP7W19aCrossEnvelopeReplayPreSSH)
	t.Run("failed_round2_inspection_invalidates_token_against_error_oracle", testP7W19aFailedRound2InvalidatesToken)
}

func assertW19aFileReplayPreSSH(
	t *testing.T,
	r *Runtime,
	ss *mcp.ServerSession,
	h *w18aSymlinkSFTPHandler,
	backend *w19aMultiNodeBackend,
	audit *w11aAuditRecorder,
	token string,
	acceptMap mcp.InputResponseMap,
	input FileInput,
) {
	t.Helper()
	audit.reset()
	backend.resetOpens()
	h.inspections.Store(0)
	req := &mcp.CallToolRequest{
		Session: ss,
		Params:  &mcp.CallToolParamsRaw{RequestState: token, InputResponses: acceptMap},
	}
	if pending, _, err := r.fileHandler(t.Context(), req, input); err == nil || pending != nil {
		t.Fatalf("file replay accepted: pending=%+v err=%v", pending, err)
	}
	if backend.totalOpens() != 0 || h.inspections.Load() != 0 {
		t.Fatalf("file replay dialed SFTP before rejection: opens=%d inspections=%d", backend.totalOpens(), h.inspections.Load())
	}
	entries := audit.snapshot()
	if len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
		t.Fatalf("file replay missing denied audit: %+v", entries)
	}
	assertW19aNoOrphanedAuthorizedAudits(t, entries)
}

func assertW19aTransferReplayPreSSH(
	t *testing.T,
	r *Runtime,
	ss *mcp.ServerSession,
	h *w18aSymlinkSFTPHandler,
	backend *w19aMultiNodeBackend,
	audit *w11aAuditRecorder,
	token string,
	acceptMap mcp.InputResponseMap,
	input TransferFileInput,
) {
	t.Helper()
	audit.reset()
	backend.resetOpens()
	h.inspections.Store(0)
	req := &mcp.CallToolRequest{
		Session: ss,
		Params:  &mcp.CallToolParamsRaw{RequestState: token, InputResponses: acceptMap},
	}
	if pending, _, err := r.stdioTransferHandler(t.Context(), req, input); err == nil || pending != nil {
		t.Fatalf("transfer replay accepted: pending=%+v err=%v", pending, err)
	}
	if backend.totalOpens() != 0 || h.inspections.Load() != 0 {
		t.Fatalf("transfer replay dialed SFTP before rejection: opens=%d inspections=%d", backend.totalOpens(), h.inspections.Load())
	}
	entries := audit.snapshot()
	if len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
		t.Fatalf("transfer replay missing denied audit: %+v", entries)
	}
	assertW19aNoOrphanedAuthorizedAudits(t, entries)
}

func testP7W19aCrossEnvelopeReplayPreSSH(t *testing.T) {
	h := newW18aFileSymlinkFixture()
	r, ss, _, backend, audit := startW19aMultiNodeRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc"},
	}, h.handlers(), "2026-07-28", func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
	}, nil)

	origFile := FileInput{NodeID: "node-a", Action: "write", Path: "/tmp/a.txt", Content: "orig"}
	p1, _, err := r.fileHandler(t.Context(), &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, origFile)
	if err != nil || p1 == nil || p1.RequestState == "" {
		t.Fatalf("mint file Round-1 token: pending=%+v err=%v", p1, err)
	}

	p2, _, err := r.createTunnel(t.Context(), &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, CreateTunnelInput{
		Action:     "create",
		RequestID:  "w19a-tun-1",
		NodeID:     "node-a",
		Mode:       "local",
		ListenHost: "127.0.0.1",
		TargetHost: "127.0.0.1",
		TargetPort: 8080,
	})
	if err != nil || p2 == nil || p2.RequestState == "" {
		t.Fatalf("mint tunnel Round-1 token: pending=%+v err=%v", p2, err)
	}
	if backend.totalOpens() != 0 {
		t.Fatalf("Round-1 token minting opened SFTP %d times, want 0", backend.totalOpens())
	}

	acceptMap := mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}}
	localDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(localDir, "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileReplays := []struct {
		name  string
		input FileInput
	}{
		{"cross_node_and_path", FileInput{NodeID: "restricted-b", Action: "write", Path: "/etc/shadow", Content: "pwn"}},
		{"cross_node_safe_read", FileInput{NodeID: "restricted-b", Action: "read", Path: "/tmp/public.txt"}},
		{"cross_action", FileInput{NodeID: "node-a", Action: "read", Path: "/tmp/a.txt"}},
		{"cross_path", FileInput{NodeID: "node-a", Action: "write", Path: "/etc/shadow", Content: "orig"}},
		{"cross_content", FileInput{NodeID: "node-a", Action: "write", Path: "/tmp/a.txt", Content: "tampered"}},
	}

	for _, tok := range []struct{ label, state string }{{"file_token", p1.RequestState}, {"tunnel_token", p2.RequestState}} {
		for _, tc := range fileReplays {
			t.Run(tok.label+"/file/"+tc.name, func(t *testing.T) {
				assertW19aFileReplayPreSSH(t, r, ss, h, backend, audit, tok.state, acceptMap, tc.input)
			})
		}
		t.Run(tok.label+"/transfer/cross_tool_restricted_node", func(t *testing.T) {
			assertW19aTransferReplayPreSSH(t, r, ss, h, backend, audit, tok.state, acceptMap, TransferFileInput{
				NodeID:     "restricted-b",
				Direction:  "push",
				LocalPath:  localDir,
				RemotePath: "/etc/shadow",
			})
		})
	}
}

func testP7W19aFailedRound2InvalidatesToken(t *testing.T) {
	h := newW18aFileSymlinkFixture()
	r, ss, _, backend, audit := startW19aMultiNodeRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc"},
	}, h.handlers(), "2026-07-28", func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
	}, nil)
	acceptMap := mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}}

	t.Run("lexical_file_token", func(t *testing.T) {
		assertW19aFailedFileRound2Invalidates(t, r, ss, backend, audit, acceptMap,
			FileInput{NodeID: "node-a", Action: "write", Path: "/tmp/oracle.txt", Content: "data"}, "")
	})
	t.Run("canonical_file_token", func(t *testing.T) {
		assertW19aFailedFileRound2Invalidates(t, r, ss, backend, audit, acceptMap,
			FileInput{NodeID: "node-a", Action: "read", Path: "/tmp/shadow_link"}, "/etc/shadow")
	})
	t.Run("stdio_transfer_token", func(t *testing.T) {
		assertW19aFailedTransferRound2Invalidates(t, r, ss, backend, audit, acceptMap)
	})
}

func assertW19aFailedFileRound2Invalidates(
	t *testing.T,
	r *Runtime,
	ss *mcp.ServerSession,
	backend *w19aMultiNodeBackend,
	audit *w11aAuditRecorder,
	acceptMap mcp.InputResponseMap,
	in FileInput,
	wantAuditPath string,
) {
	t.Helper()
	pending, _, err := r.fileHandler(t.Context(), &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, in)
	if err != nil || pending == nil || pending.RequestState == "" {
		t.Fatalf("mint token: pending=%+v err=%v", pending, err)
	}
	audit.reset()
	backend.mu.Lock()
	backend.failNextOpen = errors.New("simulated SFTP inspection outage")
	backend.mu.Unlock()
	round2Req := &mcp.CallToolRequest{
		Session: ss,
		Params:  &mcp.CallToolParamsRaw{RequestState: pending.RequestState, InputResponses: acceptMap},
	}
	if _, _, err := r.fileHandler(t.Context(), round2Req, in); err == nil {
		t.Fatal("Round 2 unexpectedly succeeded despite SFTP inspection error")
	}
	entries := audit.snapshot()
	if len(entries) == 0 || entries[len(entries)-1].Outcome != "error" {
		t.Fatalf("failed Round 2 audit = %+v, want terminal error entry", entries)
	}
	if wantAuditPath != "" && !slices.Contains(entries[len(entries)-1].Paths, wantAuditPath) {
		t.Fatalf("failed Round 2 audit missing %q: %+v", wantAuditPath, entries)
	}
	assertW19aNoOrphanedAuthorizedAudits(t, entries)

	audit.reset()
	backend.resetOpens()
	if _, _, err := r.fileHandler(t.Context(), round2Req, in); err == nil {
		t.Fatal("replayed invalidated token succeeded")
	}
	if backend.totalOpens() != 0 {
		t.Fatalf("replayed invalidated token dialed SFTP %d times, want 0", backend.totalOpens())
	}
	entries = audit.snapshot()
	if len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
		t.Fatalf("replayed invalidated token audit = %+v, want denied", entries)
	}
}

func assertW19aFailedTransferRound2Invalidates(
	t *testing.T,
	r *Runtime,
	ss *mcp.ServerSession,
	backend *w19aMultiNodeBackend,
	audit *w11aAuditRecorder,
	acceptMap mcp.InputResponseMap,
) {
	t.Helper()
	localFile := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(localFile, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	trIn := TransferFileInput{NodeID: "node-a", Direction: "push", LocalPath: localFile, RemotePath: "/tmp/tr_oracle.txt"}
	pTr, _, err := r.stdioTransferHandler(t.Context(), &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, trIn)
	if err != nil || pTr == nil || pTr.RequestState == "" {
		t.Fatalf("mint transfer token: pending=%+v err=%v", pTr, err)
	}
	audit.reset()
	backend.mu.Lock()
	backend.failNextOpen = errors.New("simulated transfer inspection failure")
	backend.mu.Unlock()
	trReq := &mcp.CallToolRequest{
		Session: ss,
		Params:  &mcp.CallToolParamsRaw{RequestState: pTr.RequestState, InputResponses: acceptMap},
	}
	if _, _, err := r.stdioTransferHandler(t.Context(), trReq, trIn); err == nil {
		t.Fatal("transfer Round 2 unexpectedly succeeded despite inspection error")
	}
	assertW19aNoOrphanedAuthorizedAudits(t, audit.snapshot())

	audit.reset()
	backend.resetOpens()
	if _, _, err := r.stdioTransferHandler(t.Context(), trReq, trIn); err == nil {
		t.Fatal("replayed invalidated transfer token succeeded")
	}
	if backend.totalOpens() != 0 {
		t.Fatalf("replayed invalidated transfer token dialed SFTP %d times, want 0", backend.totalOpens())
	}
}

// w19aSpyFileSession wraps a real ports.FileSession to record Upload/UploadExact/Download
// arguments and inject concurrent races right before transfer I/O.
type w19aSpyFileSession struct {
	ports.FileSession
	mu               sync.Mutex
	uploadCalls      int
	uploadExactCalls int
	lastUploadLocal  string
	lastUploadRemote string
	downloadCalls    int
	lastDownRemote   sftp.RemotePath
	lastDownDest     sftp.LocalDest
	beforeUpload     func()
	beforeDownload   func()
}

func (s *w19aSpyFileSession) Upload(ctx context.Context, local, remote string, progress sftp.ProgressCallback) error {
	s.mu.Lock()
	s.uploadCalls++
	s.mu.Unlock()
	return s.FileSession.Upload(ctx, local, remote, progress)
}

func (s *w19aSpyFileSession) UploadExact(ctx context.Context, local, remote string, progress sftp.ProgressCallback) error {
	s.mu.Lock()
	s.uploadExactCalls++
	s.lastUploadLocal = local
	s.lastUploadRemote = remote
	hook := s.beforeUpload
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	return s.FileSession.UploadExact(ctx, local, remote, progress)
}

func (s *w19aSpyFileSession) Download(ctx context.Context, remote sftp.RemotePath, dest sftp.LocalDest, opts sftp.DownloadOptions) error {
	s.mu.Lock()
	s.downloadCalls++
	s.lastDownRemote = remote
	s.lastDownDest = dest
	hook := s.beforeDownload
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	return s.FileSession.Download(ctx, remote, dest, opts)
}

// TestP7W19a_AB19M2_StdioTransferPinnedSourceAndExactDestinations verifies AB19-M2:
//   - Push into an existing remote directory pins localSrc to canonicalPath (immune
//     to post-check local symlink retargeting) and calls UploadExact with the
//     explicitly expanded remote destination.
//   - Pull into an existing local directory pins remoteSrc to CanonicalPath (immune
//     to post-check remote symlink retargeting) and calls Download with
//     LocalDestExact constructed via LocalDestFromTarget.
//   - Push/pull targeting a non-dir destination fail closed if a directory is
//     concurrently created at the destination before transfer I/O begins.
func TestP7W19a_AB19M2_StdioTransferPinnedSourceAndExactDestinations(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("POSIX symlink test fixture")
	}
	t.Run("push_into_remote_dir_pins_canonical_local_source_and_uses_upload_exact", testP7W19aPushDirPinnedUploadExact)
	t.Run("pull_into_local_dir_pins_canonical_remote_source_and_uses_exact_local_dest", testP7W19aPullDirPinnedLocalDestExact)
	t.Run("non_dir_push_and_pull_fail_closed_on_concurrent_dir_flip", testP7W19aNonDirConcurrentDirFlipFailsClosed)
}

func testP7W19aPushDirPinnedUploadExact(t *testing.T) {
	localRoot := t.TempDir()
	harmless := filepath.Join(localRoot, "harmless.txt")
	secret := filepath.Join(localRoot, "secret.key")
	if err := os.WriteFile(harmless, []byte("harmless-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("TOP-SECRET-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	localLink := filepath.Join(localRoot, "local_link.txt")
	if err := os.Symlink(harmless, localLink); err != nil {
		t.Fatal(err)
	}
	canonHarmless, err := filepath.EvalSymlinks(harmless)
	if err != nil {
		t.Fatal(err)
	}

	h := newW18aSymlinkSFTPHandler()
	h.setDir("/var/uploads")
	h.setSymlink("/tmp/up_dir", "/var/uploads")

	_, _, client, backend, _ := startW19aMultiNodeRuntime(t, &policy.Config{Disabled: true}, h.handlers(), "2026-07-28", nil, nil)

	var spy *w19aSpyFileSession
	backend.wrapFiles = func(_ string, fs ports.FileSession) ports.FileSession {
		s := &w19aSpyFileSession{
			FileSession: fs,
			beforeUpload: func() {
				// Retarget local_link to secret.key AFTER executeStdioTransfer's canonicalizeLocalPath!
				_ = os.Remove(localLink)
				_ = os.Symlink(secret, localLink)
			},
		}
		spy = s
		return s
	}

	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "node-a",
			Direction:  "push",
			LocalPath:  localLink,
			RemotePath: "/tmp/up_dir",
		},
	})
	if err != nil || res.IsError {
		t.Fatalf("push into remote dir failed: res=%+v err=%v", res, err)
	}
	if spy == nil || spy.uploadCalls != 0 || spy.uploadExactCalls != 1 {
		t.Fatalf("spy calls: upload=%d uploadExact=%d, want 0 and 1", spy.uploadCalls, spy.uploadExactCalls)
	}
	if spy.lastUploadLocal != canonHarmless {
		t.Fatalf("UploadExact localSrc = %q, want pinned canonical %q", spy.lastUploadLocal, canonHarmless)
	}
	if spy.lastUploadRemote != "/var/uploads/local_link.txt" {
		t.Fatalf("UploadExact remoteDst = %q, want /var/uploads/local_link.txt", spy.lastUploadRemote)
	}
	h.mu.Lock()
	got := string(h.files["/var/uploads/local_link.txt"])
	h.mu.Unlock()
	if got != "harmless-payload" {
		t.Fatalf("uploaded remote content = %q, want harmless-payload (local symlink race leaked secret!)", got)
	}
}

func testP7W19aPullDirPinnedLocalDestExact(t *testing.T) {
	localRoot := t.TempDir()
	realOutDir := filepath.Join(localRoot, "real_out")
	if err := os.MkdirAll(realOutDir, 0o700); err != nil {
		t.Fatal(err)
	}
	localDirLink := filepath.Join(localRoot, "out_link")
	if err := os.Symlink(realOutDir, localDirLink); err != nil {
		t.Fatal(err)
	}
	canonOutDir, err := filepath.EvalSymlinks(realOutDir)
	if err != nil {
		t.Fatal(err)
	}

	h := newW18aSymlinkSFTPHandler()
	h.setFile("/tmp/real_harmless.txt", []byte("safe-remote-bytes"))
	h.setFile("/etc/shadow", []byte("ROOT-SHADOW-SECRET"))
	h.setSymlink("/tmp/remote_link.txt", "/tmp/real_harmless.txt")

	_, _, client, backend, _ := startW19aMultiNodeRuntime(t, &policy.Config{Disabled: true}, h.handlers(), "2026-07-28", nil, nil)

	var spy *w19aSpyFileSession
	backend.wrapFiles = func(_ string, fs ports.FileSession) ports.FileSession {
		s := &w19aSpyFileSession{
			FileSession: fs,
			beforeDownload: func() {
				// Retarget remote symlink to /etc/shadow right before Download runs!
				h.setSymlink("/tmp/remote_link.txt", "/etc/shadow")
			},
		}
		spy = s
		return s
	}

	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "node-a",
			Direction:  "pull",
			LocalPath:  localDirLink,
			RemotePath: "/tmp/remote_link.txt",
		},
	})
	if err != nil || res.IsError {
		t.Fatalf("pull into local dir failed: res=%+v err=%v", res, err)
	}
	if spy == nil || spy.downloadCalls != 1 {
		t.Fatalf("downloadCalls = %d, want 1", spy.downloadCalls)
	}
	if spy.lastDownRemote.String() != "/tmp/real_harmless.txt" {
		t.Fatalf("Download remote = %q, want pinned /tmp/real_harmless.txt", spy.lastDownRemote.String())
	}
	if spy.lastDownDest.Mode() != sftp.LocalDestExact {
		t.Fatalf("Download LocalDest.Mode = %v, want LocalDestExact", spy.lastDownDest.Mode())
	}
	wantLocal := filepath.Join(canonOutDir, "remote_link.txt")
	if spy.lastDownDest.Path() != wantLocal {
		t.Fatalf("Download LocalDest.Path = %q, want %q", spy.lastDownDest.Path(), wantLocal)
	}
	got, err := os.ReadFile(wantLocal)
	if err != nil || string(got) != "safe-remote-bytes" {
		t.Fatalf("downloaded content = (%q, %v), want safe-remote-bytes", got, err)
	}
}

func testP7W19aNonDirConcurrentDirFlipFailsClosed(t *testing.T) {
	// 1. Push to non-existent remote file path; concurrently create remote directory at that path before UploadExact.
	localRoot := t.TempDir()
	srcFile := filepath.Join(localRoot, "app.bin")
	if err := os.WriteFile(srcFile, []byte("bin-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newW18aSymlinkSFTPHandler()
	h.setDir("/tmp/work")
	h.setFile("/tmp/work/src_remote.txt", []byte("remote-data"))

	_, _, client, backend, _ := startW19aMultiNodeRuntime(t, &policy.Config{Disabled: true}, h.handlers(), "2026-07-28", nil, nil)
	backend.wrapFiles = func(_ string, fs ports.FileSession) ports.FileSession {
		return &w19aSpyFileSession{
			FileSession: fs,
			beforeUpload: func() {
				h.setDir("/tmp/work/target")
			},
		}
	}
	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "node-a",
			Direction:  "push",
			LocalPath:  srcFile,
			RemotePath: "/tmp/work/target",
		},
	})
	if err != nil || !res.IsError {
		t.Fatalf("push over concurrently created remote dir succeeded: res=%+v err=%v", res, err)
	}
	h.mu.Lock()
	_, nested := h.files["/tmp/work/target/app.bin"]
	h.mu.Unlock()
	if nested {
		t.Fatal("UploadExact expanded into /tmp/work/target/app.bin instead of failing closed")
	}

	// 2. Pull to non-existent local file path; concurrently create local directory at that path before Download.
	localTarget := filepath.Join(localRoot, "pull_target")
	backend.wrapFiles = func(_ string, fs ports.FileSession) ports.FileSession {
		return &w19aSpyFileSession{
			FileSession: fs,
			beforeDownload: func() {
				_ = os.MkdirAll(localTarget, 0o700)
			},
		}
	}
	res2, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "node-a",
			Direction:  "pull",
			LocalPath:  localTarget,
			RemotePath: "/tmp/work/src_remote.txt",
		},
	})
	if err != nil || !res2.IsError {
		t.Fatalf("pull over concurrently created local dir succeeded: res=%+v err=%v", res2, err)
	}
	if _, statErr := os.Stat(filepath.Join(localTarget, "src_remote.txt")); statErr == nil {
		t.Fatal("Download with LocalDestExact expanded into pull_target/src_remote.txt instead of failing closed")
	}
}

type w19aFailExecuteGate struct {
	ports.ExecutionGate
	failExecute atomic.Bool
}

func (g *w19aFailExecuteGate) Enter(ctx context.Context, a ports.Admission) (ports.Permit, error) {
	if a.Phase == ports.Execute && g.failExecute.Load() {
		return nil, errors.New("simulated execution gate rejection")
	}
	return g.ExecutionGate.Enter(ctx, a)
}

// TestP7W19a_AB19L1_SinglePromptAndZeroOrphanedAuthorizedAudits verifies AB19-L1:
//   - Structural input validation (invalid action/direction/range/empty patch) runs
//     before lexical precheck with 0 prompts, 0 audits, and 0 SFTP calls.
//   - Benign canonicalization (/tmp -> /private/tmp) and container expansion
//     (push -> /tmp dir) require ONLY ONE approval prompt and leave ZERO orphaned
//     "authorized" audit entries across both 2026-07-28 and 2025-11-25 protocols.
//   - Risk/protected-path escalation (/tmp/sneaky_dir -> /etc) explicitly prompts
//     with the canonical protected target while leaving ZERO orphaned "authorized"
//     audit entries (both when declined and when accepted).
//   - Failures in r.enter (Execute gate) or pre-inspection after synchronous preAuth
//     always emit a terminal "error" audit record on the active opID.
func TestP7W19a_AB19L1_SinglePromptAndZeroOrphanedAuthorizedAudits(t *testing.T) {
	t.Run("structural_validation_fails_before_precheck_without_prompts_or_audit", testP7W19aStructuralValidationBeforePrecheck)
	t.Run("benign_canonical_and_dir_expansion_single_prompt_and_single_op", testP7W19aSinglePromptBenignCanonicalAndDirExpansion)
	t.Run("canonical_escalation_prompts_protected_target_with_zero_orphans", testP7W19aEscalationZeroOrphans)
	t.Run("enter_and_preauth_inspect_failures_record_terminal_error_audit", testP7W19aEnterAndInspectFailuresCloseAudit)
}

func testP7W19aStructuralValidationBeforePrecheck(t *testing.T) {
	h := newW18aFileSymlinkFixture()
	var prompts atomic.Int32
	_, _, client, backend, audit := startW19aMultiNodeRuntime(t, &policy.Config{
		ApprovalThreshold: "safe",
		NoElicitFallback:  guardrail.FallbackDeny,
	}, h.handlers(), "2026-07-28", func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		prompts.Add(1)
		return &mcp.ElicitResult{Action: "decline"}, nil
	}, nil)

	calls := []*mcp.CallToolParams{
		{Name: "file", Arguments: FileInput{NodeID: "node-a", Action: "patch", Path: "/tmp/a.txt", Content: ""}},
		{Name: "file", Arguments: FileInput{NodeID: "node-a", Action: "read", Path: "/tmp/a.txt", Range: []int{5, 1}}},
		{Name: "file", Arguments: FileInput{NodeID: "node-a", Action: "read", Path: "/tmp/a.txt", Range: []int{1}}},
		{Name: "file", Arguments: FileInput{NodeID: "node-a", Action: "delete", Path: "/tmp/a.txt"}},
		{Name: "transfer", Arguments: TransferFileInput{NodeID: "node-a", Direction: "sync", LocalPath: "/tmp/a", RemotePath: "/tmp/b"}},
	}
	for _, params := range calls {
		res, err := client.CallTool(t.Context(), params)
		if err != nil || !res.IsError {
			t.Fatalf("invalid structural call %+v succeeded: res=%+v err=%v", params, res, err)
		}
	}
	if prompts.Load() != 0 {
		t.Fatalf("structural validation triggered %d prompts, want 0", prompts.Load())
	}
	if got := len(audit.snapshot()); got != 0 {
		t.Fatalf("structural validation wrote %d audit entries, want 0: %+v", got, audit.snapshot())
	}
	if backend.totalOpens() != 0 {
		t.Fatalf("structural validation opened SFTP %d times, want 0", backend.totalOpens())
	}
}

func testP7W19aSinglePromptBenignCanonicalAndDirExpansion(t *testing.T) {
	for _, protocol := range []string{"2026-07-28", "2025-11-25"} {
		t.Run(protocol, func(t *testing.T) {
			h := newW18aSymlinkSFTPHandler()
			h.setDir("/private/tmp")
			h.setDir("/var/drop")
			h.setSymlink("/tmp", "/private/tmp")

			var prompts atomic.Int32
			_, _, client, _, audit := startW19aMultiNodeRuntime(t, &policy.Config{
				ApprovalThreshold: "moderate",
				NoElicitFallback:  guardrail.FallbackDeny,
				ProtectedPaths:    []string{"/etc"},
			}, h.handlers(), protocol, func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				prompts.Add(1)
				return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
			}, nil)

			// 1. file(write, /tmp/a.txt) where /tmp -> /private/tmp (macOS-style benign symlink).
			audit.reset()
			prompts.Store(0)
			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "file",
				Arguments: FileInput{NodeID: "node-a", Action: "write", Path: "/tmp/a.txt", Content: "ok\n"},
			})
			if err != nil || res.IsError {
				t.Fatalf("file write failed: res=%+v err=%v", res, err)
			}
			if prompts.Load() != 1 {
				t.Fatalf("file write prompted %d times, want 1", prompts.Load())
			}
			entries := audit.snapshot()
			if got := countW19aAuthorizedAudits(entries); got != 1 {
				t.Fatalf("file write authorized audit count = %d, want 1: %+v", got, entries)
			}
			assertW19aNoOrphanedAuthorizedAudits(t, entries)
			if !slices.ContainsFunc(entries, func(e guardrail.AuditEntry) bool {
				return e.Outcome == "executed" && slices.Contains(e.Paths, "/private/tmp/a.txt")
			}) {
				t.Fatalf("file write audit missing canonical /private/tmp/a.txt: %+v", entries)
			}

			// 2. transfer(push, localFile, /var/drop) where /var/drop is an existing dir expanding to /var/drop/upload.txt.
			localFile := filepath.Join(t.TempDir(), "upload.txt")
			if err := os.WriteFile(localFile, []byte("pushed-ok"), 0o600); err != nil {
				t.Fatal(err)
			}
			audit.reset()
			prompts.Store(0)
			res2, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name: "transfer",
				Arguments: TransferFileInput{
					NodeID:     "node-a",
					Direction:  "push",
					LocalPath:  localFile,
					RemotePath: "/var/drop",
				},
			})
			if err != nil || res2.IsError {
				t.Fatalf("transfer push into dir failed: res=%+v err=%v", res2, err)
			}
			if prompts.Load() != 1 {
				t.Fatalf("transfer push prompted %d times, want 1", prompts.Load())
			}
			entries2 := audit.snapshot()
			if got := countW19aAuthorizedAudits(entries2); got != 1 {
				t.Fatalf("transfer push authorized audit count = %d, want 1: %+v", got, entries2)
			}
			assertW19aNoOrphanedAuthorizedAudits(t, entries2)
			if !slices.ContainsFunc(entries2, func(e guardrail.AuditEntry) bool {
				return e.Outcome == "executed" && slices.Contains(e.Paths, path.Join("/var/drop", "upload.txt"))
			}) {
				t.Fatalf("transfer push audit missing expanded /var/drop/upload.txt: %+v", entries2)
			}
		})
	}
}

func testP7W19aEscalationZeroOrphans(t *testing.T) {
	for _, protocol := range []string{"2026-07-28", "2025-11-25"} {
		for _, acceptCanonical := range []bool{false, true} {
			name := protocol + "/decline_canonical"
			if acceptCanonical {
				name = protocol + "/accept_canonical"
			}
			t.Run(name, func(t *testing.T) {
				h := newW18aSymlinkSFTPHandler()
				h.setDir("/etc")
				h.setSymlink("/tmp/sneaky_dir", "/etc")

				var mu sync.Mutex
				var messages []string
				_, _, client, _, audit := startW19aMultiNodeRuntime(t, &policy.Config{
					ApprovalThreshold: "moderate",
					NoElicitFallback:  guardrail.FallbackDeny,
					ProtectedPaths:    []string{"/etc"},
				}, h.handlers(), protocol, func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
					mu.Lock()
					messages = append(messages, req.Params.Message)
					mu.Unlock()
					if strings.Contains(req.Params.Message, "/etc/a.txt") && !acceptCanonical {
						return &mcp.ElicitResult{Action: "decline"}, nil
					}
					return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
				}, nil)

				res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
					Name:      "file",
					Arguments: FileInput{NodeID: "node-a", Action: "write", Path: "/tmp/sneaky_dir/a.txt", Content: "cfg=1\n"},
				})
				if err != nil {
					t.Fatalf("CallTool transport error: %v", err)
				}
				if res.IsError == acceptCanonical {
					t.Fatalf("acceptCanonical=%v IsError=%v content=%+v", acceptCanonical, res.IsError, res.Content)
				}
				mu.Lock()
				gotMsgs := slices.Clone(messages)
				mu.Unlock()
				if len(gotMsgs) != 2 || !strings.Contains(gotMsgs[1], "/etc/a.txt") {
					t.Fatalf("prompts = %v, want 2 prompts with /etc/a.txt in second", gotMsgs)
				}
				entries := audit.snapshot()
				assertW19aNoOrphanedAuthorizedAudits(t, entries)
				if protocol == "2026-07-28" {
					wantAuth := 0
					if acceptCanonical {
						wantAuth = 1
					}
					if got := countW19aAuthorizedAudits(entries); got != wantAuth {
						t.Fatalf("2026-07-28 escalation authorized count = %d, want %d: %+v", got, wantAuth, entries)
					}
				}
				if !acceptCanonical && h.writes.Load() != 0 {
					t.Fatalf("declined escalation wrote %d times", h.writes.Load())
				}
			})
		}
	}
}

func testP7W19aEnterAndInspectFailuresCloseAudit(t *testing.T) {
	h := newW18aFileSymlinkFixture()
	baseProvider := startTransferSSH(t, h.handlers())
	cfg := baseProvider.Snapshot()
	cfg.Nodes.Set("node-a", models.Node{HostRef: "host", IdentityRef: "identity"})
	cfg.Guardrail = &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc"},
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)
	gate := &w19aFailExecuteGate{ExecutionGate: provider}

	var spyBackend *w19aMultiNodeBackend
	r, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{
		State: provider,
		Gate:  gate,
		Audit: ports.NoopAudit{},
		NewBackend: func(ctx context.Context) (ports.Backend, error) {
			inner, err := provider.NewBackend(ctx)
			if err != nil {
				return nil, err
			}
			spyBackend = newW19aMultiNodeBackend(inner)
			return spyBackend, nil
		},
	}))
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	audit := &w11aAuditRecorder{}
	r.guardrail.SetAuditWriter(audit)
	t.Cleanup(func() { _ = r.Close() })

	acceptOpts := &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
		},
	}
	_, client2026 := connectW17aInMemorySession(t, r, "2026-07-28", acceptOpts)
	_, client2025 := connectW17aInMemorySession(t, r, "2025-11-25", acceptOpts)

	// 1. Execute gate (r.enter) failure closes authorized opID with terminal "error" for both file and transfer.
	gate.failExecute.Store(true)
	audit.reset()
	res, err := client2026.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "file",
		Arguments: FileInput{NodeID: "node-a", Action: "write", Path: "/tmp/gate_fail.txt", Content: "x"},
	})
	if err != nil || !res.IsError {
		t.Fatalf("file write with failing execute gate succeeded: res=%+v err=%v", res, err)
	}
	entries := audit.snapshot()
	if countW19aAuthorizedAudits(entries) != 1 {
		t.Fatalf("file gate fail authorized count = %d, want 1: %+v", countW19aAuthorizedAudits(entries), entries)
	}
	assertW19aNoOrphanedAuthorizedAudits(t, entries)

	localFile := filepath.Join(t.TempDir(), "gate_fail.bin")
	if err := os.WriteFile(localFile, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	audit.reset()
	res2, err := client2026.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "node-a",
			Direction:  "push",
			LocalPath:  localFile,
			RemotePath: "/tmp/gate_fail_tr.bin",
		},
	})
	if err != nil || !res2.IsError {
		t.Fatalf("transfer push with failing execute gate succeeded: res=%+v err=%v", res2, err)
	}
	entries2 := audit.snapshot()
	if countW19aAuthorizedAudits(entries2) != 1 {
		t.Fatalf("transfer gate fail authorized count = %d, want 1: %+v", countW19aAuthorizedAudits(entries2), entries2)
	}
	assertW19aNoOrphanedAuthorizedAudits(t, entries2)

	// 2. 2025-11-25 synchronous preAuth followed by inspectRemotePath failure closes preAuth.opID with "error".
	gate.failExecute.Store(false)
	audit.reset()
	spyBackend.mu.Lock()
	spyBackend.failNextOpen = errors.New("simulated 2025 inspect failure")
	spyBackend.mu.Unlock()
	res3, err := client2025.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "file",
		Arguments: FileInput{NodeID: "node-a", Action: "write", Path: "/tmp/inspect_fail_2025.txt", Content: "z"},
	})
	if err != nil || !res3.IsError {
		t.Fatalf("2025 file write with failing inspect succeeded: res=%+v err=%v", res3, err)
	}
	entries3 := audit.snapshot()
	if countW19aAuthorizedAudits(entries3) != 1 {
		t.Fatalf("2025 inspect fail authorized count = %d, want 1: %+v", countW19aAuthorizedAudits(entries3), entries3)
	}
	assertW19aNoOrphanedAuthorizedAudits(t, entries3)
}
