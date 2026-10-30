package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/session"
	"github.com/wentf9/xops-cli/core/ssh"
)

type stubResultBackend struct {
	ports.Backend
	runResult ports.CommandResult
}

func (b *stubResultBackend) ProbeExecution(context.Context, ports.Permit, string) (*ssh.ProbeResult, error) {
	return &ssh.ProbeResult{
		DetectedDialect: ssh.LaunchPOSIX,
		SuggestedConfig: ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterBash,
			LaunchDialect: ssh.LaunchPOSIX,
		},
	}, nil
}

func (b *stubResultBackend) Run(context.Context, ports.Permit, string, ports.Command) (ports.CommandResult, error) {
	return b.runResult, nil
}
func (b *stubResultBackend) OpenFiles(context.Context, ports.Permit, string) (ports.FileSession, error) {
	return nil, fmt.Errorf("sftp not configured in stub")
}
func (b *stubResultBackend) Shutdown(context.Context) error { return nil }

func startStubResultRuntime(t *testing.T, backend *stubResultBackend) *mcp.ClientSession {
	t.Helper()
	provider := runtimeTestProvider("node")
	deps := ports.Dependencies{
		State:      provider,
		Gate:       executionRiskGate{provider.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(deps))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return connectRuntimeTestClient(t, r)
}

func startStdioSFTPRuntime(t *testing.T, handlers pkgsftp.Handlers) *mcp.ClientSession {
	t.Helper()
	provider := startTransferSSH(t, handlers)
	r, err := NewRuntime(t.Context(), WithConfigProvider(provider))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	ct, st := mcp.NewInMemoryTransports()
	ss, err := r.server.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test-stdio-client", Version: "1.0.0"}, nil)
	cs, err := client.Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestFileToolReadWritePatchStat(t *testing.T) {
	client := startStdioSFTPRuntime(t, pkgsftp.InMemHandler())

	// 1. Write file (with automatic parent directory creation) + valid JSON.
	writeRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "file",
		Arguments: FileInput{
			NodeID:  "files",
			Action:  "write",
			Path:    "/workspace/src/app.py",
			Content: "def greet():\n    return \"hello\"\n\ndef add(a, b):\n    return a + b\n",
		},
	})
	if err != nil || writeRes.IsError {
		t.Fatalf("file write failed: err=%v res=%+v", err, writeRes)
	}

	// 2. Patch file using <<<< ==== >>>> search/replace block.
	patchRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "file",
		Arguments: FileInput{
			NodeID: "files",
			Action: "patch",
			Path:   "/workspace/src/app.py",
			Content: `<<<<
def greet():
    return "hello"
====
def greet():
    return "hello world"
>>>>`,
		},
	})
	if err != nil || patchRes.IsError {
		t.Fatalf("file patch failed: err=%v res=%+v", err, patchRes)
	}

	// 3. Read file with line numbers and range.
	readRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "file",
		Arguments: FileInput{
			NodeID: "files",
			Action: "read",
			Path:   "/workspace/src/app.py",
			Range:  []int{1, 2},
		},
	})
	if err != nil || readRes.IsError {
		t.Fatalf("file read failed: err=%v res=%+v", err, readRes)
	}
	var readOut FileOutput
	rawRead, _ := json.Marshal(readRes.StructuredContent)
	if err := json.Unmarshal(rawRead, &readOut); err != nil {
		t.Fatalf("unmarshal read output: %v", err)
	}
	if !strings.Contains(readOut.Content, "1 | def greet():") || !strings.Contains(readOut.Content, "2 |     return \"hello world\"") {
		t.Fatalf("unexpected read content:\n%s", readOut.Content)
	}
	if readOut.TotalLines != 5 {
		t.Fatalf("expected 5 total lines, got %d", readOut.TotalLines)
	}

	// 4. Write a noise directory (.git) and verify stat tree filters it out.
	_, _ = client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "file",
		Arguments: FileInput{
			NodeID:  "files",
			Action:  "write",
			Path:    "/workspace/.git/config",
			Content: "[core]",
		},
	})
	statRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "file",
		Arguments: FileInput{
			NodeID: "files",
			Action: "stat",
			Path:   "/workspace",
		},
	})
	if err != nil || statRes.IsError {
		t.Fatalf("file stat failed: err=%v res=%+v", err, statRes)
	}
	var statOut FileOutput
	rawStat, _ := json.Marshal(statRes.StructuredContent)
	_ = json.Unmarshal(rawStat, &statOut)
	if !statOut.IsDir || !strings.Contains(statOut.Content, "src/") || !strings.Contains(statOut.Content, "app.py") {
		t.Fatalf("expected directory tree with src/app.py, got:\n%s", statOut.Content)
	}
	if strings.Contains(statOut.Content, ".git") {
		t.Fatalf("expected .git to be filtered from stat tree, got:\n%s", statOut.Content)
	}

	// 5. Write invalid JSON and verify LintWarning is populated.
	badJSONRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "file",
		Arguments: FileInput{
			NodeID:  "files",
			Action:  "write",
			Path:    "/workspace/broken.json",
			Content: "{bad json",
		},
	})
	if err != nil || badJSONRes.IsError {
		t.Fatalf("file write broken.json failed: err=%v res=%+v", err, badJSONRes)
	}
	var badJSONOut FileOutput
	rawBad, _ := json.Marshal(badJSONRes.StructuredContent)
	_ = json.Unmarshal(rawBad, &badJSONOut)
	if !strings.Contains(badJSONOut.LintWarning, "Warning: Syntax error") {
		t.Fatalf("expected lint warning for invalid JSON, got %q", badJSONOut.LintWarning)
	}
}

func TestStdioTransferPushAndPull(t *testing.T) {
	client := startStdioSFTPRuntime(t, pkgsftp.InMemHandler())
	localDir := t.TempDir()
	srcFile := filepath.Join(localDir, "hello.txt")
	if err := os.WriteFile(srcFile, []byte("push-and-pull-payload"), 0600); err != nil {
		t.Fatal(err)
	}

	pushRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "files",
			Direction:  "push",
			LocalPath:  srcFile,
			RemotePath: "/pushed.txt",
		},
	})
	if err != nil || pushRes.IsError {
		t.Fatalf("stdio transfer push failed: err=%v res=%+v", err, pushRes)
	}

	dstFile := filepath.Join(localDir, "pulled.txt")
	pullRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "transfer",
		Arguments: TransferFileInput{
			NodeID:     "files",
			Direction:  "pull",
			LocalPath:  dstFile,
			RemotePath: "/pushed.txt",
		},
	})
	if err != nil || pullRes.IsError {
		t.Fatalf("stdio transfer pull failed: err=%v res=%+v", err, pullRes)
	}
	got, err := os.ReadFile(dstFile)
	if err != nil || string(got) != "push-and-pull-payload" {
		t.Fatalf("pulled file mismatch: %q err=%v", got, err)
	}
}

func TestTerminalOutputFoldingAndGUIScreenshot(t *testing.T) {
	// Generate a 100-line output for terminal folding and a PNG screenshot for gui.
	img := image.NewRGBA(image.Rect(0, 0, 1600, 900))
	img.SetRGBA(0, 0, color.RGBA{R: 255, A: 255})
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		t.Fatal(err)
	}
	b64Img := base64.StdEncoding.EncodeToString(pngBuf.Bytes())

	var lines []string
	for i := 1; i <= 80; i++ {
		lines = append(lines, fmt.Sprintf("line-%d", i))
	}
	longOut := strings.Join(lines, "\n")

	backend := &stubResultBackend{
		runResult: ports.CommandResult{
			Output:    longOut,
			Connected: true,
			Outcome:   ssh.ExecutionCompleted,
		},
	}
	client := startStubResultRuntime(t, backend)

	// 1. Verify terminal output folding (>60 lines on exit 0 -> keeps head 15 + tail 30).
	termRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "terminal",
		Arguments: TerminalInput{
			NodeID:  "node",
			Command: "ls -la",
		},
	})
	if err != nil || termRes.IsError {
		t.Fatalf("terminal failed: err=%v res=%+v", err, termRes)
	}
	var termOut TerminalOutput
	rawTerm, _ := json.Marshal(termRes.StructuredContent)
	_ = json.Unmarshal(rawTerm, &termOut)
	if !termOut.Truncated || !strings.Contains(termOut.Output, "35 lines omitted") {
		t.Fatalf("expected folded output with 35 lines omitted, got:\n%s", termOut.Output)
	}

	// 2. Verify gui tool returns ImageContent with downscaled JPEG.
	backend.runResult = ports.CommandResult{
		Output:    "___MCP_GUI_IMG_BEGIN___\n" + b64Img + "\n___MCP_GUI_IMG_END___\n",
		Connected: true,
		Outcome:   ssh.ExecutionCompleted,
	}
	guiRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name: "gui",
		Arguments: GUIInput{
			NodeID: "node",
			Action: "shot",
		},
	})
	if err != nil || guiRes.IsError {
		t.Fatalf("gui shot failed: err=%v res=%+v", err, guiRes)
	}
	foundImage := false
	for _, c := range guiRes.Content {
		if ic, ok := c.(*mcp.ImageContent); ok && ic.MIMEType == "image/jpeg" && len(ic.Data) > 0 {
			foundImage = true
		}
	}
	if !foundImage {
		t.Fatalf("expected ImageContent(image/jpeg) in gui response, got %+v", guiRes.Content)
	}

	// 3. A screenshot cut by the output bound must fail instead of decoding garbage.
	backend.runResult.Truncated = true
	truncRes, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "gui",
		Arguments: GUIInput{NodeID: "node", Action: "shot"},
	})
	if err != nil || !truncRes.IsError {
		t.Fatalf("expected tool error for truncated screenshot, got err=%v res=%+v", err, truncRes)
	}
}

func TestFilePatchRefusesFileLargerThanReadLimit(t *testing.T) {
	client := startStdioSFTPRuntime(t, pkgsftp.InMemHandler())
	large := strings.Repeat("x", maxFileReadBytes) + "\nTAIL-MARKER\n"
	callFile(t, client, FileInput{NodeID: "files", Action: "write", Path: "/big.txt", Content: large}, false)

	res := callFile(t, client, FileInput{NodeID: "files", Action: "patch", Path: "/big.txt",
		Content: "<<<<\nTAIL-MARKER\n====\nREPLACED\n>>>>"}, true)
	if !res.IsError {
		t.Fatal("patch of a file above the read limit must be rejected")
	}

	stat := decodeFileOutput(t, callFile(t, client, FileInput{NodeID: "files", Action: "stat", Path: "/big.txt"}, false))
	if stat.Size != int64(len(large)) {
		t.Fatalf("file must be left intact: size=%d want %d", stat.Size, len(large))
	}
	read := decodeFileOutput(t, callFile(t, client, FileInput{NodeID: "files", Action: "read", Path: "/big.txt"}, false))
	if !read.Truncated || !strings.Contains(read.Content, "only the first") {
		t.Fatalf("read above the limit must report truncation, got truncated=%v", read.Truncated)
	}
}

func TestFileWriteIsAtomicAndLeavesNoTemporaryFiles(t *testing.T) {
	client := startStdioSFTPRuntime(t, pkgsftp.InMemHandler())
	callFile(t, client, FileInput{NodeID: "files", Action: "write", Path: "/dir/a.txt", Content: "one\n"}, false)
	callFile(t, client, FileInput{NodeID: "files", Action: "write", Path: "/dir/a.txt", Content: "two\n"}, false)

	stat := decodeFileOutput(t, callFile(t, client, FileInput{NodeID: "files", Action: "stat", Path: "/dir"}, false))
	if strings.Contains(stat.Content, ".tmp") || !strings.Contains(stat.Content, "a.txt") {
		t.Fatalf("expected only a.txt in /dir, got:\n%s", stat.Content)
	}
	read := decodeFileOutput(t, callFile(t, client, FileInput{NodeID: "files", Action: "read", Path: "/dir/a.txt"}, false))
	if !strings.Contains(read.Content, "1 | two") {
		t.Fatalf("expected replaced content, got %q", read.Content)
	}
}

func callFile(t *testing.T, client *mcp.ClientSession, in FileInput, allowError bool) *mcp.CallToolResult {
	t.Helper()
	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "file", Arguments: in})
	if err != nil {
		t.Fatalf("file %s: %v", in.Action, err)
	}
	if res.IsError && !allowError {
		t.Fatalf("file %s failed: %+v", in.Action, res.Content)
	}
	return res
}

func decodeFileOutput(t *testing.T, res *mcp.CallToolResult) FileOutput {
	t.Helper()
	var out FileOutput
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSessionOutputNeverReportsUnobservedCompletion(t *testing.T) {
	r := &Runtime{}
	zero := uint32(0)
	cases := []struct {
		state       session.State
		exit        *uint32
		wantOutcome string
		wantStatus  string
	}{
		{session.StateCompleted, &zero, "completed", "success"},
		{session.StateRunning, nil, "unknown", "running"},
		{session.StateLost, nil, "unknown", "failed"},
	}
	for _, tc := range cases {
		out := r.sessionOutput(t.Context(), "node", session.ExecuteResult{State: tc.state, ExitCode: tc.exit})
		if out.Outcome != tc.wantOutcome || out.Status != tc.wantStatus {
			t.Fatalf("state %v: got outcome=%q status=%q", tc.state, out.Outcome, out.Status)
		}
		if tc.state != session.StateCompleted && out.ExitCode != nil {
			t.Fatalf("state %v must not carry an exit code", tc.state)
		}
	}
}

func TestGUITypeRiskExposesText(t *testing.T) {
	for _, in := range []GUIInput{
		{NodeID: "n", Action: "type", Text: "rm -rf /\n"},
		{NodeID: "n", Action: "type", Text: "-rf /"},
		{NodeID: "n", Action: "key", Text: "Return"},
	} {
		ri := guiRiskInput(in)
		ri.ToolName = "gui"
		if ri.Text != in.Text || !strings.Contains(ri.Details, fmt.Sprintf("%q", in.Text)) {
			t.Fatalf("typed text/key must reach guardrail and audit details: %+v", ri)
		}
		if got := guardrail.Classify(ri); got != guardrail.Dangerous {
			t.Fatalf("gui %s(%q) must be classified Dangerous to prevent keystroke fragmentation bypass, got %v", in.Action, in.Text, got)
		}
	}
}

func TestTerminalPersistentSessionViaRuntime(t *testing.T) {
	pub := setupPublication(t, nil, false)
	call := func() TerminalOutput {
		t.Helper()
		sessRes, err := pub.client.CallTool(t.Context(), &mcp.CallToolParams{
			Name: "terminal",
			Arguments: TerminalInput{
				NodeID:  "node",
				Command: "echo pty_ok",
				Session: "dev",
			},
		})
		if err != nil || sessRes.IsError {
			t.Fatalf("persistent terminal session failed: err=%v res=%+v", err, sessRes)
		}
		var sessOut TerminalOutput
		rawSess, _ := json.Marshal(sessRes.StructuredContent)
		_ = json.Unmarshal(rawSess, &sessOut)
		if sessOut.Status != "success" || sessOut.Outcome != "completed" || sessOut.ExitCode == nil || *sessOut.ExitCode != 0 {
			t.Fatalf("unexpected persistent session output: %+v", sessOut)
		}
		return sessOut
	}

	first := call()
	if !first.NewSession {
		t.Fatalf("expected NewSession=true on initial persistent session call, got %+v", first)
	}
	second := call()
	if second.NewSession {
		t.Fatalf("expected NewSession=false on reused persistent session call, got %+v", second)
	}

	// Changing only target.Plan (host/port of the second fixture, while keeping
	// Version and ExecutionVersion identical) must change Generation via
	// ssh.ConnectionKey(target.Plan) and force a fresh PTY session (R6-1).
	publishTarget(t, pub, pub.second.Address)
	third := call()
	if !third.NewSession {
		t.Fatalf("expected NewSession=true after target Plan host/port change, got %+v", third)
	}
}

type pipeFileSession struct {
	ports.FileSession
	client     *pkgsftp.Client
	createHook func(ctx context.Context, remotePath string, write func(io.Writer) error) (bool, bool, error)
	setOwner   func(remotePath string, uid uint32)
}

type ownerFileInfo struct {
	os.FileInfo
	uid uint32
}

func (o ownerFileInfo) Uid() uint32 { return o.uid }
func (o ownerFileInfo) Gid() uint32 { return o.uid }

type singleLister []os.FileInfo

func (l singleLister) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(ls, l[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

type ownerTrackingFS struct {
	pkgsftp.FileLister
	cmd    pkgsftp.FileCmder
	mu     sync.Mutex
	owners map[string]uint32
}

func (l *ownerTrackingFS) setOwner(remotePath string, uid uint32) {
	l.mu.Lock()
	l.owners[remotePath] = uid
	l.mu.Unlock()
}

func (l *ownerTrackingFS) Filecmd(r *pkgsftp.Request) error {
	if err := l.cmd.Filecmd(r); err != nil {
		return err
	}
	l.mu.Lock()
	switch r.Method {
	case "Rename", "PosixRename":
		l.owners[r.Target] = l.owners[r.Filepath]
		delete(l.owners, r.Filepath)
	case "Remove":
		delete(l.owners, r.Filepath)
	}
	l.mu.Unlock()
	return nil
}

func (l *ownerTrackingFS) Lstat(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	la, err := l.FileLister.(pkgsftp.LstatFileLister).Lstat(r)
	if err != nil {
		return la, err
	}
	l.mu.Lock()
	uid := l.owners[r.Filepath]
	l.mu.Unlock()
	if uid == 0 {
		return la, nil
	}
	var buf [1]os.FileInfo
	n, _ := la.ListAt(buf[:], 0)
	if n == 0 {
		return la, nil
	}
	return singleLister{ownerFileInfo{FileInfo: buf[0], uid: uid}}, nil
}

func newPipeFileSession(t *testing.T) *pipeFileSession {
	t.Helper()
	cConn, sConn := net.Pipe()
	base := pkgsftp.InMemHandler()
	tracker := &ownerTrackingFS{
		FileLister: base.FileList,
		cmd:        base.FileCmd,
		owners:     make(map[string]uint32),
	}
	base.FileList = tracker
	base.FileCmd = tracker
	srv := pkgsftp.NewRequestServer(sConn, base)
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = sConn.Close()
	})
	client, err := pkgsftp.NewClientPipe(cConn, cConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = cConn.Close()
	})
	return &pipeFileSession{client: client, setOwner: tracker.setOwner}
}

func (p *pipeFileSession) Do(_ context.Context, fn func(*pkgsftp.Client) error) error {
	return fn(p.client)
}

func (p *pipeFileSession) CreatePrivateExclusive(ctx context.Context, remotePath string, write func(io.Writer) error) (bool, bool, error) {
	if p.createHook != nil {
		return p.createHook(ctx, remotePath, write)
	}
	f, err := p.client.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return true, false, err
	}
	defer func() { _ = f.Close() }()
	if err := write(f); err != nil {
		return true, true, err
	}
	return true, true, nil
}

func (p *pipeFileSession) Close() error { return nil }

func TestFileRefusesSymlinkAndDetectsConcurrentHashChange(t *testing.T) {
	fs := newPipeFileSession(t)
	if err := fs.client.MkdirAll("/work"); err != nil {
		t.Fatal(err)
	}

	// 1. Create a regular file and a symbolic link to it; write/patch must refuse the symlink.
	if inPlace, err := replaceFile(t.Context(), fs, "/work/real.txt", []byte("original\n"), nil); err != nil || inPlace {
		t.Fatalf("expected atomic initial write, got inPlace=%v err=%v", inPlace, err)
	}
	if err := fs.client.Symlink("/work/real.txt", "/work/link.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := replaceFile(t.Context(), fs, "/work/link.txt", []byte("hijacked\n"), nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected symlink replacement to be rejected, got %v", err)
	}

	// 2. Same size and mtime but different SHA-256 content must be rejected by verifyUnchanged.
	info, err := fs.client.Lstat("/work/real.txt")
	if err != nil {
		t.Fatal(err)
	}
	staleSnap := &fileSnapshot{
		size:    info.Size(),
		modTime: info.ModTime(),
		sha256:  sha256.Sum256([]byte("different")),
	}
	if _, err := replaceFile(t.Context(), fs, "/work/real.txt", []byte("updated\n"), staleSnap); err == nil || !strings.Contains(err.Error(), "changed since it was read") {
		t.Fatalf("expected SHA-256 mismatch to reject commit, got %v", err)
	}

	// 3. When CreatePrivateExclusive rejects creation with os.ErrExist on an already-existing
	// path owned by someone else, atomicCommit must NOT delete that unowned file (R1-1 / R4-5).
	var preExistingTmp string
	fs.createHook = func(_ context.Context, remotePath string, _ func(io.Writer) error) (bool, bool, error) {
		preExistingTmp = remotePath
		f, err := fs.client.Create(remotePath)
		if err != nil {
			return false, false, err
		}
		_, _ = io.WriteString(f, "owned-by-other")
		_ = f.Close()
		return true, false, os.ErrExist
	}
	if _, err := replaceFile(t.Context(), fs, "/work/real.txt", []byte("should-fail\n"), nil); err == nil {
		t.Fatal("expected replaceFile to fail when CreatePrivateExclusive returns ErrExist")
	}
	otherData, _, _, err := readBounded(t.Context(), fs, preExistingTmp)
	if err != nil || string(otherData) != "owned-by-other" {
		t.Fatalf("unowned file at %s was deleted or modified: data=%q err=%v", preExistingTmp, otherData, err)
	}
}

func TestFileFallsBackInPlaceOnPermissionOrOwnerMismatch(t *testing.T) {
	fs := newPipeFileSession(t)
	if err := fs.client.MkdirAll("/work"); err != nil {
		t.Fatal(err)
	}
	if _, err := replaceFile(t.Context(), fs, "/work/real.txt", []byte("original\n"), nil); err != nil {
		t.Fatal(err)
	}
	info, err := fs.client.Lstat("/work/real.txt")
	if err != nil {
		t.Fatal(err)
	}

	// 1. When CreatePrivateExclusive fails with os.ErrPermission on an existing regular file,
	// replaceFile must fall back to writeInPlace and report inPlace=true (R4-7).
	fs.createHook = func(context.Context, string, func(io.Writer) error) (bool, bool, error) {
		return true, false, os.ErrPermission
	}
	validSnap := &fileSnapshot{
		size:    info.Size(),
		modTime: info.ModTime(),
		sha256:  sha256.Sum256([]byte("original\n")),
	}
	if inPlace, err := replaceFile(t.Context(), fs, "/work/real.txt", []byte("in-place-ok\n"), validSnap); err != nil || !inPlace {
		t.Fatalf("expected writeInPlace fallback (inPlace=true), got inPlace=%v err=%v", inPlace, err)
	}
	data, _, _, err := readBounded(t.Context(), fs, "/work/real.txt")
	if err != nil || string(data) != "in-place-ok\n" {
		t.Fatalf("expected in-place content 'in-place-ok\\n', got %q err=%v", data, err)
	}

	// 2. When an existing file has a different owner (UID 999) and Chown on the temporary
	// file cannot preserve that owner, replaceFile must fall back to writeInPlace (R4-3, R5-4).
	// Because ownerTrackingFS overwrites the target's owner on PosixRename/Rename, UID 999
	// only survives if replaceFile fell back to writeInPlace instead of renaming the UID-0 tmp file.
	fs.createHook = nil
	fs.setOwner("/work/real.txt", 999)
	if inPlace, err := replaceFile(t.Context(), fs, "/work/real.txt", []byte("preserve-owner\n"), nil); err != nil || !inPlace {
		t.Fatalf("expected writeInPlace fallback to preserve owner, got inPlace=%v err=%v", inPlace, err)
	}
	afterInfo, err := fs.client.Lstat("/work/real.txt")
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := afterInfo.Sys().(*pkgsftp.FileStat); !ok || st.UID != 999 || st.GID != 999 {
		t.Fatalf("expected UID/GID 999 preserved after writeInPlace, got %+v", afterInfo.Sys())
	}
	preservedData, _, _, err := readBounded(t.Context(), fs, "/work/real.txt")
	if err != nil || string(preservedData) != "preserve-owner\n" {
		t.Fatalf("expected content 'preserve-owner\\n', got %q err=%v", preservedData, err)
	}
	entries, err := fs.client.ReadDir("/work")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("unexpected leftover temporary file %s after owner fallback", e.Name())
		}
	}
}

func TestTerminalSessionPureCwdChangeClassifiedModerate(t *testing.T) {
	ri := terminalRiskInput(TerminalInput{
		NodeID:  "node",
		Session: "dev",
		Cwd:     "/srv/app",
	})
	ri.ToolName = "terminal"
	if got := guardrail.Classify(ri); got != guardrail.Moderate {
		t.Fatalf("expected pure cwd change in persistent session to be Moderate, got %v", got)
	}
}

func TestPruneFoldedLogsBoundsCacheDirectory(t *testing.T) {
	fs := newPipeFileSession(t)
	dir := "/home/user/.cache/xops-mcp"
	if err := fs.client.MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 40; i++ {
		name := fmt.Sprintf("%s/cmd-20261029T1200%02d-000000.log", dir, i)
		f, err := fs.client.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	// Non-matching file must not be removed.
	keepFile, err := fs.client.Create(dir + "/notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	_ = keepFile.Close()

	pruneFoldedLogs(fs.client, dir, maxFoldedLogs)
	entries, err := fs.client.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var logCount int
	var hasNotes bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "cmd-") {
			logCount++
		}
		if e.Name() == "notes.txt" {
			hasNotes = true
		}
	}
	if logCount != maxFoldedLogs || !hasNotes {
		t.Fatalf("expected %d cmd logs and notes.txt preserved, got logCount=%d hasNotes=%v", maxFoldedLogs, logCount, hasNotes)
	}
}
