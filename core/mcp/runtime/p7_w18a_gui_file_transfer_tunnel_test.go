package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"path"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/ssh"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
)

func w18aTinyGUIPNGOutput(t *testing.T) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	img.SetRGBA(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return "___MCP_GUI_IMG_BEGIN___\n" + base64.StdEncoding.EncodeToString(buf.Bytes()) + "\n___MCP_GUI_IMG_END___\n"
}

type w18aGUIBackend struct {
	ports.Backend
	probes      atomic.Int32
	calls       atomic.Int32
	probeResult *ssh.ProbeResult
	probeErr    error
	screenshot  string
	mu          sync.Mutex
	lastCmd     ports.Command
}

func (b *w18aGUIBackend) ProbeExecution(ctx context.Context, p ports.Permit, _ string) (*ssh.ProbeResult, error) {
	if _, cancel, err := ports.WorkContext(ctx, p, ports.Inspect); err != nil {
		return nil, err
	} else {
		defer cancel()
	}
	b.probes.Add(1)
	return b.probeResult, b.probeErr
}

func (b *w18aGUIBackend) Run(ctx context.Context, p ports.Permit, nodeID string, command ports.Command) (ports.CommandResult, error) {
	if _, cancel, err := ports.WorkContext(ctx, p, ports.Execute); err != nil {
		return ports.CommandResult{}, err
	} else {
		defer cancel()
	}
	_, target, err := p.Snapshot().Resolve(nodeID)
	if err != nil {
		return ports.CommandResult{}, err
	}
	effective, err := ssh.ResolveExecution(command.Execution, target.Execution)
	if err != nil {
		return ports.CommandResult{Outcome: ssh.ExecutionNotStarted, ExecutionErr: err}, err
	}
	plan, err := ssh.PlanCommand(command.Text, command.CommandOptions(effective))
	if err != nil {
		return ports.CommandResult{Outcome: ssh.ExecutionNotStarted, ExecutionErr: err}, err
	}
	if command.RequirePOSIX {
		if err := ports.ValidatePOSIXBournePlan(plan, "POSIX shell target (X11/Wayland) is required"); err != nil {
			return ports.CommandResult{Outcome: ssh.ExecutionNotStarted, ExecutionErr: err}, err
		}
	}
	b.calls.Add(1)
	b.mu.Lock()
	b.lastCmd = command
	b.mu.Unlock()
	return ports.CommandResult{Output: b.screenshot, Connected: true, Outcome: ssh.ExecutionCompleted}, nil
}

func (b *w18aGUIBackend) Shutdown(context.Context) error { return nil }

func TestP7W18a_AB18H1_GUIExecutionProbeAndPOSIXCoercion(t *testing.T) {
	screenshot := w18aTinyGUIPNGOutput(t)
	no := false

	cases := []struct {
		name        string
		target      *ssh.ExecutionConfig
		probe       *ssh.ProbeResult
		pol         policy.Config
		input       GUIInput
		wantErr     bool
		wantProbes  int32
		wantCalls   int32
		wantInterp  ssh.Interpreter
		wantDialect ssh.LaunchDialect
	}{
		{
			name:        "unconfigured_linux_posix_probes_and_succeeds",
			target:      nil,
			probe:       &ssh.ProbeResult{DetectedDialect: ssh.LaunchPOSIX, AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterBash, ssh.InterpreterSh}, SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &no}},
			pol:         policy.Config{Disabled: true},
			input:       GUIInput{NodeID: "node", Action: "shot"},
			wantErr:     false,
			wantProbes:  1,
			wantCalls:   1,
			wantInterp:  ssh.InterpreterBash,
			wantDialect: ssh.LaunchPOSIX,
		},
		{
			name:        "unconfigured_linux_fish_with_sh_coerces_to_sh_over_fish",
			target:      nil,
			probe:       &ssh.ProbeResult{DetectedDialect: ssh.LaunchFish, AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterBash, ssh.InterpreterSh, ssh.InterpreterFish}, SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: &no}},
			pol:         policy.Config{Disabled: true},
			input:       GUIInput{NodeID: "node", Action: "shot"},
			wantErr:     false,
			wantProbes:  1,
			wantCalls:   1,
			wantInterp:  ssh.InterpreterSh,
			wantDialect: ssh.LaunchFish,
		},
		{
			name:        "unconfigured_bsd_csh_with_bash_coerces_to_bash_over_csh",
			target:      nil,
			probe:       &ssh.ProbeResult{DetectedDialect: ssh.LaunchCsh, AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterBash, ssh.InterpreterCsh}, SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterCsh, LaunchDialect: ssh.LaunchCsh, Login: &no}},
			pol:         policy.Config{Disabled: true},
			input:       GUIInput{NodeID: "node", Action: "shot"},
			wantErr:     false,
			wantProbes:  1,
			wantCalls:   1,
			wantInterp:  ssh.InterpreterBash,
			wantDialect: ssh.LaunchCsh,
		},
		{
			name:       "unconfigured_fish_without_posix_shells_fails_closed",
			target:     nil,
			probe:      &ssh.ProbeResult{DetectedDialect: ssh.LaunchFish, AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterFish}, SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchFish, Login: &no}},
			pol:        policy.Config{Disabled: true},
			input:      GUIInput{NodeID: "node", Action: "shot"},
			wantErr:    true,
			wantProbes: 1,
			wantCalls:  0,
		},
		{
			name:       "unconfigured_windows_cmd_fails_closed",
			target:     nil,
			probe:      &ssh.ProbeResult{DetectedDialect: ssh.LaunchCmd, AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterBash, ssh.InterpreterCmd}, SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchCmd}},
			pol:        policy.Config{Disabled: true},
			input:      GUIInput{NodeID: "node", Action: "shot"},
			wantErr:    true,
			wantProbes: 1,
			wantCalls:  0,
		},
		{
			name:       "unconfigured_windows_powershell_fails_closed",
			target:     nil,
			probe:      &ssh.ProbeResult{DetectedDialect: ssh.LaunchPowerShell, AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterPowerShell}, SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell, LaunchDialect: ssh.LaunchPowerShell}},
			pol:        policy.Config{Disabled: true},
			input:      GUIInput{NodeID: "node", Action: "shot"},
			wantErr:    true,
			wantProbes: 1,
			wantCalls:  0,
		},
		{
			name:       "pinned_fish_over_posix_fails_closed_without_probe",
			target:     &ssh.ExecutionConfig{Interpreter: ssh.InterpreterFish, LaunchDialect: ssh.LaunchPOSIX, Login: &no},
			pol:        policy.Config{Disabled: true},
			input:      GUIInput{NodeID: "node", Action: "shot"},
			wantErr:    true,
			wantProbes: 0,
			wantCalls:  0,
		},
		{
			name:       "pinned_pwsh_over_posix_fails_closed_without_probe",
			target:     &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPwsh, LaunchDialect: ssh.LaunchPOSIX},
			pol:        policy.Config{Disabled: true},
			input:      GUIInput{NodeID: "node", Action: "shot"},
			wantErr:    true,
			wantProbes: 0,
			wantCalls:  0,
		},
		{
			name:       "hard_denied_gui_type_skips_probe_and_audits_denied",
			target:     nil,
			probe:      &ssh.ProbeResult{DetectedDialect: ssh.LaunchPOSIX, AvailableInterpreters: []ssh.Interpreter{ssh.InterpreterSh}, SuggestedConfig: ssh.ExecutionConfig{Interpreter: ssh.InterpreterSh, LaunchDialect: ssh.LaunchPOSIX, Login: &no}},
			pol:        policy.Config{ApprovalThreshold: "dangerous", NoElicitFallback: guardrail.FallbackDeny},
			input:      GUIInput{NodeID: "node", Action: "type", Text: "rm -rf /"},
			wantErr:    true,
			wantProbes: 0,
			wantCalls:  0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := runtimeTestProvider("node")
			source := probeRuntimeSource{StateSource: provider, execution: tc.target, policy: tc.pol}
			backend := &w18aGUIBackend{probeResult: tc.probe, screenshot: screenshot}
			gate := &probeRuntimeGate{domain: source.DomainID()}
			r, err := NewRuntime(t.Context(), WithDependencies(ports.Dependencies{
				State:      source,
				Gate:       gate,
				Audit:      ports.NoopAudit{},
				NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
			}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)
			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "gui", Arguments: tc.input})
			if err != nil {
				t.Fatalf("CallTool transport error: %v", err)
			}
			if res.IsError != tc.wantErr {
				t.Fatalf("IsError = %v, want %v (content=%+v)", res.IsError, tc.wantErr, res.Content)
			}
			if backend.probes.Load() != tc.wantProbes || backend.calls.Load() != tc.wantCalls {
				t.Fatalf("probes=%d (want %d), calls=%d (want %d)", backend.probes.Load(), tc.wantProbes, backend.calls.Load(), tc.wantCalls)
			}
			if !tc.wantErr {
				backend.mu.Lock()
				gotExec := backend.lastCmd.Execution
				backend.mu.Unlock()
				if gotExec == nil || gotExec.Interpreter != tc.wantInterp || gotExec.LaunchDialect != tc.wantDialect {
					t.Fatalf("executed config = %+v, want interpreter=%q dialect=%q", gotExec, tc.wantInterp, tc.wantDialect)
				}
			}
		})
	}
}

// w18aSymlinkSFTPHandler is a small in-memory SFTP request handler with mutable
// symlink resolution for testing AB18-M1 canonicalization and TOCTOU defense.
type w18aSymlinkSFTPHandler struct {
	mu          sync.Mutex
	files       map[string][]byte
	dirs        map[string]bool
	symlinks    map[string]string // link path -> target path
	reads       atomic.Int32
	writes      atomic.Int32
	inspections atomic.Int32
	lists       atomic.Int32
	onAfterStat func(resolved string)
}

func (h *w18aSymlinkSFTPHandler) swapFileToDir(p string) {
	clean := path.Clean(p)
	h.mu.Lock()
	delete(h.files, clean)
	h.dirs[clean] = true
	h.mu.Unlock()
}

func newW18aSymlinkSFTPHandler() *w18aSymlinkSFTPHandler {
	return &w18aSymlinkSFTPHandler{
		files:    make(map[string][]byte),
		dirs:     map[string]bool{"/": true},
		symlinks: make(map[string]string),
	}
}

func (h *w18aSymlinkSFTPHandler) setDir(p string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cur := path.Clean(p)
	for cur != "/" && cur != "." {
		h.dirs[cur] = true
		cur = path.Dir(cur)
	}
	h.dirs["/"] = true
}

func (h *w18aSymlinkSFTPHandler) setFile(p string, data []byte) {
	h.setDir(path.Dir(p))
	h.mu.Lock()
	defer h.mu.Unlock()
	h.files[path.Clean(p)] = slices.Clone(data)
}

func (h *w18aSymlinkSFTPHandler) setSymlink(linkPath, target string) {
	clean := path.Clean(linkPath)
	h.mu.Lock()
	if parent, err := h.resolveLocked(path.Dir(clean), true); err == nil {
		clean = path.Join(parent, path.Base(clean))
	}
	h.mu.Unlock()
	h.setDir(path.Dir(clean))
	h.mu.Lock()
	defer h.mu.Unlock()
	h.symlinks[clean] = target
}

func (h *w18aSymlinkSFTPHandler) resolveLocked(p string, followFinal bool) (string, error) {
	clean := path.Clean(p)
	if !strings.HasPrefix(clean, "/") {
		return "", os.ErrNotExist
	}
	if clean == "/" {
		return "/", nil
	}
	segs := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	cur := "/"
	hops := 0
	for i := 0; i < len(segs); i++ {
		if segs[i] == "" || segs[i] == "." {
			continue
		}
		if segs[i] == ".." {
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, segs[i])
		isLast := i == len(segs)-1
		if target, isLink := h.symlinks[next]; isLink && (!isLast || followFinal) {
			hops++
			if hops > 20 {
				return "", errors.New("too many symlinks")
			}
			resolvedTarget := target
			if !strings.HasPrefix(resolvedTarget, "/") {
				resolvedTarget = path.Join(cur, resolvedTarget)
			}
			rest := ""
			if !isLast {
				rest = "/" + strings.Join(segs[i+1:], "/")
			}
			combined := path.Clean(resolvedTarget + rest)
			if combined == "/" {
				return "/", nil
			}
			segs = strings.Split(strings.TrimPrefix(combined, "/"), "/")
			cur = "/"
			i = -1
			continue
		}
		cur = next
	}
	return cur, nil
}

func (h *w18aSymlinkSFTPHandler) existsLocked(p string) bool {
	if h.dirs[p] {
		return true
	}
	if _, ok := h.files[p]; ok {
		return true
	}
	if _, ok := h.symlinks[p]; ok {
		return true
	}
	return false
}

func (h *w18aSymlinkSFTPHandler) RealPath(p string) (string, error) {
	h.inspections.Add(1)
	h.mu.Lock()
	defer h.mu.Unlock()
	resolved, err := h.resolveLocked(p, true)
	if err != nil {
		return "", err
	}
	if !h.existsLocked(resolved) {
		return "", os.ErrNotExist
	}
	return resolved, nil
}

func (h *w18aSymlinkSFTPHandler) Readlink(p string) (string, error) {
	h.inspections.Add(1)
	h.mu.Lock()
	defer h.mu.Unlock()
	resolved, err := h.resolveLocked(p, false)
	if err != nil {
		return "", err
	}
	if target, ok := h.symlinks[resolved]; ok {
		return target, nil
	}
	return "", os.ErrInvalid
}

func (h *w18aSymlinkSFTPHandler) Lstat(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.inspections.Add(1)
	h.mu.Lock()
	defer h.mu.Unlock()
	resolved, err := h.resolveLocked(r.Filepath, false)
	if err != nil {
		return nil, err
	}
	if _, ok := h.symlinks[resolved]; ok {
		return w10aListerAt{w10aSynthFileInfo{name: path.Base(resolved), mode: os.ModeSymlink | 0o777}}, nil
	}
	if h.dirs[resolved] {
		return w10aListerAt{w10aSynthFileInfo{name: path.Base(resolved), mode: os.ModeDir | 0o755}}, nil
	}
	if data, ok := h.files[resolved]; ok {
		return w10aListerAt{w10aSynthFileInfo{name: path.Base(resolved), size: int64(len(data)), mode: 0o644}}, nil
	}
	return nil, os.ErrNotExist
}

func (h *w18aSymlinkSFTPHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	var postStat func()
	defer func() {
		if postStat != nil {
			postStat()
		}
	}()
	h.mu.Lock()
	defer h.mu.Unlock()
	resolved, err := h.resolveLocked(r.Filepath, true)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "Stat":
		h.inspections.Add(1)
		if h.onAfterStat != nil {
			cb := h.onAfterStat
			target := resolved
			postStat = func() { cb(target) }
		}
		if h.dirs[resolved] {
			return w10aListerAt{w10aSynthFileInfo{name: path.Base(resolved), mode: os.ModeDir | 0o755}}, nil
		}
		if data, ok := h.files[resolved]; ok {
			return w10aListerAt{w10aSynthFileInfo{name: path.Base(resolved), size: int64(len(data)), mode: 0o644}}, nil
		}
		return nil, os.ErrNotExist
	case "List":
		h.lists.Add(1)
		if !h.dirs[resolved] {
			return nil, os.ErrNotExist
		}
		var out []os.FileInfo
		seen := make(map[string]bool)
		addChild := func(full string, fi os.FileInfo) {
			if full == resolved || path.Dir(full) != resolved {
				return
			}
			if seen[full] {
				return
			}
			seen[full] = true
			out = append(out, fi)
		}
		for d := range h.dirs {
			addChild(d, w10aSynthFileInfo{name: path.Base(d), mode: os.ModeDir | 0o755})
		}
		for f, data := range h.files {
			addChild(f, w10aSynthFileInfo{name: path.Base(f), size: int64(len(data)), mode: 0o644})
		}
		return w10aListerAt(out), nil
	case "Readlink":
		h.inspections.Add(1)
		resolvedNoFollow, err := h.resolveLocked(r.Filepath, false)
		if err != nil {
			return nil, err
		}
		if target, ok := h.symlinks[resolvedNoFollow]; ok {
			return w10aListerAt{w10aSynthFileInfo{name: target, mode: os.ModeSymlink | 0o777}}, nil
		}
		return nil, os.ErrNotExist
	default:
		return nil, pkgsftp.ErrSSHFxOpUnsupported
	}
}

func (h *w18aSymlinkSFTPHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	resolved, err := h.resolveLocked(r.Filepath, true)
	if err != nil {
		return nil, err
	}
	data, ok := h.files[resolved]
	if !ok {
		return nil, os.ErrNotExist
	}
	h.reads.Add(1)
	return bytes.NewReader(slices.Clone(data)), nil
}

type w18aMemWriter struct {
	h    *w18aSymlinkSFTPHandler
	path string
}

func (w *w18aMemWriter) WriteAt(p []byte, off int64) (int, error) {
	w.h.mu.Lock()
	defer w.h.mu.Unlock()
	cur := w.h.files[w.path]
	end := int(off) + len(p)
	if end > len(cur) {
		grown := make([]byte, end)
		copy(grown, cur)
		cur = grown
	}
	copy(cur[off:], p)
	w.h.files[w.path] = cur
	return len(p), nil
}

func (h *w18aSymlinkSFTPHandler) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	resolved, err := h.resolveLocked(r.Filepath, true)
	if err != nil {
		return nil, err
	}
	if !h.dirs[path.Dir(resolved)] {
		return nil, os.ErrNotExist
	}
	h.writes.Add(1)
	if r.Pflags().Trunc || r.Pflags().Creat {
		if _, exists := h.files[resolved]; !exists || r.Pflags().Trunc {
			h.files[resolved] = nil
		}
	}
	return &w18aMemWriter{h: h, path: resolved}, nil
}

func (h *w18aSymlinkSFTPHandler) Filecmd(r *pkgsftp.Request) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	resolved, err := h.resolveLocked(r.Filepath, false)
	if err != nil {
		return err
	}
	switch r.Method {
	case "Setstat":
		return nil
	case "Mkdir":
		h.dirs[resolved] = true
		return nil
	case "Remove":
		delete(h.files, resolved)
		delete(h.symlinks, resolved)
		return nil
	case "Rename", "PosixRename":
		target, err := h.resolveLocked(r.Target, false)
		if err != nil {
			return err
		}
		if data, ok := h.files[resolved]; ok {
			h.files[target] = data
			delete(h.files, resolved)
			return nil
		}
		return os.ErrNotExist
	default:
		return nil
	}
}

func (h *w18aSymlinkSFTPHandler) handlers() pkgsftp.Handlers {
	return pkgsftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

func startW18aStdioSFTPRuntime(
	t *testing.T,
	guardCfg *policy.Config,
	handlers pkgsftp.Handlers,
	protocol string,
	elicitHandler func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error),
) (*Runtime, *mcp.ServerSession, *mcp.ClientSession, *w11aAuditRecorder) {
	t.Helper()
	provider := startTransferSSH(t, handlers)
	cfg := provider.Snapshot()
	cfg.Guardrail = guardCfg
	r, err := NewRuntime(t.Context(), WithConfigProvider(config.NewProviderWithoutOpenSSH(cfg)))
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
	return r, ss, cs, recorder
}

func TestP7W18a_AB18M1_FileCanonicalProtectedPathsAndTOCTOU(t *testing.T) {
	t.Run("read_and_stat_symlinks_disclose_canonical_protected_paths", testP7W18aFileReadStatSymlinks)
	t.Run("write_parent_symlink_and_final_symlink_rejection", testP7W18aFileWriteParentSymlink)
	t.Run("two_step_toctou_symlink_retargeting_rejected", testP7W18aFileTwoStepTOCTOU)
	t.Run("forged_roundtrip_rejected_before_ssh_on_lexical_need_approval", testP7W18aForgedRoundTripPreSSH)
	t.Run("stat_isdir_toctou_and_canonical_path_pinning", testP7W18aFileStatIsDirTOCTOUAndPinning)
}

func newW18aFileSymlinkFixture() *w18aSymlinkSFTPHandler {
	h := newW18aSymlinkSFTPHandler()
	h.setFile("/etc/shadow", []byte("root:secret\n"))
	h.setFile("/etc/passwd", []byte("root:x:0:0\n"))
	h.setFile("/opt/app/secrets/cfg.txt", []byte("token=old\n"))
	h.setFile("/tmp/public.txt", []byte("hello\n"))
	h.setSymlink("/tmp/shadow_link", "/etc/shadow")
	h.setSymlink("/tmp/etc_dir_link", "/etc")
	h.setSymlink("/tmp/sec_dir", "/opt/app/secrets")
	h.setSymlink("/tmp/sec_dir/final_link", "/etc/shadow")
	return h
}

func testP7W18aFileReadStatSymlinks(t *testing.T) {
	h := newW18aFileSymlinkFixture()
	var mu sync.Mutex
	var elicited []string
	_, _, client, audit := startW18aStdioSFTPRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc", "/opt/app/secrets"},
	}, h.handlers(), "2026-07-28", func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		mu.Lock()
		elicited = append(elicited, req.Params.Message)
		mu.Unlock()
		return &mcp.ElicitResult{Action: "decline"}, nil
	})

	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "file",
		Arguments: FileInput{NodeID: "files", Action: "read", Path: "/tmp/shadow_link"},
	})
	if err != nil || !res.IsError {
		t.Fatalf("read symlink to /etc/shadow bypassed guardrail: res=%+v err=%v", res, err)
	}
	if h.reads.Load() != 0 {
		t.Fatalf("remote file read %d times despite declined approval", h.reads.Load())
	}
	mu.Lock()
	if len(elicited) != 1 || !strings.Contains(elicited[0], "/etc/shadow") {
		t.Fatalf("elicitation messages = %v, want /etc/shadow disclosed", elicited)
	}
	mu.Unlock()
	entries := audit.snapshot()
	if len(entries) == 0 || !slices.Contains(entries[len(entries)-1].Paths, "/etc/shadow") {
		t.Fatalf("audit entries missing canonical /etc/shadow: %+v", entries)
	}

	audit.reset()
	res, err = client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "file",
		Arguments: FileInput{NodeID: "files", Action: "stat", Path: "/tmp/etc_dir_link"},
	})
	if err != nil || !res.IsError {
		t.Fatalf("stat symlink to /etc bypassed guardrail: res=%+v err=%v", res, err)
	}
	entries = audit.snapshot()
	if len(entries) == 0 || !slices.Contains(entries[len(entries)-1].Paths, "/etc") {
		t.Fatalf("stat audit missing canonical /etc: %+v", entries)
	}
}

func testP7W18aFileWriteParentSymlink(t *testing.T) {
	h := newW18aFileSymlinkFixture()
	_, _, client, audit := startW18aStdioSFTPRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc", "/opt/app/secrets"},
	}, h.handlers(), "2026-07-28", func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
	})

	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "file",
		Arguments: FileInput{NodeID: "files", Action: "write", Path: "/tmp/sec_dir/new.txt", Content: "v=1\n"},
	})
	if err != nil || res.IsError {
		t.Fatalf("approved write through parent symlink failed: res=%+v err=%v", res, err)
	}
	entries := audit.snapshot()
	if !slices.ContainsFunc(entries, func(e guardrail.AuditEntry) bool {
		return e.Outcome == "executed" && slices.Contains(e.Paths, "/opt/app/secrets/new.txt")
	}) {
		t.Fatalf("write audit missing executed canonical path /opt/app/secrets/new.txt: %+v", entries)
	}

	res, err = client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "file",
		Arguments: FileInput{NodeID: "files", Action: "write", Path: "/tmp/sec_dir/final_link", Content: "pwn"},
	})
	if err != nil || !res.IsError {
		t.Fatalf("write to final-component symlink inside symlinked parent must fail: res=%+v err=%v", res, err)
	}
}

func testP7W18aFileTwoStepTOCTOU(t *testing.T) {
	h := newW18aFileSymlinkFixture()
	h.setSymlink("/tmp/toctou_link", "/etc/shadow")
	r, ss, _, _ := startW18aStdioSFTPRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc"},
	}, h.handlers(), "2026-07-28", func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
	})

	in := FileInput{NodeID: "files", Action: "read", Path: "/tmp/toctou_link"}
	pending, _, err := r.fileHandler(t.Context(), &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, in)
	if err != nil || pending == nil || pending.RequestState == "" {
		t.Fatalf("TOCTOU round 1: pending=%+v err=%v", pending, err)
	}
	h.setSymlink("/tmp/toctou_link", "/etc/passwd")
	readsBefore := h.reads.Load()
	_, _, err = r.fileHandler(t.Context(), &mcp.CallToolRequest{
		Session: ss,
		Params: &mcp.CallToolParamsRaw{
			RequestState:   pending.RequestState,
			InputResponses: mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}},
		},
	}, in)
	if err == nil {
		t.Fatal("TOCTOU symlink retargeting between Round 1 and Round 2 was accepted")
	}
	if h.reads.Load() != readsBefore {
		t.Fatalf("TOCTOU retargeted file was read (%d -> %d)", readsBefore, h.reads.Load())
	}
}

func testP7W18aForgedRoundTripPreSSH(t *testing.T) {
	h := newW18aFileSymlinkFixture()
	r, ss1, _, audit := startW18aStdioSFTPRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc"},
	}, h.handlers(), "2026-07-28", func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
	})
	ss2, _ := connectW17aInMemorySession(t, r, "2026-07-28", &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
		},
	})

	// Mint a live pending token on ss2 so we can test cross-session replay too.
	fileIn := FileInput{NodeID: "files", Action: "read", Path: "/etc/shadow"}
	otherPending, _, err := r.fileHandler(t.Context(), &mcp.CallToolRequest{Session: ss2, Params: &mcp.CallToolParamsRaw{}}, fileIn)
	if err != nil || otherPending == nil || otherPending.RequestState == "" {
		t.Fatalf("mint ss2 pending token: pending=%+v err=%v", otherPending, err)
	}
	if h.inspections.Load() != 0 {
		t.Fatalf("lexical Round 1 opened SFTP (%d inspections)", h.inspections.Load())
	}

	acceptMap := mcp.InputResponseMap{"approval": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}}
	invalidParams := []*mcp.CallToolParamsRaw{
		{RequestState: "forged-state", InputResponses: acceptMap},
		{InputResponses: acceptMap},
		{RequestState: otherPending.RequestState, InputResponses: acceptMap},
	}
	transferIn := TransferFileInput{
		NodeID:     "files",
		Direction:  "pull",
		LocalPath:  filepath.Join(t.TempDir(), "shadow.out"),
		RemotePath: "/etc/shadow",
	}

	for _, params := range invalidParams {
		assertW18aInvalidRoundTripPreSSH(t, r, ss1, h, audit, params, fileIn, transferIn)
	}

	// Legitimate canonical Round 2 on ss1 still succeeds end-to-end.
	canonIn := FileInput{NodeID: "files", Action: "read", Path: "/tmp/shadow_link"}
	pending, _, err := r.fileHandler(t.Context(), &mcp.CallToolRequest{Session: ss1, Params: &mcp.CallToolParamsRaw{}}, canonIn)
	if err != nil || pending == nil || pending.RequestState == "" {
		t.Fatalf("canonical round 1: pending=%+v err=%v", pending, err)
	}
	_, out, err := r.fileHandler(t.Context(), &mcp.CallToolRequest{
		Session: ss1,
		Params:  &mcp.CallToolParamsRaw{RequestState: pending.RequestState, InputResponses: acceptMap},
	}, canonIn)
	if err != nil || !strings.Contains(out.Content, "root:secret") {
		t.Fatalf("legitimate canonical round 2 failed: out=%+v err=%v", out, err)
	}
}

func assertW18aInvalidRoundTripPreSSH(
	t *testing.T,
	r *Runtime,
	ss *mcp.ServerSession,
	h *w18aSymlinkSFTPHandler,
	audit *w11aAuditRecorder,
	params *mcp.CallToolParamsRaw,
	fileIn FileInput,
	transferIn TransferFileInput,
) {
	t.Helper()
	audit.reset()
	h.inspections.Store(0)
	if pending, _, err := r.fileHandler(t.Context(), &mcp.CallToolRequest{Session: ss, Params: params}, fileIn); err == nil || pending != nil {
		t.Fatalf("fileHandler accepted invalid round-trip %+v: pending=%+v err=%v", params, pending, err)
	}
	if h.inspections.Load() != 0 {
		t.Fatalf("fileHandler dialed SFTP (%d inspections) on invalid round-trip %+v", h.inspections.Load(), params)
	}
	if entries := audit.snapshot(); len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
		t.Fatalf("fileHandler invalid round-trip %+v missing denied audit: %+v", params, entries)
	}

	audit.reset()
	h.inspections.Store(0)
	if pending, _, err := r.stdioTransferHandler(t.Context(), &mcp.CallToolRequest{Session: ss, Params: params}, transferIn); err == nil || pending != nil {
		t.Fatalf("stdioTransferHandler accepted invalid round-trip %+v: pending=%+v err=%v", params, pending, err)
	}
	if h.inspections.Load() != 0 {
		t.Fatalf("stdioTransferHandler dialed SFTP (%d inspections) on invalid round-trip %+v", h.inspections.Load(), params)
	}
	if entries := audit.snapshot(); len(entries) == 0 || entries[len(entries)-1].Outcome != "denied" {
		t.Fatalf("stdioTransferHandler invalid round-trip %+v missing denied audit: %+v", params, entries)
	}
}

func testP7W18aFileStatIsDirTOCTOUAndPinning(t *testing.T) {
	// Part A: IsDir flip between Inspect (regular file -> Allow) and Execute
	// (directory containing protected /opt/app/secrets) MUST fail closed.
	h := newW18aSymlinkSFTPHandler()
	h.setFile("/opt/app", []byte("plain-file"))
	var flipped atomic.Bool
	h.onAfterStat = func(resolved string) {
		if resolved == "/opt/app" && flipped.CompareAndSwap(false, true) {
			h.swapFileToDir("/opt/app")
			h.setFile("/opt/app/secrets/db.env", []byte("SECRET=1"))
		}
	}
	_, _, client, _ := startW18aStdioSFTPRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/opt/app/secrets"},
	}, h.handlers(), "2026-07-28", func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})
	res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "file",
		Arguments: FileInput{NodeID: "files", Action: "stat", Path: "/opt/app"},
	})
	if err != nil || !res.IsError {
		t.Fatalf("stat IsDir flip TOCTOU succeeded: res=%+v err=%v", res, err)
	}
	if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "remote file path resolution changed since authorization") {
		t.Fatalf("stat IsDir flip error = %q, want path resolution changed", res.Content[0].(*mcp.TextContent).Text)
	}
	if h.lists.Load() != 0 {
		t.Fatalf("stat IsDir flip listed directory %d times", h.lists.Load())
	}

	// Part B: file(action=stat) executes against pinned canonical path.
	h2 := newW18aFileSymlinkFixture()
	_, _, client2, _ := startW18aStdioSFTPRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc"},
	}, h2.handlers(), "2026-07-28", func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
	})
	res2, err := client2.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "file",
		Arguments: FileInput{NodeID: "files", Action: "stat", Path: "/tmp/etc_dir_link"},
	})
	if err != nil || res2.IsError {
		t.Fatalf("approved stat on symlink failed: res=%+v err=%v", res2, err)
	}
	out := decodeFileOutput(t, res2)
	if !out.IsDir || !strings.HasPrefix(out.Content, "/etc/\n") {
		t.Fatalf("stat output did not execute against pinned canonical path /etc: %+v", out)
	}
}

func TestP7W18a_AB18M1_StdioTransferCanonicalAndRecursiveProtectedPaths(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("POSIX symlink test fixture")
	}
	localRoot, localProtected, localProtectedFile, localLinkToProtected, localPushDir, localPlainFile := setupW18aLocalTransferFixture(t)
	h := setupW18aRemoteTransferFixture()

	canonLocalProtected, err := filepath.EvalSymlinks(localProtected)
	if err != nil {
		t.Fatal(err)
	}
	canonLocalProtectedFile, err := filepath.EvalSymlinks(localProtectedFile)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("pull_canonical_and_recursive", func(t *testing.T) {
		assertW18aStdioPullDeniedWithCanonicalAudit(t, h, localProtected, []w18aTransferCase{
			{
				name:         "pull_remote_symlink_to_etc_shadow",
				input:        TransferFileInput{NodeID: "files", Direction: "pull", LocalPath: filepath.Join(localRoot, "out1.txt"), RemotePath: "/tmp/shadow_link"},
				wantAuditSub: "/etc/shadow",
			},
			{
				name:         "pull_into_local_symlink_pointing_to_protected_dir",
				input:        TransferFileInput{NodeID: "files", Direction: "pull", LocalPath: filepath.Join(localLinkToProtected, "dropped.txt"), RemotePath: "/tmp/harmless.txt"},
				wantAuditSub: filepath.Join(canonLocalProtected, "dropped.txt"),
			},
			{
				name:         "pull_recursive_parent_directory_containing_protected_subdir",
				input:        TransferFileInput{NodeID: "files", Direction: "pull", LocalPath: filepath.Join(localRoot, "pulled_app"), RemotePath: "/opt/app"},
				wantAuditSub: "/opt/app",
			},
		})
	})

	t.Run("push_canonical_nested_symlinks_and_expanded_remote_dir", func(t *testing.T) {
		assertW18aStdioPushDeniedOnCanonicalPrompt(t, h, localProtected, []w18aTransferCase{
			{
				name:         "push_directory_containing_symlink_to_protected_local_file",
				input:        TransferFileInput{NodeID: "files", Direction: "push", LocalPath: localPushDir, RemotePath: "/tmp/upload_dir"},
				wantAuditSub: canonLocalProtectedFile,
			},
			{
				name:         "push_file_into_remote_dir_symlink_to_protected_dir",
				input:        TransferFileInput{NodeID: "files", Direction: "push", LocalPath: localPlainFile, RemotePath: "/tmp/sec_dir_link"},
				wantAuditSub: "/opt/app/secrets/plain.txt",
			},
		})
	})
}

type w18aTransferCase struct {
	name         string
	input        TransferFileInput
	wantAuditSub string
}

func setupW18aLocalTransferFixture(t *testing.T) (string, string, string, string, string, string) {
	t.Helper()
	localRoot := t.TempDir()
	localProtected := filepath.Join(localRoot, "protected_local")
	if err := os.MkdirAll(localProtected, 0o700); err != nil {
		t.Fatal(err)
	}
	localProtectedFile := filepath.Join(localProtected, "secret.key")
	if err := os.WriteFile(localProtectedFile, []byte("local-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	localLinkToProtected := filepath.Join(localRoot, "local_etc_link")
	if err := os.Symlink(localProtected, localLinkToProtected); err != nil {
		t.Fatal(err)
	}
	localPushDir := filepath.Join(localRoot, "push_dir")
	if err := os.MkdirAll(localPushDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(localProtectedFile, filepath.Join(localPushDir, "escape.key")); err != nil {
		t.Fatal(err)
	}
	localPlainFile := filepath.Join(localRoot, "plain.txt")
	if err := os.WriteFile(localPlainFile, []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	return localRoot, localProtected, localProtectedFile, localLinkToProtected, localPushDir, localPlainFile
}

func setupW18aRemoteTransferFixture() *w18aSymlinkSFTPHandler {
	h := newW18aSymlinkSFTPHandler()
	h.setFile("/etc/shadow", []byte("shadow-bytes"))
	h.setFile("/tmp/harmless.txt", []byte("harmless"))
	h.setFile("/opt/app/secrets/db.env", []byte("DB_PASS=123"))
	h.setSymlink("/tmp/shadow_link", "/etc/shadow")
	h.setSymlink("/tmp/sec_dir_link", "/opt/app/secrets")
	return h
}

func assertW18aStdioPullDeniedWithCanonicalAudit(t *testing.T, h *w18aSymlinkSFTPHandler, localProtected string, cases []w18aTransferCase) {
	t.Helper()
	_, _, client, audit := startW18aStdioSFTPRuntime(t, &policy.Config{
		ApprovalThreshold: "moderate",
		NoElicitFallback:  guardrail.FallbackDeny,
		ProtectedPaths:    []string{"/etc", "/opt/app/secrets", localProtected},
	}, h.handlers(), "2026-07-28", func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit.reset()
			readsBefore := h.reads.Load()
			res, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "transfer", Arguments: tc.input})
			if err != nil || !res.IsError {
				t.Fatalf("%s bypassed guardrail: res=%+v err=%v", tc.name, res, err)
			}
			if h.reads.Load() != readsBefore {
				t.Fatalf("%s performed remote read despite denial", tc.name)
			}
			entries := audit.snapshot()
			if len(entries) == 0 || !slices.Contains(entries[len(entries)-1].Paths, tc.wantAuditSub) {
				t.Fatalf("%s audit Paths missing %q: %+v", tc.name, tc.wantAuditSub, entries)
			}
		})
	}
}

func assertW18aStdioPushDeniedOnCanonicalPrompt(t *testing.T, h *w18aSymlinkSFTPHandler, localProtected string, cases []w18aTransferCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writesBefore := h.writes.Load()
			var secondPromptSeen bool
			_, _, pushClient, pushAudit := startW18aStdioSFTPRuntime(t, &policy.Config{
				ApprovalThreshold: "moderate",
				NoElicitFallback:  guardrail.FallbackDeny,
				ProtectedPaths:    []string{"/etc", "/opt/app/secrets", localProtected},
			}, h.handlers(), "2025-11-25", func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				if strings.Contains(req.Params.Message, tc.wantAuditSub) {
					secondPromptSeen = true
					return &mcp.ElicitResult{Action: "decline"}, nil
				}
				return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
			})
			res, err := pushClient.CallTool(t.Context(), &mcp.CallToolParams{Name: "transfer", Arguments: tc.input})
			if err != nil || !res.IsError {
				t.Fatalf("%s did not fail when canonical prompt was declined: res=%+v err=%v", tc.name, res, err)
			}
			if !secondPromptSeen {
				t.Fatalf("%s never disclosed canonical path %q in approval prompt", tc.name, tc.wantAuditSub)
			}
			if h.writes.Load() != writesBefore {
				t.Fatalf("%s wrote remote file despite declining canonical approval", tc.name)
			}
			entries := pushAudit.snapshot()
			if len(entries) == 0 || !slices.Contains(entries[len(entries)-1].Paths, tc.wantAuditSub) {
				t.Fatalf("%s audit Paths missing %q: %+v", tc.name, tc.wantAuditSub, entries)
			}
		})
	}
}

func TestP7W18a_AB18M2_TunnelStatusStopGateAndAuditBinding(t *testing.T) {
	t.Run("manager_inspect_does_not_mutate_or_prune", testP7W18aTunnelManagerInspect)
	t.Run("missing_tunnel_gated_before_tunnel_not_found_on_blocked_patterns_and_approval", testP7W18aTunnelMissingGatedBlocked)
	t.Run("stop_tunnel_preserves_audit_binding_in_record_authorized_context", testP7W18aTunnelStopPreservesAuditBinding)
	t.Run("missing_tunnel_roundtrip_forged_rejected_and_audit_failure_fails_closed", testP7W18aTunnelMissingRoundTripAndAuditFail)
}

func testP7W18aTunnelManagerInspect(t *testing.T) {
	mgr := tunnel.New(t.Context(), func(ctx context.Context, _ tunnel.Spec, ready func(string) bool, _ func(error)) error {
		ready("127.0.0.1:43210")
		<-ctx.Done()
		return nil
	}, nil)
	t.Cleanup(func() { _ = mgr.Shutdown(t.Context()) })
	st, err := mgr.Create(t.Context(), tunnel.Spec{
		RequestID:  "inspect-1",
		NodeID:     "node",
		Mode:       "local",
		TargetHost: "127.0.0.1",
		TargetPort: 80,
	}, "op-1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := mgr.Inspect(st.TunnelID)
	if err != nil || got.TunnelID != st.TunnelID {
		t.Fatalf("Inspect(existing) = (%+v, %v)", got, err)
	}
	if _, err := mgr.Inspect("missing-id"); err == nil || !strings.Contains(err.Error(), "tunnel_not_found") {
		t.Fatalf("Inspect(missing) = %v, want tunnel_not_found", err)
	}
}

func testP7W18aTunnelMissingGatedBlocked(t *testing.T) {
	f := startTunnelSSHFixture(t, 0)
	cfg := f.provider.Snapshot()
	cfg.Guardrail = &config.GuardrailConfig{
		ApprovalThreshold: "safe",
		NoElicitFallback:  guardrail.FallbackDeny,
		BlockedPatterns:   []string{"*"},
	}
	f.provider = config.NewProviderWithoutOpenSSH(cfg)
	r := newTunnelRuntime(t, f)
	audit := &w17aFailAuditSink{}
	r.guardrail.SetAuditWriter(audit)
	_, client := connectW17aInMemorySession(t, r, "2025-11-25", nil)

	for _, action := range []string{"status", "stop"} {
		audit.reset()
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "tunnel",
			Arguments: TunnelInput{Action: action, TunnelID: "nonexistent-tunnel-id"},
		})
		if err != nil || !res.IsError {
			t.Fatalf("tunnel %s(missing) under BlockedPatterns: res=%+v err=%v", action, res, err)
		}
		msg := res.Content[0].(*mcp.TextContent).Text
		if strings.Contains(msg, "tunnel_not_found") {
			t.Fatalf("tunnel %s(missing) leaked tunnel_not_found before guardrail deny: %s", action, msg)
		}
		entries := audit.snapshot()
		if len(entries) != 1 || entries[0].Outcome != "denied" || entries[0].Binding == "" {
			t.Fatalf("tunnel %s(missing) audit = %+v, want single denied entry with binding", action, entries)
		}
	}
}

func testP7W18aTunnelStopPreservesAuditBinding(t *testing.T) {
	f := startTunnelSSHFixture(t, 0)
	target := startTunnelEcho(t)
	cfg := f.provider.Snapshot()
	cfg.Guardrail = &config.GuardrailConfig{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDeny,
	}
	f.provider = config.NewProviderWithoutOpenSSH(cfg)
	r := newTunnelRuntime(t, f)
	audit := &w17aFailAuditSink{}
	r.guardrail.SetAuditWriter(audit)
	_, client := connectW17aInMemorySession(t, r, "2025-11-25", nil)

	created := callTunnelTool(t, client, "xops_tunnel_create", tunnelTestInput(t, target, "local", "binding-stop-test"))
	audit.reset()

	stopped := callTunnelTool(t, client, "xops_tunnel_stop", TunnelInput{TunnelID: created.TunnelID})
	if stopped.State != "stopped" {
		t.Fatalf("stopped state = %+v, want stopped", stopped)
	}
	assertW18aTunnelStopAuditBinding(t, audit.snapshot())

	audit.reset()
	for _, action := range []string{"status", "stop"} {
		res, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "tunnel",
			Arguments: TunnelInput{Action: action, TunnelID: "missing-after-admission"},
		})
		if err != nil || !res.IsError {
			t.Fatalf("admitted %s(missing): res=%+v err=%v", action, res, err)
		}
		if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "tunnel_not_found") {
			t.Fatalf("admitted %s(missing) expected tunnel_not_found, got: %s", action, res.Content[0].(*mcp.TextContent).Text)
		}
	}
}

func assertW18aTunnelStopAuditBinding(t *testing.T, entries []guardrail.AuditEntry) {
	t.Helper()
	var authEntry, stopEntry *guardrail.AuditEntry
	for i := range entries {
		if entries[i].Tool == "tunnel" && entries[i].Outcome == "authorized" {
			authEntry = &entries[i]
		}
		if entries[i].Tool == "tunnel" && entries[i].Outcome == "stop_requested" {
			stopEntry = &entries[i]
		}
	}
	if authEntry == nil || stopEntry == nil {
		t.Fatalf("missing authorized or stop_requested audit entry: %+v", entries)
	}
	if authEntry.Binding == "" || stopEntry.Binding == "" || authEntry.Binding != stopEntry.Binding {
		t.Fatalf("audit Binding mismatch: auth=%q stop=%q", authEntry.Binding, stopEntry.Binding)
	}
	if authEntry.OperationID != stopEntry.OperationID {
		t.Fatalf("stop_requested OperationID %q != authorized OperationID %q", stopEntry.OperationID, authEntry.OperationID)
	}
}

func testP7W18aTunnelMissingRoundTripAndAuditFail(t *testing.T) {
	f := startTunnelSSHFixture(t, 0)
	cfg := f.provider.Snapshot()
	cfg.Guardrail = &config.GuardrailConfig{
		ApprovalThreshold: "dangerous",
		NoElicitFallback:  guardrail.FallbackDeny,
	}
	f.provider = config.NewProviderWithoutOpenSSH(cfg)
	r := newTunnelRuntime(t, f)
	audit := &w17aFailAuditSink{}
	r.guardrail.SetAuditWriter(audit)
	ss, client := connectW17aInMemorySession(t, r, "2026-07-28", nil)

	forged := &mcp.CallToolRequest{
		Session: ss,
		Params:  &mcp.CallToolParamsRaw{RequestState: "forged-tunnel-state"},
	}
	if _, _, err := r.tunnelStatus(t.Context(), forged, TunnelInput{TunnelID: "missing-id"}); err == nil || strings.Contains(err.Error(), "tunnel_not_found") {
		t.Fatalf("tunnelStatus with forged RequestState = %v, want guardrail error", err)
	}
	if _, _, err := r.stopTunnel(t.Context(), forged, TunnelInput{TunnelID: "missing-id"}); err == nil || strings.Contains(err.Error(), "tunnel_not_found") {
		t.Fatalf("stopTunnel with forged RequestState = %v, want guardrail error", err)
	}

	audit.failOutcomes = map[string]error{"authorized": errors.New("audit down")}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, action := range []string{"status", "stop"} {
		res, err := client.CallTool(ctx, &mcp.CallToolParams{
			Name:      "tunnel",
			Arguments: TunnelInput{Action: action, TunnelID: "missing-id"},
		})
		if err != nil || !res.IsError {
			t.Fatalf("%s under audit failure: res=%+v err=%v", action, res, err)
		}
		if strings.Contains(res.Content[0].(*mcp.TextContent).Text, "tunnel_not_found") {
			t.Fatalf("%s leaked tunnel_not_found despite audit failure: %s", action, res.Content[0].(*mcp.TextContent).Text)
		}
	}
}
