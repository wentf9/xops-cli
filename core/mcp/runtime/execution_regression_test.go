package runtime

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
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
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestExecutionRiskUsesTrustedDialectAndLegacyDefaults(t *testing.T) {
	for _, test := range []struct {
		name            string
		request, target *ssh.ExecutionConfig
		want            guardrail.RiskLevel
		dialect         string
	}{
		{"legacy", nil, nil, guardrail.Safe, "posix"},
		{"unspecified server dialect", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, nil, guardrail.Moderate, "unknown"},
		{"node server unspecified dialect", nil, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, guardrail.Moderate, "unknown"},
		{"untrusted POSIX assertion", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}, nil, guardrail.Moderate, "unknown"},
		{"trusted POSIX server", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}, guardrail.Safe, "posix"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ri, err := resolveExecutionRisk(guardrail.RiskInput{ToolName: "xops_ssh_run", Command: "ls", Execution: test.request}, ports.Target{Execution: test.target})
			if err != nil {
				t.Fatal(err)
			}
			if ri.Dialect != test.dialect || guardrail.Classify(ri) != test.want || ri.PlanDigest == "" {
				t.Fatalf("incorrect effective risk: %+v", ri)
			}
		})
	}
}

type executionRiskSource struct {
	ports.StateSource
	execution *ssh.ExecutionConfig
}

func (s executionRiskSource) Resolve(ctx context.Context, request ports.ResolveRequest) (ports.OperationSnapshot, error) {
	view, err := s.StateSource.Resolve(ctx, request)
	if err != nil {
		return view, err
	}
	view = view.Clone()
	view.Policy = policy.Config{Enabled: true, ApprovalThreshold: "moderate", NoElicitFallback: guardrail.FallbackDeny}
	for id, target := range view.Targets {
		target.Execution = s.execution.Clone()
		target.ExecutionVersion = ports.ExecutionVersion(target.Execution)
		view.Targets[id] = target
	}
	return view, nil
}

type executionRiskGate struct{ domain string }

func (g executionRiskGate) DomainID() string { return g.domain }
func (g executionRiskGate) Enter(ctx context.Context, a ports.Admission) (ports.Permit, error) {
	return ports.NewPermit(ctx, a, nil)
}

type executionRiskBackend struct {
	ports.Backend
	calls atomic.Int32
}

func (b *executionRiskBackend) Run(context.Context, ports.Permit, string, ports.Command) (ports.CommandResult, error) {
	b.calls.Add(1)
	return ports.CommandResult{Output: "executed", Connected: true, Outcome: ssh.ExecutionCompleted}, nil
}
func (b *executionRiskBackend) Shutdown(context.Context) error { return nil }

func TestUnknownServerRequiresApprovalBeforeBackend(t *testing.T) {
	for _, test := range []struct {
		name            string
		request, target *ssh.ExecutionConfig
		denied          bool
	}{
		{"legacy request", nil, nil, false},
		{"request server unknown", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, nil, true},
		{"node server unknown", nil, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}, true},
		{"request cannot assert safety", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := runtimeTestProvider("node")
			source := executionRiskSource{provider, test.target}
			backend := &executionRiskBackend{}
			dependencies := ports.Dependencies{State: source, Gate: executionRiskGate{source.DomainID()}, Audit: ports.NoopAudit{}, NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil }}
			r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)
			result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_ssh_run", Arguments: SshRunInput{NodeID: "node", Command: "ls", Execution: test.request}})
			if err != nil {
				t.Fatal(err)
			}
			wantCalls := int32(1)
			if test.denied {
				wantCalls = 0
			}
			if result.IsError != test.denied || backend.calls.Load() != wantCalls {
				t.Fatalf("unknown server bypassed approval: result=%+v calls=%d", result, backend.calls.Load())
			}
		})
	}
}

func TestMCPToolExecutionNullLoginHandling(t *testing.T) {
	provider := runtimeTestProvider("node")
	target := &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}
	source := executionRiskSource{provider, target}
	backend := &executionRiskBackend{}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)

	// Call tool with server interpreter and explicit null login
	argsServerNullLogin := map[string]any{
		"nodeID":  "node",
		"command": "ls",
		"execution": map[string]any{
			"interpreter": "server",
			"login":       nil,
		},
	}
	result, err := client.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_ssh_run", Arguments: argsServerNullLogin})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("expected server with null login to succeed, got error: %+v", result)
	}

	// Call tool with null login alone
	argsNullLogin := map[string]any{
		"nodeID":  "node",
		"command": "ls",
		"execution": map[string]any{
			"login": nil,
		},
	}
	result, err = client.CallTool(t.Context(), &mcp.CallToolParams{Name: "xops_ssh_run", Arguments: argsNullLogin})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("expected null login to succeed, got error: %+v", result)
	}
}

type fsExecutionSource struct {
	ports.StateSource
	execution *ssh.ExecutionConfig
}

func (s fsExecutionSource) Resolve(ctx context.Context, request ports.ResolveRequest) (ports.OperationSnapshot, error) {
	view, err := s.StateSource.Resolve(ctx, request)
	if err != nil {
		return view, err
	}
	view = view.Clone()
	for id, target := range view.Targets {
		target.Execution = s.execution.Clone()
		target.ExecutionVersion = ports.ExecutionVersion(target.Execution)
		view.Targets[id] = target
	}
	return view, nil
}

type mockFileInfo struct {
	name      string
	isDir     bool
	isSymlink bool
}

func (m mockFileInfo) Name() string { return m.name }
func (m mockFileInfo) Size() int64  { return 0 }
func (m mockFileInfo) Mode() os.FileMode {
	if m.isSymlink {
		return os.ModeSymlink | 0777
	}
	if m.isDir {
		return os.ModeDir | 0755
	}
	return 0644
}
func (m mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m mockFileInfo) IsDir() bool        { return m.isDir }
func (m mockFileInfo) Sys() any           { return nil }

type mockFileSession struct {
	mu              sync.Mutex
	removeAllCalls  []string
	remoteCopyCalls [][2]string
	isDirMap        map[string]bool
	isSymlinkMap    map[string]bool
	realPathMap     map[string]string
	err             error
	closed          bool
}

func (m *mockFileSession) Do(context.Context, func(*pkgsftp.Client) error) error {
	return m.err
}
func (m *mockFileSession) Upload(context.Context, string, string, sftp.ProgressCallback) error {
	return m.err
}
func (m *mockFileSession) Download(context.Context, string, string, sftp.ProgressCallback) error {
	return m.err
}
func (m *mockFileSession) CreatePrivateExclusive(context.Context, string, func(io.Writer) error) (bool, bool, error) {
	return true, true, m.err
}
func (m *mockFileSession) RemoveAll(_ context.Context, remotePath string) error {
	m.mu.Lock()
	m.removeAllCalls = append(m.removeAllCalls, remotePath)
	m.mu.Unlock()
	return m.err
}
func (m *mockFileSession) RemoteCopy(_ context.Context, src, dst string) error {
	m.mu.Lock()
	m.remoteCopyCalls = append(m.remoteCopyCalls, [2]string{src, dst})
	m.mu.Unlock()
	return m.err
}
func (m *mockFileSession) Stat(_ context.Context, remotePath string) (os.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	target := remotePath
	if m.realPathMap != nil {
		if r, ok := m.realPathMap[remotePath]; ok {
			target = r
		} else if r, ok := m.realPathMap[path.Clean(remotePath)]; ok {
			target = r
		}
	}
	if m.isDirMap != nil {
		if isDir, ok := m.isDirMap[target]; ok {
			return mockFileInfo{name: path.Base(target), isDir: isDir}, nil
		}
		if isDir, ok := m.isDirMap[path.Clean(target)]; ok {
			return mockFileInfo{name: path.Base(target), isDir: isDir}, nil
		}
	}
	return nil, os.ErrNotExist
}
func (m *mockFileSession) Lstat(_ context.Context, remotePath string) (os.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	hasTrailingSlash := strings.HasSuffix(remotePath, "/")
	clean := path.Clean(remotePath)
	if m.isSymlinkMap != nil && !hasTrailingSlash {
		if isSym, ok := m.isSymlinkMap[remotePath]; ok && isSym {
			return mockFileInfo{name: path.Base(remotePath), isSymlink: true}, nil
		}
		if isSym, ok := m.isSymlinkMap[clean]; ok && isSym {
			return mockFileInfo{name: path.Base(clean), isSymlink: true}, nil
		}
	}
	target := remotePath
	if hasTrailingSlash && m.realPathMap != nil {
		if r, ok := m.realPathMap[remotePath]; ok {
			target = r
		} else if r, ok := m.realPathMap[clean]; ok {
			target = r
		}
	}
	if m.isDirMap != nil {
		if isDir, ok := m.isDirMap[target]; ok {
			return mockFileInfo{name: path.Base(target), isDir: isDir}, nil
		}
		if isDir, ok := m.isDirMap[path.Clean(target)]; ok {
			return mockFileInfo{name: path.Base(target), isDir: isDir}, nil
		}
	}
	return nil, os.ErrNotExist
}
func (m *mockFileSession) RealPath(_ context.Context, remotePath string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return "", m.err
	}
	if m.realPathMap != nil {
		if r, ok := m.realPathMap[remotePath]; ok {
			return r, nil
		}
		if r, ok := m.realPathMap[path.Clean(remotePath)]; ok {
			return r, nil
		}
	}
	return path.Clean(remotePath), nil
}
func (m *mockFileSession) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	return nil
}

type fsTestingBackend struct {
	ports.Backend
	files    *mockFileSession
	runCalls atomic.Int32
}

func (b *fsTestingBackend) Run(context.Context, ports.Permit, string, ports.Command) (ports.CommandResult, error) {
	b.runCalls.Add(1)
	return ports.CommandResult{Output: "executed", Connected: true, Outcome: ssh.ExecutionCompleted}, nil
}
func (b *fsTestingBackend) OpenFiles(context.Context, ports.Permit, string) (ports.FileSession, error) {
	return b.files, nil
}
func (b *fsTestingBackend) Shutdown(context.Context) error { return nil }

func TestFSRmAndCpSupportNonPOSIXViaSFTP(t *testing.T) {
	for _, test := range []struct {
		name   string
		target *ssh.ExecutionConfig
	}{
		{
			name:   "server cmd supported via sftp",
			target: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchCmd},
		},
		{
			name:   "server powershell supported via sftp",
			target: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPowerShell},
		},
		{
			name:   "server unknown dialect supported via sftp",
			target: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchUnknown},
		},
		{
			name:   "server unconfigured dialect supported via sftp",
			target: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer},
		},
		{
			name:   "server posix supported via sftp",
			target: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX},
		},
		{
			name:   "default bash supported via sftp",
			target: nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := runtimeTestProvider("node")
			source := fsExecutionSource{provider, test.target}
			session := &mockFileSession{isDirMap: map[string]bool{"/remote/src": false}}
			backend := &fsTestingBackend{files: session}
			dependencies := ports.Dependencies{
				State:      source,
				Gate:       executionRiskGate{source.DomainID()},
				Audit:      ports.NoopAudit{},
				NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
			}
			r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)

			// Test xops_fs_rm
			rmResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "xops_fs_rm",
				Arguments: FSRmInput{NodeID: "node", Path: "/remote/path/to/delete"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if rmResult.IsError {
				t.Fatalf("xops_fs_rm failed unexpectedly: %+v", rmResult)
			}
			if backend.runCalls.Load() != 0 {
				t.Fatalf("xops_fs_rm executed shell command instead of using SFTP: runCalls=%d", backend.runCalls.Load())
			}
			session.mu.Lock()
			if len(session.removeAllCalls) != 1 || session.removeAllCalls[0] != "/remote/path/to/delete" {
				t.Fatalf("xops_fs_rm did not call RemoveAll on SFTP session: calls=%v", session.removeAllCalls)
			}
			session.mu.Unlock()

			// Test xops_fs_cp
			cpResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "xops_fs_cp",
				Arguments: FSCpInput{NodeID: "node", Src: "/remote/src", Dest: "/remote/dst"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if cpResult.IsError {
				t.Fatalf("xops_fs_cp failed unexpectedly: %+v", cpResult)
			}
			if backend.runCalls.Load() != 0 {
				t.Fatalf("xops_fs_cp executed shell command instead of using SFTP: runCalls=%d", backend.runCalls.Load())
			}
			session.mu.Lock()
			if len(session.remoteCopyCalls) != 1 || session.remoteCopyCalls[0] != [2]string{"/remote/src", "/remote/dst"} {
				t.Fatalf("xops_fs_cp did not call RemoteCopy on SFTP session: calls=%v", session.remoteCopyCalls)
			}
			session.mu.Unlock()
		})
	}
}

func TestFSRmAndCpSFTPErrorPropagation(t *testing.T) {
	provider := runtimeTestProvider("node")
	target := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchCmd}
	source := fsExecutionSource{provider, target}
	session := &mockFileSession{err: errors.New("sftp permission denied")}
	backend := &fsTestingBackend{files: session}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)

	rmResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "xops_fs_rm",
		Arguments: FSRmInput{NodeID: "node", Path: "/file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rmResult.IsError {
		t.Fatal("expected xops_fs_rm to fail on SFTP error")
	}

	cpResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "xops_fs_cp",
		Arguments: FSCpInput{NodeID: "node", Src: "/src", Dest: "/dst"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cpResult.IsError {
		t.Fatal("expected xops_fs_cp to fail on SFTP error")
	}
}

func TestFSRmRejectsRootEquivalentPaths(t *testing.T) {
	rootPaths := []string{
		"/",
		"///",
		"/..",
		"/a/..",
		".",
		"..",
		"C:\\",
		"c:/",
		"/c:/",
	}

	for _, targetPath := range rootPaths {
		t.Run(targetPath, func(t *testing.T) {
			provider := runtimeTestProvider("node")
			source := fsExecutionSource{provider, nil}
			session := &mockFileSession{}
			backend := &fsTestingBackend{files: session}
			dependencies := ports.Dependencies{
				State:      source,
				Gate:       executionRiskGate{source.DomainID()},
				Audit:      ports.NoopAudit{},
				NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
			}
			r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)

			rmResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "xops_fs_rm",
				Arguments: FSRmInput{NodeID: "node", Path: targetPath},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !rmResult.IsError {
				t.Fatalf("expected xops_fs_rm to reject root path %q, but succeeded", targetPath)
			}
			var foundMsg bool
			for _, c := range rmResult.Content {
				if tc, ok := c.(*mcp.TextContent); ok && strings.Contains(tc.Text, "preserve-root") {
					foundMsg = true
					break
				}
			}
			if !foundMsg {
				t.Fatalf("expected preserve-root in error message for %q, got: %+v", targetPath, rmResult.Content)
			}
			session.mu.Lock()
			if len(session.removeAllCalls) != 0 {
				t.Fatalf("expected RemoveAll to not be called for root path %q, got: %v", targetPath, session.removeAllCalls)
			}
			session.mu.Unlock()
		})
	}

	t.Run("safe path allowed", func(t *testing.T) {
		provider := runtimeTestProvider("node")
		source := fsExecutionSource{provider, nil}
		session := &mockFileSession{}
		backend := &fsTestingBackend{files: session}
		dependencies := ports.Dependencies{
			State:      source,
			Gate:       executionRiskGate{source.DomainID()},
			Audit:      ports.NoopAudit{},
			NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
		}
		r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
		client := connectRuntimeTestClient(t, r)

		rmResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "xops_fs_rm",
			Arguments: FSRmInput{NodeID: "node", Path: "/tmp/safe/dir"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if rmResult.IsError {
			t.Fatalf("expected safe path to succeed, got error: %+v", rmResult)
		}
		session.mu.Lock()
		defer session.mu.Unlock()
		if len(session.removeAllCalls) != 1 || session.removeAllCalls[0] != "/tmp/safe/dir" {
			t.Fatalf("expected RemoveAll(/tmp/safe/dir), got: %v", session.removeAllCalls)
		}
	})
}

func TestFSCpResolvesExistingDestinationDirectory(t *testing.T) {
	for _, test := range []struct {
		name     string
		src      string
		dest     string
		isDirMap map[string]bool
		wantDst  string
	}{
		{
			name:     "copy directory into existing destination directory",
			src:      "/src",
			dest:     "/backup",
			isDirMap: map[string]bool{"/backup": true, "/src": true},
			wantDst:  "/backup/src",
		},
		{
			name:     "copy directory with trailing slash into existing destination directory",
			src:      "/src/",
			dest:     "/backup",
			isDirMap: map[string]bool{"/backup": true, "/src": true},
			wantDst:  "/backup/src",
		},
		{
			name:     "copy file into existing destination directory",
			src:      "/data/file.txt",
			dest:     "/backup",
			isDirMap: map[string]bool{"/backup": true, "/data/file.txt": false},
			wantDst:  "/backup/file.txt",
		},
		{
			name:     "copy to nonexistent destination path",
			src:      "/src",
			dest:     "/backup",
			isDirMap: map[string]bool{"/src": true},
			wantDst:  "/backup",
		},
		{
			name:     "copy file to existing destination file",
			src:      "/src/file.txt",
			dest:     "/backup/file.txt",
			isDirMap: map[string]bool{"/backup/file.txt": false, "/src/file.txt": false},
			wantDst:  "/backup/file.txt",
		},
		{
			name:     "copy directory into existing destination directory with trailing slash",
			src:      "/src",
			dest:     "/backup/",
			isDirMap: map[string]bool{"/backup": true, "/src": true},
			wantDst:  "/backup/src",
		},
		{
			name:     "copy directory contents with trailing dot into existing destination directory",
			src:      "/src/.",
			dest:     "/backup",
			isDirMap: map[string]bool{"/backup": true, "/src": true},
			wantDst:  "/backup",
		},
		{
			name:     "copy directory contents with trailing dot and slash into existing destination directory",
			src:      "/src/./",
			dest:     "/backup",
			isDirMap: map[string]bool{"/backup": true, "/src": true},
			wantDst:  "/backup",
		},
		{
			name:     "copy current directory into existing destination directory",
			src:      ".",
			dest:     "/backup",
			isDirMap: map[string]bool{"/backup": true, ".": true},
			wantDst:  "/backup",
		},
		{
			name:     "copy current directory slash into existing destination directory",
			src:      "./",
			dest:     "/backup",
			isDirMap: map[string]bool{"/backup": true, ".": true},
			wantDst:  "/backup",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := runtimeTestProvider("node")
			source := fsExecutionSource{provider, nil}
			session := &mockFileSession{isDirMap: test.isDirMap}
			backend := &fsTestingBackend{files: session}
			dependencies := ports.Dependencies{
				State:      source,
				Gate:       executionRiskGate{source.DomainID()},
				Audit:      ports.NoopAudit{},
				NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
			}
			r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)

			cpResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "xops_fs_cp",
				Arguments: FSCpInput{NodeID: "node", Src: test.src, Dest: test.dest},
			})
			if err != nil {
				t.Fatal(err)
			}
			if cpResult.IsError {
				t.Fatalf("expected xops_fs_cp to succeed, got error: %+v", cpResult)
			}
			session.mu.Lock()
			defer session.mu.Unlock()
			if len(session.remoteCopyCalls) != 1 {
				t.Fatalf("expected 1 RemoteCopy call, got: %d", len(session.remoteCopyCalls))
			}
			gotDst := session.remoteCopyCalls[0][1]
			if gotDst != test.wantDst {
				t.Fatalf("expected destination %q, got %q (calls: %v)", test.wantDst, gotDst, session.remoteCopyCalls)
			}
		})
	}
}

func TestFSCpDestinationStatError(t *testing.T) {
	provider := runtimeTestProvider("node")
	source := fsExecutionSource{provider, nil}
	session := &mockFileSession{err: errors.New("sftp stat permission denied")}
	backend := &fsTestingBackend{files: session}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)

	cpResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "xops_fs_cp",
		Arguments: FSCpInput{NodeID: "node", Src: "/src", Dest: "/backup"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cpResult.IsError {
		t.Fatal("expected xops_fs_cp to fail when destination stat errors")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.remoteCopyCalls) != 0 {
		t.Fatalf("expected RemoteCopy not to be called on stat error, got: %v", session.remoteCopyCalls)
	}
}

func TestFSRmRemoteRootAliasRejection(t *testing.T) {
	provider := runtimeTestProvider("node")
	source := fsExecutionSource{provider, nil}

	t.Run("rejects root symlink alias with trailing slash", func(t *testing.T) {
		session := &mockFileSession{
			isSymlinkMap: map[string]bool{"/tmp/root-link": true},
			isDirMap:     map[string]bool{"/": true},
			realPathMap:  map[string]string{"/tmp/root-link/": "/", "/tmp/root-link": "/"},
		}
		backend := &fsTestingBackend{files: session}
		dependencies := ports.Dependencies{
			State:      source,
			Gate:       executionRiskGate{source.DomainID()},
			Audit:      ports.NoopAudit{},
			NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
		}
		r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
		client := connectRuntimeTestClient(t, r)

		rmResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "xops_fs_rm",
			Arguments: FSRmInput{NodeID: "node", Path: "/tmp/root-link/"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !rmResult.IsError {
			t.Fatal("expected xops_fs_rm to reject /tmp/root-link/ but succeeded")
		}
		var foundMsg bool
		for _, c := range rmResult.Content {
			if tc, ok := c.(*mcp.TextContent); ok && strings.Contains(tc.Text, "preserve-root") {
				foundMsg = true
				break
			}
		}
		if !foundMsg {
			t.Fatalf("expected preserve-root in error message, got: %+v", rmResult.Content)
		}
		session.mu.Lock()
		defer session.mu.Unlock()
		if len(session.removeAllCalls) != 0 {
			t.Fatalf("expected RemoveAll not to be called, got: %v", session.removeAllCalls)
		}
	})

	t.Run("allows non-root directory with trailing slash", func(t *testing.T) {
		session := &mockFileSession{
			isDirMap:    map[string]bool{"/tmp/normal-dir": true},
			realPathMap: map[string]string{"/tmp/normal-dir/": "/tmp/normal-dir"},
		}
		backend := &fsTestingBackend{files: session}
		dependencies := ports.Dependencies{
			State:      source,
			Gate:       executionRiskGate{source.DomainID()},
			Audit:      ports.NoopAudit{},
			NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
		}
		r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
		client := connectRuntimeTestClient(t, r)

		rmResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "xops_fs_rm",
			Arguments: FSRmInput{NodeID: "node", Path: "/tmp/normal-dir/"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if rmResult.IsError {
			t.Fatalf("expected removing normal directory to succeed, got error: %+v", rmResult)
		}
		session.mu.Lock()
		defer session.mu.Unlock()
		if len(session.removeAllCalls) != 1 {
			t.Fatalf("expected RemoveAll call, got: %v", session.removeAllCalls)
		}
	})
}

func TestFSRmPreservesOrdinarySymlinkDeletion(t *testing.T) {
	provider := runtimeTestProvider("node")
	source := fsExecutionSource{provider, nil}
	session := &mockFileSession{
		isSymlinkMap: map[string]bool{"/tmp/root-link": true},
		realPathMap:  map[string]string{"/tmp/root-link": "/"},
	}
	backend := &fsTestingBackend{files: session}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)

	rmResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "xops_fs_rm",
		Arguments: FSRmInput{NodeID: "node", Path: "/tmp/root-link"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rmResult.IsError {
		t.Fatalf("expected removing symlink itself to succeed, got error: %+v", rmResult)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.removeAllCalls) != 1 || session.removeAllCalls[0] != "/tmp/root-link" {
		t.Fatalf("expected RemoveAll(/tmp/root-link), got: %v", session.removeAllCalls)
	}
}

func TestFSRmRejectsTrailingSlashSymlink(t *testing.T) {
	provider := runtimeTestProvider("node")
	source := fsExecutionSource{provider, nil}

	for _, tc := range []struct {
		name         string
		path         string
		isSymlinkMap map[string]bool
		isDirMap     map[string]bool
		realPathMap  map[string]string
	}{
		{
			name:         "trailing slash symlink pointing to non-root directory",
			path:         "/tmp/link/",
			isSymlinkMap: map[string]bool{"/tmp/link": true},
			isDirMap:     map[string]bool{"/tmp/target-dir": true},
			realPathMap:  map[string]string{"/tmp/link/": "/tmp/target-dir", "/tmp/link": "/tmp/target-dir"},
		},
		{
			name:         "trailing slash dangling symlink",
			path:         "/tmp/dangling/",
			isSymlinkMap: map[string]bool{"/tmp/dangling": true},
			realPathMap:  map[string]string{"/tmp/dangling/": "/tmp/nonexistent", "/tmp/dangling": "/tmp/nonexistent"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := &mockFileSession{
				isSymlinkMap: tc.isSymlinkMap,
				isDirMap:     tc.isDirMap,
				realPathMap:  tc.realPathMap,
			}
			backend := &fsTestingBackend{files: session}
			dependencies := ports.Dependencies{
				State:      source,
				Gate:       executionRiskGate{source.DomainID()},
				Audit:      ports.NoopAudit{},
				NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
			}
			r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)

			rmResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "xops_fs_rm",
				Arguments: FSRmInput{NodeID: "node", Path: tc.path},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !rmResult.IsError {
				t.Fatalf("expected xops_fs_rm to reject trailing-slash symlink %q, but succeeded", tc.path)
			}
			var foundMsg bool
			for _, c := range rmResult.Content {
				if textContent, ok := c.(*mcp.TextContent); ok && strings.Contains(textContent.Text, "symbolic link") && strings.Contains(textContent.Text, "trailing slash") {
					foundMsg = true
					break
				}
			}
			if !foundMsg {
				t.Fatalf("expected trailing slash symlink rejection error message, got: %+v", rmResult.Content)
			}
			session.mu.Lock()
			defer session.mu.Unlock()
			if len(session.removeAllCalls) != 0 {
				t.Fatalf("expected RemoveAll not to be called, got: %v", session.removeAllCalls)
			}
		})
	}
}

func TestFSRmPreservesFilenameCharacters(t *testing.T) {
	provider := runtimeTestProvider("node")
	source := fsExecutionSource{provider, nil}

	for _, path := range []string{
		"/data/report  ",
		"/data/report\\",
		"/data/report with space",
	} {
		t.Run(path, func(t *testing.T) {
			session := &mockFileSession{}
			backend := &fsTestingBackend{files: session}
			dependencies := ports.Dependencies{
				State:      source,
				Gate:       executionRiskGate{source.DomainID()},
				Audit:      ports.NoopAudit{},
				NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
			}
			r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)

			rmResult, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "xops_fs_rm",
				Arguments: FSRmInput{NodeID: "node", Path: path},
			})
			if err != nil {
				t.Fatal(err)
			}
			if rmResult.IsError {
				t.Fatalf("expected xops_fs_rm to succeed for %q, got: %+v", path, rmResult.Content)
			}
			session.mu.Lock()
			defer session.mu.Unlock()
			if len(session.removeAllCalls) != 1 || session.removeAllCalls[0] != path {
				t.Fatalf("expected RemoveAll(%q), got: %v", path, session.removeAllCalls)
			}
		})
	}
}

func TestMCPToolExecutionSupportedJSONForms(t *testing.T) {
	provider := runtimeTestProvider("node")
	target := &ssh.ExecutionConfig{LaunchDialect: ssh.LaunchPOSIX}
	source := executionRiskSource{provider, target}
	backend := &executionRiskBackend{}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)

	validForms := []struct {
		name      string
		execution map[string]any
	}{
		{
			name: "launch_dialect alias",
			execution: map[string]any{
				"launch_dialect": "posix",
			},
		},
		{
			name: "launchDialect camelCase",
			execution: map[string]any{
				"launchDialect": "posix",
			},
		},
		{
			name: "login enabled string",
			execution: map[string]any{
				"login": "enabled",
			},
		},
		{
			name: "login disabled string",
			execution: map[string]any{
				"login": "disabled",
			},
		},
		{
			name: "login inherit string",
			execution: map[string]any{
				"login": "inherit",
			},
		},
		{
			name: "login boolean true",
			execution: map[string]any{
				"login": true,
			},
		},
		{
			name: "login boolean false",
			execution: map[string]any{
				"login": false,
			},
		},
		{
			name: "login null",
			execution: map[string]any{
				"login": nil,
			},
		},
		{
			name: "combined server with launch_dialect and login inherit",
			execution: map[string]any{
				"interpreter":    "server",
				"launch_dialect": "posix",
				"login":          "inherit",
			},
		},
		{
			name: "combined server with launchDialect and login null",
			execution: map[string]any{
				"interpreter":   "server",
				"launchDialect": "posix",
				"login":         nil,
			},
		},
	}

	for _, tc := range validForms {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]any{
				"nodeID":    "node",
				"command":   "uptime",
				"execution": tc.execution,
			}
			result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "xops_ssh_run",
				Arguments: args,
			})
			if err != nil {
				t.Fatalf("call tool error: %v", err)
			}
			if result.IsError {
				t.Fatalf("expected valid execution form %v to succeed, got error: %+v", tc.execution, result)
			}
		})
	}

	// Verify schema rejects unknown properties in execution
	t.Run("rejects unknown field in execution", func(t *testing.T) {
		args := map[string]any{
			"nodeID":  "node",
			"command": "uptime",
			"execution": map[string]any{
				"unknown_property": "bad",
			},
		}
		result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "xops_ssh_run",
			Arguments: args,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatal("expected schema validation error for unknown_property, but call succeeded")
		}
	})

	// Verify schema rejects invalid login type (e.g. integer)
	t.Run("rejects numeric login", func(t *testing.T) {
		args := map[string]any{
			"nodeID":  "node",
			"command": "uptime",
			"execution": map[string]any{
				"login": 12345,
			},
		}
		result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "xops_ssh_run",
			Arguments: args,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatal("expected schema validation error for numeric login, but call succeeded")
		}
	})
}

func TestFSRmRejectsTerminalDotComponents(t *testing.T) {
	provider := runtimeTestProvider("node")
	source := fsExecutionSource{provider, nil}
	for _, targetPath := range []string{"/data/.", "/data/./", "/data/subdir/..", "/data/subdir/../", "rel/."} {
		t.Run(targetPath, func(t *testing.T) {
			session := &mockFileSession{isDirMap: map[string]bool{"/data": true, "/data/subdir": true}}
			backend := &fsTestingBackend{files: session}
			dependencies := ports.Dependencies{
				State:      source,
				Gate:       executionRiskGate{source.DomainID()},
				Audit:      ports.NoopAudit{},
				NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
			}
			r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
			client := connectRuntimeTestClient(t, r)
			result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "xops_fs_rm",
				Arguments: FSRmInput{NodeID: "node", Path: targetPath},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Fatalf("expected xops_fs_rm to reject %q", targetPath)
			}
			session.mu.Lock()
			defer session.mu.Unlock()
			if len(session.removeAllCalls) != 0 {
				t.Fatalf("expected RemoveAll not to be called, got %v", session.removeAllCalls)
			}
		})
	}
}

func TestFSCpResolvesSymlinkDirectorySourceWithTrailingDot(t *testing.T) {
	provider := runtimeTestProvider("node")
	source := fsExecutionSource{provider, nil}
	session := &mockFileSession{
		isDirMap:     map[string]bool{"/target": true},
		isSymlinkMap: map[string]bool{"/link": true},
		realPathMap:  map[string]string{"/link": "/target"},
	}
	backend := &fsTestingBackend{files: session}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)
	result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "xops_fs_cp",
		Arguments: FSCpInput{NodeID: "node", Src: "/link/.", Dest: "/dst"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("expected success, got %+v", result.Content)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.remoteCopyCalls) != 1 || session.remoteCopyCalls[0] != [2]string{"/target", "/dst"} {
		t.Fatalf("expected RemoteCopy(/target, /dst), got %v", session.remoteCopyCalls)
	}
}

func TestFSCpRejectsNonexistentTrailingSlashDestination(t *testing.T) {
	provider := runtimeTestProvider("node")
	source := fsExecutionSource{provider, nil}
	session := &mockFileSession{
		isDirMap: map[string]bool{"/file.txt": false, "/dir": true},
	}
	backend := &fsTestingBackend{files: session}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)

	for _, src := range []string{"/file.txt", "/dir"} {
		t.Run("src="+src, func(t *testing.T) {
			result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "xops_fs_cp",
				Arguments: FSCpInput{NodeID: "node", Src: src, Dest: "/missing/"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Fatalf("expected copy to nonexistent trailing slash destination /missing/ to fail for %s", src)
			}
			session.mu.Lock()
			defer session.mu.Unlock()
			if len(session.remoteCopyCalls) != 0 {
				t.Fatalf("expected RemoteCopy not to be called, got %v", session.remoteCopyCalls)
			}
		})
	}
}

func TestFSCpRejectsDestinationDirectorySymlink(t *testing.T) {
	provider := runtimeTestProvider("node")
	source := fsExecutionSource{provider, nil}
	session := &mockFileSession{
		isDirMap:     map[string]bool{"/source": true, "/backup": true, "/other": true},
		isSymlinkMap: map[string]bool{"/backup/source": true},
		realPathMap:  map[string]string{"/backup/source": "/other"},
	}
	backend := &fsTestingBackend{files: session}
	dependencies := ports.Dependencies{
		State:      source,
		Gate:       executionRiskGate{source.DomainID()},
		Audit:      ports.NoopAudit{},
		NewBackend: func(context.Context) (ports.Backend, error) { return backend, nil },
	}
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	client := connectRuntimeTestClient(t, r)

	result, err := client.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "xops_fs_cp",
		Arguments: FSCpInput{NodeID: "node", Src: "/source", Dest: "/backup"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected copy to existing destination symlink /backup/source to fail, but succeeded")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.remoteCopyCalls) != 0 {
		t.Fatalf("expected RemoteCopy not to be called, got %v", session.remoteCopyCalls)
	}
}
