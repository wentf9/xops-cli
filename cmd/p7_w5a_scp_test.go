package cmd

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestP7W5a_AB5M2_SCPRemoteToRemoteUsesCoreSFTPAndPreserves0600(t *testing.T) {
	t.Run("cmd_scp_delegates_relay_to_core_sftp_with_no_bespoke_sftp_OpenFile", testP7W5aSCPDelegatesRelayAST)
	t.Run("relay_preserves_0600_mode_and_mtime", testP7W5aSCPRelayPreserves0600AndMtime)
	t.Run("relay_rejects_preexisting_symlink_temp_file", testP7W5aSCPRelayRejectsSymlinkTemp)
}

func testP7W5aSCPDelegatesRelayAST(t *testing.T) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file path")
	}
	scpGoPath := filepath.Join(filepath.Dir(thisFile), "scp.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, scpGoPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", scpGoPath, err)
	}
	calledRelayFileFrom := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "OpenFile":
			pos := fset.Position(call.Pos())
			t.Errorf("%s:%d: cmd/scp.go must not open remote staging files directly", filepath.Base(pos.Filename), pos.Line)
		case "RelayFileFrom":
			calledRelayFileFrom = true
		}
		return true
	})
	if !calledRelayFileFrom {
		t.Fatal("cmd/scp.go must delegate remote-to-remote file relay to core/sftp.(*Client).RelayFileFrom")
	}
}

func testP7W5aSCPRelayPreserves0600AndMtime(t *testing.T) {
	t.Helper()
	fixture := newSCPTransferFixture(t)
	for _, dir := range []string{"src", "dst"} {
		if err := os.Mkdir(filepath.Join(fixture.home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	srcFile := filepath.Join(fixture.home, "src", "id_ed25519")
	if err := os.WriteFile(srcFile, []byte("private-key-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(srcFile, 0o600); err != nil {
		t.Fatal(err)
	}
	wantTime := time.Unix(1700001234, 0)
	if err := os.Chtimes(srcFile, wantTime, wantTime); err != nil {
		t.Fatal(err)
	}

	opts := NewScpOptions()
	opts.Source = "scp-test:./src/id_ed25519"
	opts.Dest = "scp-test:./dst/id_ed25519"
	opts.Force = true
	opts.Quiet = true
	if err := opts.runTransfer(fixture.ctx, fixture.repo, fixture.connector); err != nil {
		t.Fatalf("remote-to-remote scp failed: %v", err)
	}

	dstFile := filepath.Join(fixture.home, "dst", "id_ed25519")
	assertSCPTestFile(t, dstFile, "private-key-bytes")
	info, err := os.Stat(dstFile)
	if err != nil {
		t.Fatalf("Stat(%q): %v", dstFile, err)
	}
	if info.ModTime().Unix() != wantTime.Unix() {
		t.Fatalf("relayed mtime = %v, want %v", info.ModTime(), wantTime)
	}
	if runtime.GOOS != "windows" {
		if gotPerm := info.Mode().Perm(); gotPerm != 0o600 {
			t.Fatalf("relayed file mode = %04o, want 0600", gotPerm)
		}
	}
}

func testP7W5aSCPRelayRejectsSymlinkTemp(t *testing.T) {
	t.Helper()
	fixture := newSCPTransferFixture(t)
	for _, dir := range []string{"src", "dst"} {
		if err := os.Mkdir(filepath.Join(fixture.home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	srcFile := filepath.Join(fixture.home, "src", "secret.key")
	writeSCPTestFile(t, srcFile, "attacker-data")
	victim := filepath.Join(fixture.home, "victim.txt")
	writeSCPTestFile(t, victim, "precious-victim")
	dstFile := filepath.Join(fixture.home, "dst", "secret.key")
	if err := os.Symlink(victim, dstFile+sftp.DefaultTempSuffix); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows: %v", err)
		}
		t.Fatal(err)
	}

	opts := NewScpOptions()
	opts.Source = "scp-test:./src/secret.key"
	opts.Dest = "scp-test:./dst/secret.key"
	opts.Force = true
	opts.Quiet = true
	err := opts.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("remote-to-remote scp with symlink temp path = %v, want not a regular file error", err)
	}
	assertSCPTestFile(t, victim, "precious-victim")
	if _, statErr := os.Lstat(dstFile); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination %q must not exist after rejected relay: %v", dstFile, statErr)
	}
}

func TestP7W5a_EFG5L1_SCPRejectsAliasInBatchAndRemoteToRemote(t *testing.T) {
	t.Run("cli_rejects_alias_before_reading_stdin_credentials", func(t *testing.T) {
		cases := []struct {
			name string
			args []string
		}{
			{name: "batch_single_host", args: []string{"--alias", "box", "--host", "web1", "./local.txt", "/tmp/remote.txt"}},
			{name: "batch_multi_host", args: []string{"--alias", "box", "--host", "web1,web2", "./local.txt", "/tmp/remote.txt"}},
			{name: "batch_tag", args: []string{"--alias", "box", "--tag", "prod", "./local.txt", "/tmp/remote.txt"}},
			{name: "batch_ifile", args: []string{"--alias", "box", "--ifile", "hosts.txt", "./local.txt", "/tmp/remote.txt"}},
			{name: "remote_to_remote_distinct", args: []string{"--alias", "box", "web1:/src.txt", "web2:/dst.txt"}},
			{name: "remote_to_remote_same_host", args: []string{"--alias", "box", "web1:/src.txt", "web1:/dst.txt"}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				setSCPTestConfirmation(t, "secret-must-not-be-read")
				cmd := NewCmdScp()
				cmd.SetOut(io.Discard)
				cmd.SetErr(io.Discard)
				cmd.SetArgs(append(append([]string(nil), tc.args...), "--password-stdin"))
				err := cmd.Execute()
				if err == nil || !strings.Contains(err.Error(), "--alias") {
					t.Fatalf("scp %v error = %v, want --alias rejection", tc.args, err)
				}
				pos, seekErr := os.Stdin.Seek(0, io.SeekCurrent)
				if seekErr != nil || pos != 0 {
					t.Fatalf("rejected --alias invocation consumed stdin credentials: pos=%d err=%v", pos, seekErr)
				}
			})
		}
	})

	t.Run("planTransfer_and_runTransfer_reject_alias_before_WithPendingNode", func(t *testing.T) {
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		repo, err := config.NewRepositoryWithoutOpenSSH(cfg, &memoryStore{cfg: cfg})
		if err != nil {
			t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
		}
		initialNodes := repo.Snapshot().Nodes.Count()

		cases := []struct {
			name  string
			setup func(o *ScpOptions)
		}{
			{
				name: "batch_host",
				setup: func(o *ScpOptions) {
					o.Host = "10.0.0.10"
					o.Source = "./local.txt"
					o.Dest = "/tmp/remote.txt"
				},
			},
			{
				name: "batch_tag",
				setup: func(o *ScpOptions) {
					o.Tag = "prod"
					o.Source = "./local.txt"
					o.Dest = "/tmp/remote.txt"
				},
			},
			{
				name: "batch_ifile",
				setup: func(o *ScpOptions) {
					o.HostFile = filepath.Join(t.TempDir(), "hosts.txt")
					writeSCPTestFile(t, o.HostFile, "10.0.0.10\n")
					o.Source = "./local.txt"
					o.Dest = "/tmp/remote.txt"
				},
			},
			{
				name: "remote_to_remote",
				setup: func(o *ScpOptions) {
					o.Source = "10.0.0.10:/src.txt"
					o.Dest = "10.0.0.11:/dst.txt"
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				o := NewScpOptions()
				o.Alias = "my-box"
				o.control.ConfigFile = "none"
				tc.setup(o)

				if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "--alias") {
					t.Fatalf("Validate(%s) = %v, want --alias rejection", tc.name, err)
				}
				if _, err := o.planTransfer(t.Context(), repo); err == nil || !strings.Contains(err.Error(), "--alias") {
					t.Fatalf("planTransfer(%s) = %v, want --alias rejection", tc.name, err)
				}
				if err := o.runTransfer(t.Context(), repo, nil); err == nil || !strings.Contains(err.Error(), "--alias") {
					t.Fatalf("runTransfer(%s) = %v, want --alias rejection", tc.name, err)
				}
				if got := repo.Snapshot().Nodes.Count(); got != initialNodes {
					t.Fatalf("node count mutated from %d to %d despite fail-closed rejection", initialNodes, got)
				}
			})
		}

		// Direct runRemoteToRemote call must also fail closed before WithPendingNode.
		o := NewScpOptions()
		o.Alias = "my-box"
		err = o.runRemoteToRemote(
			t.Context(),
			PathInfo{IsRemote: true, Host: "10.0.0.10", Path: "/src.txt"},
			PathInfo{IsRemote: true, Host: "10.0.0.11", Path: "/dst.txt"},
			repo,
			nil,
		)
		if err == nil || !strings.Contains(err.Error(), "--alias") {
			t.Fatalf("runRemoteToRemote with --alias = %v, want --alias rejection", err)
		}
		if got := repo.Snapshot().Nodes.Count(); got != initialNodes {
			t.Fatalf("runRemoteToRemote mutated nodes from %d to %d", initialNodes, got)
		}
	})

	t.Run("single_endpoint_upload_and_download_allow_alias", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			src  string
			dst  string
		}{
			{name: "upload", src: "./local.txt", dst: "web1:/tmp/remote.txt"},
			{name: "download", src: "web1:/tmp/remote.txt", dst: "./local.txt"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				o := NewScpOptions()
				o.Alias = "my-box"
				o.Source = tc.src
				o.Dest = tc.dst
				if err := o.Validate(); err != nil {
					t.Fatalf("Validate(%s with --alias) unexpected error: %v", tc.name, err)
				}
			})
		}
	})
}
