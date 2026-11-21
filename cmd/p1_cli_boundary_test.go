package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
)

func TestP1SanitizeHostForFilename(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"fixture", "fixture"},
		{"10.0.0.1", "10.0.0.1"},
		{"web-01.prod.internal", "web-01.prod.internal"},
		{"openssh:web1", "openssh_web1"},
		{"2001:db8::1", "2001_db8__1"},
		{"fe80::1%eth0", "fe80__1_eth0"},
		{"host with spaces", "host_with_spaces"},
		{"", "unknown_host"},
		{"   ", "unknown_host"},
		{".", "unknown_host"},
		{"..", "unknown_host"},
		{"...", "unknown_host"},
		{"///", "unknown_host"},
		{"CON", "_CON"},
		{"con", "_con"},
		{"NUL", "_NUL"},
		{"nul.example.com", "_nul.example.com"},
		{"AUX", "_AUX"},
		{"PRN.local", "_PRN.local"},
		{"COM1", "_COM1"},
		{"com9.prod", "_com9.prod"},
		{"LPT1", "_LPT1"},
		{"lpt9.prod", "_lpt9.prod"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := sanitizeHostForFilename(tc.input)
			if got != tc.want {
				t.Errorf("sanitizeHostForFilename(%q) = %q, want %q", tc.input, got, tc.want)
			}
			if strings.Contains(got, "..") || strings.ContainsAny(got, `:/\ %`) {
				t.Errorf("sanitizeHostForFilename(%q) = %q contains unsafe characters", tc.input, got)
			}
		})
	}

	// Path traversal inputs must never contain separators or "..".
	for _, trav := range []string{"../../etc/passwd", `..\..\windows\system32`, "a/b\\c"} {
		got := sanitizeHostForFilename(trav)
		if got == "" || strings.Contains(got, "..") || strings.ContainsAny(got, `/\:`) {
			t.Errorf("sanitizeHostForFilename(%q) = %q is unsafe", trav, got)
		}
	}
}

func TestP1AssignExecTaskLogNames_UniqueAndDisambiguated(t *testing.T) {
	t.Run("unique_batch_keeps_base_log_name", func(t *testing.T) {
		tasks := []execHostTask{
			{nodeID: "ops@10.0.0.1:22", host: "10.0.0.1", user: "ops", port: 22},
			{nodeID: "ops@web2:22", host: "web2", user: "ops", port: 22},
		}
		assignExecTaskLogNames(tasks)
		if tasks[0].outLogName != "10.0.0.1.log" {
			t.Errorf("tasks[0].outLogName = %q, want 10.0.0.1.log", tasks[0].outLogName)
		}
		if tasks[1].outLogName != "web2.log" {
			t.Errorf("tasks[1].outLogName = %q, want web2.log", tasks[1].outLogName)
		}
	})

	t.Run("colliding_host_disambiguates_users_ports_and_sanitized_collisions", func(t *testing.T) {
		tasks := []execHostTask{
			{nodeID: "alice@10.0.0.1:22", host: "10.0.0.1", user: "alice", port: 22},
			{nodeID: "bob@10.0.0.1:2222", host: "10.0.0.1", user: "bob", port: 2222},
			{nodeID: "openssh:web1", host: "openssh:web1", user: "ops", port: 22},
			{nodeID: "openssh_web1", host: "openssh_web1", user: "ops", port: 22},
			{nodeID: "unique.example", host: "unique.example", user: "ops", port: 22},
		}
		assignExecTaskLogNames(tasks)

		seen := make(map[string]int, len(tasks))
		for i, task := range tasks {
			if task.outLogName == "" || !strings.HasSuffix(task.outLogName, ".log") {
				t.Fatalf("tasks[%d].outLogName = %q, want non-empty .log", i, task.outLogName)
			}
			key := strings.ToLower(task.outLogName)
			if prev, dup := seen[key]; dup {
				t.Fatalf("log name collision between task %d and %d: %q", prev, i, task.outLogName)
			}
			seen[key] = i
		}
		if tasks[0].outLogName != "alice_10.0.0.1_22.log" {
			t.Errorf("tasks[0].outLogName = %q, want alice_10.0.0.1_22.log", tasks[0].outLogName)
		}
		if tasks[1].outLogName != "bob_10.0.0.1_2222.log" {
			t.Errorf("tasks[1].outLogName = %q, want bob_10.0.0.1_2222.log", tasks[1].outLogName)
		}
		if tasks[4].outLogName != "unique.example.log" {
			t.Errorf("unique task outLogName = %q, want unique.example.log", tasks[4].outLogName)
		}
	})
}

func TestP1ExecOutDir_Mode0600AndConsistentDisambiguatedPath(t *testing.T) {
	ctx, connector, _ := newExecCombinationFixture(t, nil)
	outDir := t.TempDir()

	var stdout bytes.Buffer
	o := NewExecOptions()
	o.OutDir = outDir
	o.Command = "echo ok"
	o.stdout = &stdout
	o.stderr = &bytes.Buffer{}

	tasks := []execHostTask{
		{nodeID: "fixture", host: "10.0.0.1", user: "alice", port: 22},
		{nodeID: "fixture", host: "10.0.0.1", user: "bob", port: 2222},
	}
	// Make nodeIDs distinct so disambiguatedTaskLogBase picks distinct readable names,
	// while using fixture for connection in the first task.
	tasks[0].outLogName = "alice_10.0.0.1_22.log"

	var mu sync.Mutex
	if err := o.executeTask(ctx, connector, tasks[0], "echo ok", false, 2, &mu); err != nil {
		t.Fatalf("executeTask failed: %v", err)
	}

	wantPath := filepath.Join(outDir, "alice_10.0.0.1_22.log")
	info, err := os.Stat(wantPath)
	if err != nil {
		t.Fatalf("expected log file %q to exist: %v", wantPath, err)
	}
	if runtime.GOOS != "windows" {
		if gotPerm := info.Mode().Perm(); gotPerm != 0o600 {
			t.Errorf("out-dir log file mode = %o, want 600", gotPerm)
		}
	}
	if !strings.Contains(stdout.String(), wantPath) {
		t.Errorf("printTaskResult output %q does not reference resolved log file %q", stdout.String(), wantPath)
	}
}

func TestP1SCPDownloadDirectory_PreservesBasenameIntoExistingLocalDir(t *testing.T) {
	t.Run("into_existing_local_dir_creates_subdirectory", func(t *testing.T) {
		fixture := newSCPTransferFixture(t)
		remoteDir := filepath.Join(fixture.home, "release")
		if err := os.MkdirAll(filepath.Join(remoteDir, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeSCPTestFile(t, filepath.Join(remoteDir, "app.txt"), "root-file")
		writeSCPTestFile(t, filepath.Join(remoteDir, "sub", "nested.txt"), "nested-file")

		localParent := t.TempDir()
		options := NewScpOptions()
		options.Recursive = true
		options.Force = true
		if err := options.runDownload(fixture.ctx, PathInfo{Host: "scp-test", Path: "~/release"}, localParent, fixture.repo, fixture.connector); err != nil {
			t.Fatalf("runDownload directory failed: %v", err)
		}

		// Files must be placed inside <localParent>/release/..., not dumped directly into <localParent>.
		assertSCPTestFile(t, filepath.Join(localParent, "release", "app.txt"), "root-file")
		assertSCPTestFile(t, filepath.Join(localParent, "release", "sub", "nested.txt"), "nested-file")
		if _, err := os.Stat(filepath.Join(localParent, "app.txt")); !os.IsNotExist(err) {
			t.Fatalf("directory contents leaked directly into local parent directory: err=%v", err)
		}
	})

	t.Run("trailing_dot_copies_contents_into_existing_local_dir", func(t *testing.T) {
		fixture := newSCPTransferFixture(t)
		remoteDir := filepath.Join(fixture.home, "release")
		if err := os.MkdirAll(remoteDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeSCPTestFile(t, filepath.Join(remoteDir, "app.txt"), "dot-contents")

		localParent := t.TempDir()
		options := NewScpOptions()
		options.Recursive = true
		options.Force = true
		if err := options.runDownload(fixture.ctx, PathInfo{Host: "scp-test", Path: "~/release/."}, localParent, fixture.repo, fixture.connector); err != nil {
			t.Fatalf("runDownload directory/. failed: %v", err)
		}

		assertSCPTestFile(t, filepath.Join(localParent, "app.txt"), "dot-contents")
	})

	t.Run("into_nonexistent_local_dir_creates_named_target", func(t *testing.T) {
		fixture := newSCPTransferFixture(t)
		remoteDir := filepath.Join(fixture.home, "release")
		if err := os.MkdirAll(remoteDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeSCPTestFile(t, filepath.Join(remoteDir, "app.txt"), "renamed-dir")

		localTarget := filepath.Join(t.TempDir(), "custom-dest")
		options := NewScpOptions()
		options.Recursive = true
		options.Force = true
		if err := options.runDownload(fixture.ctx, PathInfo{Host: "scp-test", Path: "~/release"}, localTarget, fixture.repo, fixture.connector); err != nil {
			t.Fatalf("runDownload to new local dir failed: %v", err)
		}

		assertSCPTestFile(t, filepath.Join(localTarget, "app.txt"), "renamed-dir")
	})

	t.Run("remote_dotdot_does_not_escape_existing_local_dir", func(t *testing.T) {
		fixture := newSCPTransferFixture(t)
		if err := os.MkdirAll(filepath.Join(fixture.home, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeSCPTestFile(t, filepath.Join(fixture.home, "escaped-check.txt"), "stay-inside")

		outerDir := t.TempDir()
		localDestDir := filepath.Join(outerDir, "dest")
		if err := os.MkdirAll(localDestDir, 0o700); err != nil {
			t.Fatal(err)
		}

		options := NewScpOptions()
		options.Recursive = true
		options.Force = true
		if err := options.runDownload(fixture.ctx, PathInfo{Host: "scp-test", Path: "~/sub/.."}, localDestDir, fixture.repo, fixture.connector); err == nil {
			t.Fatalf("runDownload ~/sub/.. unexpectedly succeeded, want unsafe remote filename error")
		} else if !strings.Contains(err.Error(), "unsafe remote filename") {
			t.Fatalf("runDownload ~/sub/.. error = %v, want unsafe remote filename error", err)
		}

		if _, err := os.Stat(filepath.Join(localDestDir, "escaped-check.txt")); !os.IsNotExist(err) {
			t.Fatalf("remote ~/sub/.. wrote into localDestDir despite unsafe basename: err=%v", err)
		}
		if _, err := os.Stat(filepath.Join(outerDir, "escaped-check.txt")); !os.IsNotExist(err) {
			t.Fatalf("remote ~/sub/.. escaped localDestDir into parent dir: err=%v", err)
		}
	})

	t.Run("safe_local_path_component_guard", func(t *testing.T) {
		for _, unsafe := range []string{"", ".", "..", "a/b", `a\b`, "/abs", `\abs`} {
			if err := fsx.ValidateLocalComponent(unsafe); err == nil {
				t.Errorf("fsx.ValidateLocalComponent(%q) = nil, want error", unsafe)
			}
		}
		for _, safe := range []string{"release", "app.log", ".hidden", "v1.2-rc1"} {
			if err := fsx.ValidateLocalComponent(safe); err != nil {
				t.Errorf("fsx.ValidateLocalComponent(%q) unexpected error: %v", safe, err)
			}
		}
	})
}

func TestP1SCPRemoteToRemote_RejectsDirectorySource(t *testing.T) {
	fixture := newSCPTransferFixture(t)
	if err := os.MkdirAll(filepath.Join(fixture.home, "srcdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fixture.home, "dstdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeSCPTestFile(t, filepath.Join(fixture.home, "srcdir", "file.txt"), "hello")

	options := NewScpOptions()
	options.Force = true
	err := options.runRemoteToRemote(
		fixture.ctx,
		PathInfo{Host: "scp-test", Path: "~/srcdir"},
		PathInfo{Host: "scp-test", Path: "~/dstdir/"},
		fixture.repo,
		fixture.connector,
	)
	if err == nil {
		t.Fatal("runRemoteToRemote on directory source succeeded, want unsupported error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "directory") {
		t.Fatalf("error = %v, want clear directory transfer error", err)
	}

	// Destination directory must remain clean (no stray temp files created).
	entries, readErr := os.ReadDir(filepath.Join(fixture.home, "dstdir"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("expected destination directory to remain empty, found %d entries", len(entries))
	}
}

func TestP1SFTPStdinCredentialConflictFailsClosedOnNonTerminalStdin(t *testing.T) {
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = wPipe.Close() }()
	defer func() { _ = rPipe.Close() }()

	origStdin := os.Stdin
	os.Stdin = rPipe
	t.Cleanup(func() { os.Stdin = origStdin })

	for _, flag := range []string{"--password-stdin", "--passphrase-stdin", "--otp-stdin"} {
		t.Run("Complete/"+flag, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				so := NewSftpOptions()
				cmd := newCmdSftpWithOptions(so)
				if parseErr := cmd.Flags().Parse([]string{flag, "web"}); parseErr != nil {
					done <- parseErr
					return
				}
				done <- so.Complete(cmd, cmd.Flags().Args())
			}()

			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("sftp %s Complete succeeded on piped stdin, want fail-closed error", flag)
				}
				if !strings.Contains(err.Error(), "SFTP batch commands") {
					t.Fatalf("sftp %s error = %v, want stdin ownership conflict message", flag, err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatalf("sftp %s Complete blocked reading piped stdin instead of failing closed", flag)
			}
		})
	}

	t.Run("RunContext_direct", func(t *testing.T) {
		so := NewSftpOptions()
		so.Host = "web"
		so.PasswordStdin = true
		err := so.RunContext(t.Context())
		if err == nil || !strings.Contains(err.Error(), "SFTP batch commands") {
			t.Fatalf("SftpOptions.RunContext with PasswordStdin on piped stdin = %v, want conflict error", err)
		}
	})
}

func TestP1CLIIdentityPathValidationDelegatesCoreSSH(t *testing.T) {
	badInputs := []struct {
		name string
		raw  string
	}{
		{"newline", "/tmp/id\nrsa"},
		{"nul_byte", "/tmp/id\x00rsa"},
		{"unicode_line_sep", "/tmp/id\u2028rsa"},
		{"unknown_percent_token", "%d/.ssh/id_%k"},
		{"trailing_percent", "/tmp/id%"},
		{"unclosed_env", "${SSH_KEY"},
		{"invalid_env_ident", "${BAD-NAME}/id"},
	}

	for _, tc := range badInputs {
		t.Run("dash_i_rejects_"+tc.name, func(t *testing.T) {
			o := NewSshOptions()
			c := newCmdSshWithOptions(o)
			if err := c.Flags().Parse([]string{"-i", tc.raw, "web"}); err != nil {
				t.Fatalf("Parse(-i %q): %v", tc.raw, err)
			}
			if err := ApplyGeneralOptions(o, o.control.Options, c.Flags()); err == nil {
				t.Fatalf("ApplyGeneralOptions(-i %q) unexpectedly succeeded", tc.raw)
			}
		})

		t.Run("dash_o_rejects_"+tc.name, func(t *testing.T) {
			o := NewSshOptions()
			if err := ApplyGeneralOptions(o, []string{"IdentityFile=" + tc.raw}, nil); err == nil {
				t.Fatalf("ApplyGeneralOptions(-o IdentityFile=%q) unexpectedly succeeded", tc.raw)
			}
		})

		t.Run("normalize_preserves_invalid_"+tc.name, func(t *testing.T) {
			if got := normalizeCLIIdentityPath(tc.raw); got != tc.raw {
				t.Fatalf("normalizeCLIIdentityPath(%q) = %q, want verbatim invalid input for downstream fail-closed", tc.raw, got)
			}
		})
	}
}
