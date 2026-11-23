package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestP7W18b_AB18M3_SCPUploadNoDoubleExpansion(t *testing.T) {
	t.Run("upload_fails_closed_when_expanded_target_is_directory_with_nested_regular_or_dangling", testP7W18bSCPUploadDirCollision)
	t.Run("upload_fails_closed_when_expanded_target_is_directory_symlink", testP7W18bSCPUploadDirSymlinkCollision)
	t.Run("batch_upload_fails_closed_when_expanded_target_is_directory_or_dir_symlink", testP7W18bSCPBatchUploadDirCollision)
	t.Run("remote_to_remote_fails_closed_when_expanded_target_is_directory_or_dir_symlink", testP7W18bSCPRemoteToRemoteDirCollision)
	t.Run("upload_directory_into_existing_same_named_dir_does_not_double_nest", testP7W18bSCPUploadDirMerge)
}

func testP7W18bSCPUploadDirCollision(t *testing.T) {
	for _, tc := range []struct {
		name        string
		force       bool
		noOverwrite bool
		nestedLink  bool
	}{
		{name: "interactive_nested_regular", force: false, noOverwrite: false, nestedLink: false},
		{name: "force_nested_regular", force: true, noOverwrite: false, nestedLink: false},
		{name: "no_clobber_nested_regular", force: false, noOverwrite: true, nestedLink: false},
		{name: "force_nested_dangling", force: true, noOverwrite: false, nestedLink: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSCPTransferFixture(t)
			localSrc := filepath.Join(t.TempDir(), "app")
			writeSCPTestFile(t, localSrc, "incoming-payload")

			nestedDir := filepath.Join(fixture.home, "work", "app")
			if err := os.MkdirAll(nestedDir, 0o700); err != nil {
				t.Fatal(err)
			}
			nestedEntry := filepath.Join(nestedDir, "app")
			missingTarget := filepath.Join(fixture.home, "missing-nested-target")
			if tc.nestedLink {
				createSCPDanglingSymlink(t, nestedEntry, missingTarget)
			} else {
				writeSCPTestFile(t, nestedEntry, "keep-nested")
			}

			options := NewScpOptions()
			options.Source = localSrc
			options.Dest = "scp-test:./work"
			options.Force = tc.force
			options.NoOverwrite = tc.noOverwrite
			setSCPTestConfirmation(t, "y")

			var runErr error
			captured := captureSCPOutput(t, false, func() {
				runErr = options.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
			})
			if runErr == nil || !strings.Contains(runErr.Error(), "cannot overwrite remote directory") {
				t.Fatalf("upload (%s) err = %v, want directory overwrite error", tc.name, runErr)
			}
			if got := strings.Count(captured, "[y/N]"); got != 0 {
				t.Fatalf("upload (%s) unexpectedly prompted %d times: %q", tc.name, got, captured)
			}
			if tc.nestedLink {
				assertDanglingSymlinkIntact(t, nestedEntry, missingTarget)
				if _, err := os.Lstat(missingTarget); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("upload (%s) created missing symlink target: err=%v", tc.name, err)
				}
			} else {
				assertSCPTestFile(t, nestedEntry, "keep-nested")
			}
		})
	}
}

func testP7W18bSCPUploadDirSymlinkCollision(t *testing.T) {
	fixture := newSCPTransferFixture(t)
	localSrc := filepath.Join(t.TempDir(), "app")
	writeSCPTestFile(t, localSrc, "incoming-payload")

	realTargetDir := filepath.Join(fixture.home, "real-dir")
	if err := os.MkdirAll(realTargetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedFile := filepath.Join(realTargetDir, "app")
	writeSCPTestFile(t, nestedFile, "keep-through-link")

	workDir := filepath.Join(fixture.home, "work")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(workDir, "app")
	createSCPDanglingSymlink(t, dirLink, realTargetDir)

	options := NewScpOptions()
	options.Source = localSrc
	options.Dest = "scp-test:./work"
	options.Force = true
	options.Quiet = true

	err := options.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
	if err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory") {
		t.Fatalf("upload onto expanded directory symlink err = %v, want directory overwrite error", err)
	}
	assertSCPTestFile(t, nestedFile, "keep-through-link")
	if info, lstatErr := os.Lstat(dirLink); lstatErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("directory symlink was altered: info=%v err=%v", info, lstatErr)
	}
}

func testP7W18bSCPBatchUploadDirCollision(t *testing.T) {
	for _, useDirSymlink := range []bool{false, true} {
		name := "real_dir"
		if useDirSymlink {
			name = "dir_symlink"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newSCPTransferFixture(t)
			localSrc := filepath.Join(t.TempDir(), "app")
			writeSCPTestFile(t, localSrc, "batch-incoming")

			workDir := filepath.Join(fixture.home, "work")
			if err := os.MkdirAll(workDir, 0o700); err != nil {
				t.Fatal(err)
			}
			var nestedFile string
			if useDirSymlink {
				realDir := filepath.Join(fixture.home, "real-batch-dir")
				if err := os.MkdirAll(realDir, 0o700); err != nil {
					t.Fatal(err)
				}
				nestedFile = filepath.Join(realDir, "app")
				writeSCPTestFile(t, nestedFile, "batch-keep")
				createSCPDanglingSymlink(t, filepath.Join(workDir, "app"), realDir)
			} else {
				nestedDir := filepath.Join(workDir, "app")
				if err := os.MkdirAll(nestedDir, 0o700); err != nil {
					t.Fatal(err)
				}
				nestedFile = filepath.Join(nestedDir, "app")
				writeSCPTestFile(t, nestedFile, "batch-keep")
			}

			options := NewScpOptions()
			options.Source = localSrc
			options.Dest = "./work"
			options.Force = true
			options.Quiet = true

			err := options.executeTransfer(fixture.ctx, "scp-test", PathInfo{Host: "scp-test"}, "", fixture.repo, fixture.connector)
			if err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory") {
				t.Fatalf("batch upload (%s) err = %v, want directory overwrite error", name, err)
			}
			assertSCPTestFile(t, nestedFile, "batch-keep")
		})
	}
}

func testP7W18bSCPRemoteToRemoteDirCollision(t *testing.T) {
	for _, tc := range []struct {
		name    string
		force   bool
		symlink bool
	}{
		{name: "interactive_dir", force: false, symlink: false},
		{name: "force_dir", force: true, symlink: false},
		{name: "force_dir_symlink", force: true, symlink: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSCPTransferFixture(t)
			writeSCPTestFile(t, filepath.Join(fixture.home, "src.txt"), "relay-incoming")

			workDir := filepath.Join(fixture.home, "work")
			if err := os.MkdirAll(workDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if tc.symlink {
				realDir := filepath.Join(fixture.home, "relay-real-dir")
				if err := os.MkdirAll(realDir, 0o700); err != nil {
					t.Fatal(err)
				}
				createSCPDanglingSymlink(t, filepath.Join(workDir, "src.txt"), realDir)
			} else {
				if err := os.MkdirAll(filepath.Join(workDir, "src.txt"), 0o700); err != nil {
					t.Fatal(err)
				}
			}

			options := NewScpOptions()
			options.Source = "scp-test:./src.txt"
			options.Dest = "scp-test:./work"
			options.Force = tc.force
			setSCPTestConfirmation(t, "y")

			var runErr error
			captured := captureSCPOutput(t, false, func() {
				runErr = options.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
			})
			if runErr == nil || !strings.Contains(runErr.Error(), "cannot overwrite remote directory") {
				t.Fatalf("remote-to-remote (%s) err = %v, want directory overwrite error", tc.name, runErr)
			}
			if got := strings.Count(captured, "[y/N]"); got != 0 {
				t.Fatalf("remote-to-remote (%s) unexpectedly prompted %d times: %q", tc.name, got, captured)
			}
		})
	}
}

func testP7W18bSCPUploadDirMerge(t *testing.T) {
	fixture := newSCPTransferFixture(t)
	localDir := filepath.Join(t.TempDir(), "mydir")
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSCPTestFile(t, filepath.Join(localDir, "hello.txt"), "dir-payload")

	remoteDir := filepath.Join(fixture.home, "work", "mydir")
	if err := os.MkdirAll(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}

	options := NewScpOptions()
	options.Source = localDir
	options.Dest = "scp-test:./work"
	options.Force = true
	options.Quiet = true

	if err := options.runTransfer(fixture.ctx, fixture.repo, fixture.connector); err != nil {
		t.Fatalf("upload directory failed: %v", err)
	}
	assertSCPTestFile(t, filepath.Join(remoteDir, "hello.txt"), "dir-payload")
	if _, err := os.Lstat(filepath.Join(remoteDir, "mydir")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("upload directory double-nested into mydir/mydir: err=%v", err)
	}
}
