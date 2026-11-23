package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func createSCPDanglingSymlink(t *testing.T, linkPath, targetPath string) {
	t.Helper()
	if err := os.Symlink(targetPath, linkPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows without privilege: %v", err)
		}
		t.Fatalf("os.Symlink(%q, %q): %v", targetPath, linkPath, err)
	}
}

func assertDanglingSymlinkIntact(t *testing.T, linkPath, wantTarget string) {
	t.Helper()
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", linkPath, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%q is no longer a symlink (mode=%v); dangling symlink was clobbered", linkPath, info.Mode())
	}
	gotTarget, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink(%q): %v", linkPath, err)
	}
	if gotTarget != wantTarget {
		t.Fatalf("symlink %q target = %q, want %q", linkPath, gotTarget, wantTarget)
	}
}

func TestP7W17a_AB17M3_DanglingRemoteSymlinkOverwriteChecks(t *testing.T) {
	t.Run("upload_no_clobber_and_decline_preserve_dangling_symlink", func(t *testing.T) {
		for _, mode := range []string{"no-clobber", "decline"} {
			t.Run(mode, func(t *testing.T) {
				fixture := newSCPTransferFixture(t)
				localSrc := filepath.Join(t.TempDir(), "upload.txt")
				writeSCPTestFile(t, localSrc, "incoming payload")

				missingTarget := filepath.Join(fixture.home, "missing-target.txt")
				danglingPath := filepath.Join(fixture.home, "dangling.txt")
				createSCPDanglingSymlink(t, danglingPath, missingTarget)

				options := NewScpOptions()
				options.Source = localSrc
				options.Dest = "scp-test:./dangling.txt"
				options.NoOverwrite = mode == "no-clobber"
				setSCPTestConfirmation(t, "n")

				var runErr error
				captured := captureSCPOutput(t, false, func() {
					runErr = options.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
				})
				if runErr != nil {
					t.Fatalf("upload (%s) unexpected error: %v", mode, runErr)
				}
				wantPrompts := 0
				if mode == "decline" {
					wantPrompts = 1
				}
				if got := strings.Count(captured, "[y/N]"); got != wantPrompts {
					t.Fatalf("upload (%s) prompts = %d, want %d; output=%q", mode, got, wantPrompts, captured)
				}
				assertDanglingSymlinkIntact(t, danglingPath, missingTarget)
				if _, err := os.Lstat(missingTarget); !os.IsNotExist(err) {
					t.Fatalf("upload (%s) created missing symlink target %q: err=%v", mode, missingTarget, err)
				}
			})
		}
	})

	t.Run("remote_to_remote_no_clobber_and_decline_preserve_dangling_symlink", func(t *testing.T) {
		for _, mode := range []string{"no-clobber", "decline"} {
			t.Run(mode, func(t *testing.T) {
				fixture := newSCPTransferFixture(t)
				writeSCPTestFile(t, filepath.Join(fixture.home, "src.txt"), "relay payload")

				missingTarget := filepath.Join(fixture.home, "missing-relay-target.txt")
				danglingPath := filepath.Join(fixture.home, "dangling-relay.txt")
				createSCPDanglingSymlink(t, danglingPath, missingTarget)

				options := NewScpOptions()
				options.Source = "scp-test:./src.txt"
				options.Dest = "scp-test:./dangling-relay.txt"
				options.NoOverwrite = mode == "no-clobber"
				setSCPTestConfirmation(t, "n")

				var runErr error
				captured := captureSCPOutput(t, false, func() {
					runErr = options.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
				})
				if runErr != nil {
					t.Fatalf("relay (%s) unexpected error: %v", mode, runErr)
				}
				wantPrompts := 0
				if mode == "decline" {
					wantPrompts = 1
				}
				if got := strings.Count(captured, "[y/N]"); got != wantPrompts {
					t.Fatalf("relay (%s) prompts = %d, want %d; output=%q", mode, got, wantPrompts, captured)
				}
				assertDanglingSymlinkIntact(t, danglingPath, missingTarget)
				if _, err := os.Lstat(missingTarget); !os.IsNotExist(err) {
					t.Fatalf("relay (%s) created missing symlink target %q: err=%v", mode, missingTarget, err)
				}
			})
		}
	})

	t.Run("batch_upload_default_and_no_clobber_preserve_dangling_symlink", func(t *testing.T) {
		for _, mode := range []string{"default", "no-clobber"} {
			t.Run(mode, func(t *testing.T) {
				fixture := newSCPTransferFixture(t)
				localSrc := filepath.Join(t.TempDir(), "batch.txt")
				writeSCPTestFile(t, localSrc, "batch payload")

				missingTarget := filepath.Join(fixture.home, "missing-batch-target.txt")
				danglingPath := filepath.Join(fixture.home, "dangling-batch.txt")
				createSCPDanglingSymlink(t, danglingPath, missingTarget)

				options := NewScpOptions()
				options.Source = localSrc
				options.Dest = "./dangling-batch.txt"
				options.NoOverwrite = mode == "no-clobber"
				options.Quiet = true

				if err := options.executeTransfer(fixture.ctx, "scp-test", PathInfo{Host: "scp-test"}, "", fixture.repo, fixture.connector); err != nil {
					t.Fatalf("batch upload (%s) unexpected error: %v", mode, err)
				}
				assertDanglingSymlinkIntact(t, danglingPath, missingTarget)
				if _, err := os.Lstat(missingTarget); !os.IsNotExist(err) {
					t.Fatalf("batch upload (%s) created missing symlink target %q: err=%v", mode, missingTarget, err)
				}
			})
		}
	})

	t.Run("existing_directory_symlink_resolution_still_places_file_inside", func(t *testing.T) {
		fixture := newSCPTransferFixture(t)
		localSrc := filepath.Join(t.TempDir(), "inside.txt")
		writeSCPTestFile(t, localSrc, "inside dir symlink")

		realDir := filepath.Join(fixture.home, "real-dir")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		dirLink := filepath.Join(fixture.home, "dir-link")
		createSCPDanglingSymlink(t, dirLink, realDir)

		options := NewScpOptions()
		options.Source = localSrc
		options.Dest = "scp-test:./dir-link"
		options.Quiet = true

		if err := options.runTransfer(fixture.ctx, fixture.repo, fixture.connector); err != nil {
			t.Fatalf("upload into directory symlink failed: %v", err)
		}
		assertSCPTestFile(t, filepath.Join(realDir, "inside.txt"), "inside dir symlink")
	})
}
