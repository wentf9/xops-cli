package config

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

type countingRepeatReader struct {
	remaining int64
	readTotal int64
	pattern   []byte
	offset    int
}

func (r *countingRepeatReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.remaining)
	for i := range n {
		p[i] = r.pattern[r.offset]
		r.offset = (r.offset + 1) % len(r.pattern)
	}
	r.remaining -= n
	r.readTotal += n
	return int(n), nil
}

func writeDepthChain(t *testing.T, dir, relPrefix, hostPrefix, ipPrefix string, count int, tailInclude string) {
	t.Helper()
	for i := 1; i <= count; i++ {
		var sb strings.Builder
		if i < count {
			sb.WriteString("Include " + relPrefix + "/d" + twoDigit(i+1) + ".conf\n")
		} else if tailInclude != "" {
			sb.WriteString("Include " + tailInclude + "\n")
		}
		sb.WriteString("Host " + hostPrefix + twoDigit(i) + "\n    HostName " + ipPrefix + strconv.Itoa(i) + "\n")
		writeSSHTestFile(t, filepath.Join(dir, "d"+twoDigit(i)+".conf"), sb.String())
	}
}

func TestP5_OpenSSHIncludeFailClosedDepthBoundary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	sshDir := filepath.Join(home, ".ssh")
	okDir := filepath.Join(sshDir, "depth_ok")
	badDir := filepath.Join(sshDir, "depth_bad")
	emptyPatDir := filepath.Join(sshDir, "depth_nonexistent")
	for _, d := range []string{okDir, badDir, emptyPatDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	writeDepthChain(t, okDir, "depth_ok", "ok-depth-", "10.10.0.", maxIncludeDepth, "")
	okRoot := filepath.Join(sshDir, "config_ok")
	writeSSHTestFile(t, okRoot, "Include depth_ok/d01.conf\n")
	parser, err := NewOpenSSHParserFromPath(okRoot)
	if err != nil {
		t.Fatalf("depth == maxIncludeDepth (%d) should succeed, got error = %v", maxIncludeDepth, err)
	}
	if !parser.HasHost("ok-depth-16") {
		t.Fatal("expected ok-depth-16 to be parsed at exact maxIncludeDepth boundary")
	}

	writeDepthChain(t, badDir, "depth_bad", "bad-depth-", "10.11.0.", maxIncludeDepth+1, "")
	badRoot := filepath.Join(sshDir, "config_bad")
	writeSSHTestFile(t, badRoot, "Include depth_bad/d01.conf\n")
	if _, err := NewOpenSSHParserFromPath(badRoot); err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("depth == maxIncludeDepth+1 should fail closed with depth limit error, got %v", err)
	}

	writeDepthChain(t, emptyPatDir, "depth_nonexistent", "ne-depth-", "10.12.0.", maxIncludeDepth, "depth_nonexistent/missing-*.conf")
	neRoot := filepath.Join(sshDir, "config_ne")
	writeSSHTestFile(t, neRoot, "Include depth_nonexistent/d01.conf\n")
	if _, err := NewOpenSSHParserFromPath(neRoot); err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("Include at depth == maxIncludeDepth with missing pattern should fail closed, got %v", err)
	}
}

func TestP5_OpenSSHConfigSizeBudgets(t *testing.T) {
	t.Run("stream_reader_enforces_per_file_limit_without_unbounded_read", testP5OpenSSHStreamSizeLimit)
	t.Run("root_and_included_file_size_limit", testP5OpenSSHFileSizeLimits)
	t.Run("total_bytes_budget_across_included_files", testP5OpenSSHTotalSizeBudget)
}

func testP5OpenSSHStreamSizeLimit(t *testing.T) {
	overReader := &countingRepeatReader{
		remaining: maxOpenSSHConfigFileBytes + 1024*1024,
		pattern:   []byte("#\n"),
	}
	_, err := NewOpenSSHParserFromReader(overReader)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected size limit error for >16MiB stream, got %v", err)
	}
	if overReader.readTotal > maxOpenSSHConfigFileBytes+1 {
		t.Fatalf("reader was not bounded by io.LimitReader: read %d bytes (limit+1=%d)", overReader.readTotal, maxOpenSSHConfigFileBytes+1)
	}
}

func createTruncatedFile(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func testP5OpenSSHFileSizeLimits(t *testing.T) {
	dir := t.TempDir()
	overRoot := filepath.Join(dir, "over_root.conf")
	createTruncatedFile(t, overRoot, maxOpenSSHConfigFileBytes+1)
	if _, err := NewOpenSSHParserFromPath(overRoot); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected root file >16MiB to fail with size limit, got %v", err)
	}

	overInc := filepath.Join(dir, "over_inc.conf")
	createTruncatedFile(t, overInc, maxOpenSSHConfigFileBytes+1)
	rootWithOverInc := filepath.Join(dir, "root_over_inc.conf")
	writeSSHTestFile(t, rootWithOverInc, "Include "+overInc+"\n")
	if _, err := NewOpenSSHParserFromPath(rootWithOverInc); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected included file >16MiB to fail with size limit, got %v", err)
	}
}

func testP5OpenSSHTotalSizeBudget(t *testing.T) {
	dir := t.TempDir()
	chunk := append([]byte("#"), bytes.Repeat([]byte("a"), maxOpenSSHConfigFileBytes-2)...)
	chunk = append(chunk, '\n')

	var incLines strings.Builder
	for i := range 4 {
		p := filepath.Join(dir, "chunk_"+strconv.Itoa(i)+".conf")
		if err := os.WriteFile(p, chunk, 0o600); err != nil {
			t.Fatal(err)
		}
		incLines.WriteString("Include " + p + "\n")
	}
	rootOverTotal := filepath.Join(dir, "root_over_total.conf")
	writeSSHTestFile(t, rootOverTotal, incLines.String())
	if _, err := NewOpenSSHParserFromPath(rootOverTotal); err == nil || !strings.Contains(err.Error(), "total size limit") {
		t.Fatalf("expected total size limit error when root+includes > 64MiB, got %v", err)
	}

	tailPath := filepath.Join(dir, "tail_exact.conf")
	rootContent := "Include " + filepath.Join(dir, "chunk_0.conf") + "\n" +
		"Include " + filepath.Join(dir, "chunk_1.conf") + "\n" +
		"Include " + filepath.Join(dir, "chunk_2.conf") + "\n" +
		"Include " + tailPath + "\n" +
		"Host exact-budget\n    HostName 10.22.0.1\n"
	tailLen := maxOpenSSHConfigTotalBytes - len(rootContent) - 3*maxOpenSSHConfigFileBytes
	tailData := append([]byte("#"), bytes.Repeat([]byte("b"), tailLen-2)...)
	tailData = append(tailData, '\n')
	if err := os.WriteFile(tailPath, tailData, 0o600); err != nil {
		t.Fatal(err)
	}
	rootExact := filepath.Join(dir, "root_exact.conf")
	writeSSHTestFile(t, rootExact, rootContent)
	parser, err := NewOpenSSHParserFromPath(rootExact)
	if err != nil {
		t.Fatalf("exact 64MiB total budget should succeed, got %v", err)
	}
	if !parser.HasHost("exact-budget") {
		t.Fatal("expected exact-budget host to be parsed")
	}
}

func TestP5_OpenSSHRootNonRegularFilesAndDevNull(t *testing.T) {
	baseParser, err := NewOpenSSHParserFromReader(strings.NewReader("Host base-host\n  HostName 10.1.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	base := NewProviderWithOpenSSHParser(nil, baseParser)

	t.Run("os_DevNull_allowed_as_empty_noop_root", func(t *testing.T) {
		assertP5DevNullAccepted(t, base, os.DevNull)
	})
	t.Run("directory_rejected", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := NewOpenSSHParserFromPath(dir); err == nil || !strings.Contains(err.Error(), "directory") {
			t.Fatalf("NewOpenSSHParserFromPath(dir) = %v, want directory error", err)
		}
		if _, err := WithOpenSSHConfigOverride(base, dir); err == nil || !strings.Contains(err.Error(), "directory") {
			t.Fatalf("WithOpenSSHConfigOverride(dir) = %v, want directory error", err)
		}
	})
	if runtime.GOOS == "windows" {
		return
	}
	t.Run("unix_non_regular_devices_and_symlinks", func(t *testing.T) {
		testP5UnixNonRegularDevicesAndSymlinks(t, base)
	})
	t.Run("unix_socket_and_fifo_rejected", func(t *testing.T) {
		testP5UnixSocketAndFIFORejected(t, base)
	})
}

func assertP5DevNullAccepted(t *testing.T, base ConfigProvider, path string) {
	t.Helper()
	parser, err := NewOpenSSHParserFromPath(path)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath(%q) error = %v", path, err)
	}
	if parser == nil || parser.HasHost("anything") {
		t.Fatalf("expected empty parser for %q", path)
	}
	ov, err := WithOpenSSHConfigOverride(base, path)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride(%q) error = %v", path, err)
	}
	if ov.Find("base-host") != "" {
		t.Fatalf("WithOpenSSHConfigOverride(%q) should skip base OpenSSH hosts", path)
	}
}

func assertP5RootRejectedNonRegular(t *testing.T, base ConfigProvider, path string) {
	t.Helper()
	if _, err := NewOpenSSHParserFromPath(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("NewOpenSSHParserFromPath(%q) = %v, want not a regular file", path, err)
	}
	if _, err := WithOpenSSHConfigOverride(base, path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("WithOpenSSHConfigOverride(%q) = %v, want not a regular file", path, err)
	}
}

func testP5UnixNonRegularDevicesAndSymlinks(t *testing.T, base ConfigProvider) {
	dir := t.TempDir()
	assertP5RootRejectedNonRegular(t, base, "/dev/zero")

	zeroLink := filepath.Join(dir, "zero_link")
	if err := os.Symlink("/dev/zero", zeroLink); err != nil {
		t.Fatal(err)
	}
	assertP5RootRejectedNonRegular(t, base, zeroLink)

	nullLink := filepath.Join(dir, "null_link")
	if err := os.Symlink(os.DevNull, nullLink); err != nil {
		t.Fatal(err)
	}
	assertP5DevNullAccepted(t, base, nullLink)

	regTarget := filepath.Join(dir, "real.conf")
	writeSSHTestFile(t, regTarget, "Host sym-ok\n  HostName 10.2.0.1\n")
	regLink := filepath.Join(dir, "real_link.conf")
	if err := os.Symlink(regTarget, regLink); err != nil {
		t.Fatal(err)
	}
	if p, err := NewOpenSSHParserFromPath(regLink); err != nil || !p.HasHost("sym-ok") {
		t.Fatalf("NewOpenSSHParserFromPath(symlink->regular) = (%v, %v), want sym-ok", p, err)
	}
}

func testP5UnixSocketAndFIFORejected(t *testing.T, base ConfigProvider) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "cfg.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen(unix): %v", err)
	}
	defer func() { _ = ln.Close() }()
	assertP5RootRejectedNonRegular(t, base, sockPath)

	mkfifoPath, err := exec.LookPath("mkfifo")
	if err != nil || mkfifoPath == "" {
		return
	}
	fifoPath := filepath.Join(dir, "root.fifo")
	if out, mkErr := exec.CommandContext(t.Context(), mkfifoPath, fifoPath).CombinedOutput(); mkErr != nil {
		t.Fatalf("mkfifo failed: %v (%s)", mkErr, string(out))
	}
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{name: "NewOpenSSHParserFromPath", fn: func() error { _, err := NewOpenSSHParserFromPath(fifoPath); return err }},
		{name: "WithOpenSSHConfigOverride", fn: func() error { _, err := WithOpenSSHConfigOverride(base, fifoPath); return err }},
	} {
		done := make(chan error, 1)
		go func() { done <- tc.fn() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("%s(FIFO) = %v, want not a regular file", tc.name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s(FIFO) blocked instead of rejecting non-regular root file", tc.name)
		}
	}
}

func newP5SharedIdentityRepo(t *testing.T, idName string, ident models.Identity) *Repository {
	t.Helper()
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "cfg.yaml"), filepath.Join(dir, "cfg.key"))
	cfg := cloneConfiguration(nil)
	cfg.SchemaVersion = 2
	cfg.Hosts.Set("h-a", models.Host{Address: "10.30.0.1", Port: 22})
	cfg.Hosts.Set("h-b", models.Host{Address: "10.30.0.2", Port: 22})
	cfg.Identities.Set(idName, cloneIdentity(ident))
	cfg.Nodes.Set("node-a", models.Node{HostRef: "h-a", IdentityRef: idName})
	cfg.Nodes.Set("node-b", models.Node{HostRef: "h-b", IdentityRef: idName})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	return repo
}

func makeP5SharedMFAIdentity() models.Identity {
	return models.Identity{
		User:     "ops",
		AuthType: "keyboard-interactive",
		OTP: &models.OTPConfig{
			TOTPSecretRef: &credential.Ref{StoreID: "file", ItemID: "totp-orig"},
			Args:          []string{"--orig"},
			PromptPattern: "OTP:",
		},
		KeyboardInteractive: &models.KeyboardInteractiveConfig{
			Rules: []models.ChallengeRule{
				{
					Name:          "mfa-rule",
					PromptPattern: "Code:",
					Source:        models.ChallengeSourceSecret,
					SecretRef:     &credential.Ref{StoreID: "file", ItemID: "kbi-orig"},
					Args:          []string{"--arg"},
				},
			},
		},
	}
}

func TestP5_SharedIdentityForkDeepClonesOTPAndKeyboardInteractive(t *testing.T) {
	t.Parallel()
	t.Run("rotating_TOTP_on_shared_identity_does_not_mutate_sibling_node", testP5SharedIdentityForkTOTP)
	t.Run("rotating_and_deleting_KeyboardInteractive_rule_does_not_mutate_sibling_node", testP5SharedIdentityForkKBI)
	t.Run("UpdateAuthAtVersionContext_fork_deep_clones_nested_pointers", testP5SharedIdentityForkLegacyAuth)
}

func testP5SharedIdentityForkTOTP(t *testing.T) {
	repo := newP5SharedIdentityRepo(t, "shared-otp", makeP5SharedMFAIdentity())
	snapA, err := repo.ResolveConnection("node-a")
	if err != nil {
		t.Fatal(err)
	}
	newRef := &credential.Ref{StoreID: "file", ItemID: "totp-rotated"}
	_, _, err = repo.UpdateNodeCredentialRefAtVersionContext(
		t.Context(), "node-a", string(snapA.UpdateRef.AuthVersion[:]), credential.KindTOTPSecret, newRef,
	)
	if err != nil {
		t.Fatalf("UpdateNodeCredentialRefAtVersionContext(TOTP): %v", err)
	}

	nodeA, _, identA, err := repo.Resolve("node-a")
	if err != nil {
		t.Fatal(err)
	}
	nodeB, _, identB, err := repo.Resolve("node-b")
	if err != nil {
		t.Fatal(err)
	}
	if nodeA.IdentityRef == nodeB.IdentityRef {
		t.Fatalf("expected node-a to fork private IdentityRef, both still %q", nodeA.IdentityRef)
	}
	if identA.OTP == nil || identA.OTP.TOTPSecretRef == nil || identA.OTP.TOTPSecretRef.ItemID != "totp-rotated" {
		t.Fatalf("node-a OTP = %+v, want totp-rotated", identA.OTP)
	}
	if identB.OTP == nil || identB.OTP.TOTPSecretRef == nil || identB.OTP.TOTPSecretRef.ItemID != "totp-orig" {
		t.Fatalf("sibling node-b OTP was mutated in place! got %+v, want totp-orig", identB.OTP)
	}
}

func testP5SharedIdentityForkKBI(t *testing.T) {
	repo := newP5SharedIdentityRepo(t, "shared-kbi", makeP5SharedMFAIdentity())
	snapA, err := repo.ResolveConnection("node-a")
	if err != nil {
		t.Fatal(err)
	}
	newRef := &credential.Ref{StoreID: "file", ItemID: "kbi-rotated"}
	_, nextVer, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(
		t.Context(),
		credential.Target{NodeID: "node-a", Kind: credential.KindChallengeAnswer, RuleName: "mfa-rule"},
		string(snapA.UpdateRef.AuthVersion[:]),
		newRef,
	)
	if err != nil {
		t.Fatalf("ApplyCredentialRefAtVersion(ChallengeAnswer rotate): %v", err)
	}

	_, _, identA, err := repo.Resolve("node-a")
	if err != nil {
		t.Fatal(err)
	}
	_, _, identB, err := repo.Resolve("node-b")
	if err != nil {
		t.Fatal(err)
	}
	if identA.KeyboardInteractive == nil || len(identA.KeyboardInteractive.Rules) != 1 || identA.KeyboardInteractive.Rules[0].SecretRef.ItemID != "kbi-rotated" {
		t.Fatalf("node-a KBI = %+v, want kbi-rotated", identA.KeyboardInteractive)
	}
	if identB.KeyboardInteractive == nil || len(identB.KeyboardInteractive.Rules) != 1 || identB.KeyboardInteractive.Rules[0].SecretRef.ItemID != "kbi-orig" {
		t.Fatalf("sibling node-b KBI was mutated in place! got %+v, want kbi-orig", identB.KeyboardInteractive)
	}

	if _, _, err := repo.AsConfigUpdater().ApplyCredentialRefAtVersion(
		t.Context(),
		credential.Target{NodeID: "node-a", Kind: credential.KindChallengeAnswer, RuleName: "mfa-rule"},
		nextVer,
		nil,
	); err != nil {
		t.Fatalf("ApplyCredentialRefAtVersion(ChallengeAnswer clear): %v", err)
	}
	_, _, identBAfterDel, err := repo.Resolve("node-b")
	if err != nil {
		t.Fatal(err)
	}
	if identBAfterDel.KeyboardInteractive == nil || len(identBAfterDel.KeyboardInteractive.Rules) != 1 || identBAfterDel.KeyboardInteractive.Rules[0].SecretRef.ItemID != "kbi-orig" {
		t.Fatalf("sibling node-b KBI affected by rule deletion on node-a: %+v", identBAfterDel.KeyboardInteractive)
	}
}

func testP5SharedIdentityForkLegacyAuth(t *testing.T) {
	cfg := cloneConfiguration(nil)
	cfg.SchemaVersion = 1
	cfg.Hosts.Set("h-a", models.Host{Address: "10.30.0.1", Port: 22})
	cfg.Hosts.Set("h-b", models.Host{Address: "10.30.0.2", Port: 22})
	cfg.Identities.Set("shared-legacy", makeP5SharedMFAIdentity())
	cfg.Nodes.Set("node-a", models.Node{HostRef: "h-a", IdentityRef: "shared-legacy"})
	cfg.Nodes.Set("node-b", models.Node{HostRef: "h-b", IdentityRef: "shared-legacy"})
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	snapA, err := repo.ResolveConnection("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateAuthAtVersionContext(
		t.Context(), "node-a", string(snapA.UpdateRef.AuthVersion[:]), "discovered-pw", "", "",
	); err != nil {
		t.Fatalf("UpdateAuthAtVersionContext: %v", err)
	}
	liveA, _ := repo.provider.cfg.Nodes.Get("node-a")
	liveB, _ := repo.provider.cfg.Nodes.Get("node-b")
	idA, _ := repo.provider.cfg.Identities.Get(liveA.IdentityRef)
	idB, _ := repo.provider.cfg.Identities.Get(liveB.IdentityRef)
	if idA.OTP == idB.OTP {
		t.Fatal("forked identity shares OTP pointer with sibling identity")
	}
	if idA.KeyboardInteractive == idB.KeyboardInteractive {
		t.Fatal("forked identity shares KeyboardInteractive pointer with sibling identity")
	}
}
