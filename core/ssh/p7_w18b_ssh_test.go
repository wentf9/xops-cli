package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func generateW18bTestKey(t *testing.T) cryptoSSH.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sshPub, err := cryptoSSH.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub
}

func generateW18bTestRSAKey(t *testing.T) cryptoSSH.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	sshPub, err := cryptoSSH.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey(rsa): %v", err)
	}
	return sshPub
}

func createW18bSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows without privilege: %v", err)
		}
		t.Fatalf("os.Symlink(%q, %q): %v", target, link, err)
	}
}

func TestP7W18b_C18M1_LockedKnownHostsSnapshotAndOrdering(t *testing.T) {
	t.Run("symlink_user_known_hosts_rejected_in_options_and_ignored_in_readonly_ordering", testP7W18bC18M1SymlinkRejection)
	t.Run("concurrent_append_and_options_or_readonly_lock_coordination", testP7W18bC18M1ConcurrentLockCoordination)
	t.Run("custom_user_known_hosts_missing_skipped_and_nonregular_rejected", testP7W18bC18M1CustomUserKnownHostsNoTOCTOU)
	t.Run("options_reuses_loaded_snapshot_for_algorithms", testP7W18bC18M1SingleSnapshotReuse)
}

func testP7W18bC18M1SymlinkRejection(t *testing.T) {
	dir := t.TempDir()
	realKH := filepath.Join(dir, "real_known_hosts")
	symlinkKH := filepath.Join(dir, "link_known_hosts")

	caKey := generateW18bTestKey(t)
	rsaKey := generateW18bTestRSAKey(t)
	caLine := "@cert-authority pinned.example " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(caKey))) + "\n"
	rsaLine := knownhosts.Line([]string{"rsa-only.example"}, rsaKey) + "\n"
	if err := os.WriteFile(realKH, []byte(caLine+rsaLine), 0o600); err != nil {
		t.Fatalf("write real known_hosts: %v", err)
	}
	createW18bSymlink(t, realKH, symlinkKH)

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = symlinkKH
	env.GlobalKnownHostsFiles = nil
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	// 1. Default KnownHostsFile pointing to a symlink must fail closed in getHostKeyOptionsWithState.
	defaultCfg := &ClientConfig{Address: "pinned.example", Port: 22, User: "ops"}
	if _, _, err := conn.getHostKeyOptionsWithState(t.Context(), nil, defaultCfg, nil, nil); err == nil {
		t.Fatal("getHostKeyOptionsWithState succeeded on default symlink KnownHostsFile")
	}

	// 2. Explicit UserKnownHostsFile pointing to a symlink must fail closed in getHostKeyOptionsWithState.
	customCfg := &ClientConfig{
		Address: "pinned.example",
		Port:    22,
		User:    "ops",
		Options: MustOptions(OptionUserKnownHostsFile, symlinkKH),
	}
	if _, _, err := conn.getHostKeyOptionsWithState(t.Context(), nil, customCfg, nil, nil); err == nil {
		t.Fatal("getHostKeyOptionsWithState succeeded on custom UserKnownHostsFile symlink")
	}

	// 3. Standalone loadReadOnlyKnownHostsDB / getHostKeyAlgorithms MUST NOT follow symlink user files.
	unpinnedBaseline := conn.orderKnownHostsHostKeyAlgorithmsWithDB(
		&ClientConfig{Address: "unpinned.example", Port: 22, User: "ops"},
		cryptoSSH.SupportedAlgorithms().HostKeys,
		newKnownHostsDB(),
	)
	explicitPool := []string{
		cryptoSSH.KeyAlgoED25519,
		cryptoSSH.KeyAlgoRSASHA512,
		cryptoSSH.CertAlgoED25519v01,
	}
	for _, tc := range []struct {
		name string
		cfg  *ClientConfig
	}{
		{name: "default_symlink_ca", cfg: defaultCfg},
		{name: "custom_symlink_ca", cfg: customCfg},
		{name: "custom_symlink_rsa", cfg: &ClientConfig{
			Address: "rsa-only.example",
			Port:    22,
			User:    "ops",
			Options: MustOptions(OptionUserKnownHostsFile, symlinkKH),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := conn.loadReadOnlyKnownHostsDB(tc.cfg)
			if len(db.lines) != 0 {
				t.Fatalf("loadReadOnlyKnownHostsDB followed symlinked user known_hosts: loaded %d lines", len(db.lines))
			}
			algs, err := conn.getHostKeyAlgorithms(t.Context(), nil, tc.cfg)
			if err != nil {
				t.Fatalf("getHostKeyAlgorithms: %v", err)
			}
			if !slices.Equal(algs, unpinnedBaseline) {
				t.Fatalf("getHostKeyAlgorithms = %v, want unpinned baseline %v", algs, unpinnedBaseline)
			}
			orderedPool := conn.orderKnownHostsHostKeyAlgorithms(tc.cfg, explicitPool)
			if len(orderedPool) == 0 || orderedPool[0] != cryptoSSH.KeyAlgoED25519 {
				t.Fatalf("orderKnownHostsHostKeyAlgorithms(explicitPool) = %v, want %q first (symlink ignored)", orderedPool, cryptoSSH.KeyAlgoED25519)
			}
		})
	}
}

func testP7W18bC18M1ConcurrentLockCoordination(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")

	caKey := generateW18bTestKey(t)
	rsaKey := generateW18bTestRSAKey(t)
	caLine := "@cert-authority cert.example " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(caKey))) + "\n"
	rsaLine := knownhosts.Line([]string{"rsa.example"}, rsaKey) + "\n"
	if err := os.WriteFile(khPath, []byte(caLine+rsaLine), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = khPath
	env.GlobalKnownHostsFiles = nil
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	assertP7W18bReadOnlyWaitsForExclusiveLock(t, conn, khPath)
	assertP7W18bConcurrentAppendAndRead(t, conn, khPath)
}

func assertP7W18bReadOnlyWaitsForExclusiveLock(t *testing.T, conn *Connector, khPath string) {
	t.Helper()
	lf, err := fsx.OpenLocked(khPath, fsx.LockExclusive, false, 0)
	if err != nil {
		t.Fatalf("fsx.OpenLocked(LockExclusive): %v", err)
	}
	lateKey := generateW18bTestRSAKey(t)
	lateLine := knownhosts.Line([]string{"late-rsa.example"}, lateKey) + "\n"

	readDone := make(chan *knownHostsDB, 1)
	go func() {
		readDone <- conn.loadReadOnlyKnownHostsDB(&ClientConfig{
			Address: "late-rsa.example",
			Port:    22,
			User:    "ops",
			Options: MustOptions(OptionUserKnownHostsFile, khPath),
		})
	}()

	select {
	case <-readDone:
		_ = lf.Close()
		t.Fatal("loadReadOnlyKnownHostsDB completed while LockExclusive was held")
	case <-time.After(60 * time.Millisecond):
	}

	if _, seekErr := lf.Seek(0, 2); seekErr != nil {
		_ = lf.Close()
		t.Fatalf("seek locked file: %v", seekErr)
	}
	if _, writeErr := lf.Write([]byte(lateLine)); writeErr != nil {
		_ = lf.Close()
		t.Fatalf("write locked file: %v", writeErr)
	}
	if closeErr := lf.Close(); closeErr != nil {
		t.Fatalf("close exclusive lock: %v", closeErr)
	}

	var lockedDB *knownHostsDB
	select {
	case lockedDB = <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("loadReadOnlyKnownHostsDB did not unblock after exclusive lock release")
	}
	_, pinned := lockedDB.matchingHostKeyTypes(khAddr{host: "late-rsa.example", port: "22"})
	if !slices.Contains(pinned, cryptoSSH.KeyAlgoRSA) {
		t.Fatalf("loadReadOnlyKnownHostsDB missed newly written pinned RSA entry after lock release: %v", pinned)
	}
}

func assertP7W18bConcurrentAppendAndRead(t *testing.T, conn *Connector, khPath string) {
	t.Helper()
	const (
		writers    = 4
		writesEach = 10
		readers    = 4
		readsEach  = 15
	)
	var wg sync.WaitGroup
	errCh := make(chan error, writers*writesEach+readers*readsEach*2)

	for w := range writers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range writesEach {
				host := fmt.Sprintf("w%d-h%d.example:22", id, i)
				if err := appendKnownHost(khPath, host, generateW18bTestKey(t), false); err != nil {
					errCh <- fmt.Errorf("appendKnownHost(%s): %w", host, err)
					return
				}
			}
		}(w)
	}
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			certCfg := &ClientConfig{Address: "cert.example", Port: 22, User: "ops"}
			rsaCfg := &ClientConfig{Address: "rsa.example", Port: 22, User: "ops"}
			for range readsEach {
				_, certAlgs, optErr := conn.getHostKeyOptionsWithState(t.Context(), nil, certCfg, nil, nil)
				if optErr != nil {
					errCh <- fmt.Errorf("getHostKeyOptionsWithState(cert): %w", optErr)
					return
				}
				if len(certAlgs) == 0 || !isCertAlgorithm(certAlgs[0]) {
					errCh <- fmt.Errorf("getHostKeyOptionsWithState(cert) dropped @cert-authority priority: %v", certAlgs)
					return
				}
				rsaAlgs, algErr := conn.getHostKeyAlgorithms(t.Context(), nil, rsaCfg)
				if algErr != nil {
					errCh <- fmt.Errorf("getHostKeyAlgorithms(rsa): %w", algErr)
					return
				}
				if len(rsaAlgs) == 0 || !strings.HasPrefix(rsaAlgs[0], "rsa-sha2-") {
					errCh <- fmt.Errorf("getHostKeyAlgorithms(rsa) dropped pinned RSA priority: %v", rsaAlgs)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func testP7W18bC18M1CustomUserKnownHostsNoTOCTOU(t *testing.T) {
	dir := t.TempDir()
	missingKH := filepath.Join(dir, "does_not_exist_kh")
	existingKH := filepath.Join(dir, "existing_kh")
	danglingKH := filepath.Join(dir, "dangling_kh")
	malformedKH := filepath.Join(dir, "malformed_kh")
	dirKH := filepath.Join(dir, "dir_kh")
	if err := os.Mkdir(dirKH, 0o700); err != nil {
		t.Fatal(err)
	}

	rsaKey := generateW18bTestRSAKey(t)
	if err := os.WriteFile(existingKH, []byte(knownhosts.Line([]string{"second.example"}, rsaKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(malformedKH, []byte("not-a-valid-line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = filepath.Join(dir, "default_known_hosts")
	env.GlobalKnownHostsFiles = nil
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	// 1. Missing custom UserKnownHostsFile + existing second file: skips missing cleanly without creating it.
	pairSpec := missingKH + " " + existingKH
	cfgPair := &ClientConfig{
		Address: "second.example",
		Port:    22,
		User:    "ops",
		Options: MustOptions(OptionUserKnownHostsFile, pairSpec),
	}
	primary, noWrite, cb, err := conn.openKnownHostsCallback(pairSpec, cfgPair)
	if err != nil {
		t.Fatalf("openKnownHostsCallback(missing + existing) failed: %v", err)
	}
	if primary != missingKH || noWrite {
		t.Fatalf("primary=%q noWrite=%v, want primary=%q noWrite=false", primary, noWrite, missingKH)
	}
	if _, statErr := os.Lstat(missingKH); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("openKnownHostsCallback unexpectedly created missing custom file: err=%v", statErr)
	}
	if err := cb("second.example:22", &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}, rsaKey); err != nil {
		t.Fatalf("callback failed to match entry from second custom known_hosts: %v", err)
	}

	// Standalone read-only DB must also never create missing files.
	roDB := conn.loadReadOnlyKnownHostsDB(cfgPair)
	if _, statErr := os.Lstat(missingKH); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("loadReadOnlyKnownHostsDB unexpectedly created missing custom file: err=%v", statErr)
	}
	if _, pinned := roDB.matchingHostKeyTypes(khAddr{host: "second.example", port: "22"}); !slices.Contains(pinned, cryptoSSH.KeyAlgoRSA) {
		t.Fatalf("loadReadOnlyKnownHostsDB missed second.example RSA entry: %v", pinned)
	}

	// 2. Directory must fail closed with "is a directory".
	dirCfg := &ClientConfig{
		Address: "dir.example",
		Port:    22,
		User:    "ops",
		Options: MustOptions(OptionUserKnownHostsFile, dirKH),
	}
	if _, _, err := conn.getHostKeyOptionsWithState(t.Context(), nil, dirCfg, nil, nil); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory UserKnownHostsFile err = %v, want error containing 'is a directory'", err)
	}

	// 3. Malformed custom UserKnownHostsFile must fail closed.
	badCfg := &ClientConfig{
		Address: "bad.example",
		Port:    22,
		User:    "ops",
		Options: MustOptions(OptionUserKnownHostsFile, malformedKH),
	}
	if _, _, err := conn.getHostKeyOptionsWithState(t.Context(), nil, badCfg, nil, nil); err == nil {
		t.Fatal("malformed custom UserKnownHostsFile unexpectedly succeeded")
	}

	// 4. Dangling symlink must NEVER be skipped as os.ErrNotExist — must fail closed!
	createW18bSymlink(t, filepath.Join(dir, "dangling_target"), danglingKH)
	danglingCfg := &ClientConfig{
		Address: "dangling.example",
		Port:    22,
		User:    "ops",
		Options: MustOptions(OptionUserKnownHostsFile, danglingKH),
	}
	if _, _, err := conn.getHostKeyOptionsWithState(t.Context(), nil, danglingCfg, nil, nil); err == nil {
		t.Fatal("dangling symlink UserKnownHostsFile unexpectedly succeeded instead of failing closed")
	}
}

func testP7W18bC18M1SingleSnapshotReuse(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	rsaKey := generateW18bTestRSAKey(t)
	if err := os.WriteFile(khPath, []byte(knownhosts.Line([]string{"single.example"}, rsaKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = khPath
	env.GlobalKnownHostsFiles = nil
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	cfg := &ClientConfig{
		Address: "single.example",
		Port:    22,
		User:    "ops",
		Options: MustOptions(OptionUserKnownHostsFile, khPath),
	}
	cb, algs, err := conn.getHostKeyOptionsWithState(t.Context(), nil, cfg, &atomic.Bool{}, &atomic.Bool{})
	if err != nil {
		t.Fatalf("getHostKeyOptionsWithState: %v", err)
	}
	if cb == nil {
		t.Fatal("getHostKeyOptionsWithState returned nil callback")
	}
	if len(algs) == 0 || algs[0] != cryptoSSH.KeyAlgoRSASHA512 {
		t.Fatalf("HostKeyAlgorithms = %v, want %q first", algs, cryptoSSH.KeyAlgoRSASHA512)
	}
	if err := cb("single.example:22", &net.TCPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 22}, rsaKey); err != nil {
		t.Fatalf("callback rejected pinned rsa key: %v", err)
	}
}

func TestP7W18b_C18L1_SSHProxyDialerAndAgentRouterGuards(t *testing.T) {
	t.Run("proxy_dialer_nil_and_unconnected_client_guards", testP7W18bC18L1ProxyDialerGuards)
	t.Run("connect_plan_with_synthetic_pooled_jump_nil_conn_no_panic", testP7W18bC18L1SyntheticPooledJump)
	t.Run("getOrCreateAgentRouter_rejects_nil_and_nil_conn", testP7W18bC18L1AgentRouterGuards)
}

func testP7W18bC18L1ProxyDialerGuards(t *testing.T) {
	ctx := t.Context()
	var nilDialer *SSHProxyDialer
	emptyDialer := &SSHProxyDialer{}
	unconnectedDialer := &SSHProxyDialer{Client: &cryptoSSH.Client{}}

	if nilDialer.transportClosed() || nilDialer.abortedBySelf() {
		t.Fatal("nil SSHProxyDialer reported transportClosed/abortedBySelf")
	}

	for _, tc := range []struct {
		name   string
		dialer *SSHProxyDialer
	}{
		{name: "nil_receiver", dialer: nilDialer},
		{name: "nil_client", dialer: emptyDialer},
		{name: "nil_client_conn", dialer: unconnectedDialer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if conn, err := tc.dialer.Dial("tcp", "127.0.0.1:22"); err == nil || conn != nil {
				t.Fatalf("Dial = (%v, %v), want nil conn and error", conn, err)
			}
			if conn, err := tc.dialer.DialContext(ctx, "tcp", "127.0.0.1:22"); err == nil || conn != nil {
				t.Fatalf("DialContext = (%v, %v), want nil conn and error", conn, err)
			}
			//nolint:staticcheck // intentionally verifying nil context guard
			if conn, err := tc.dialer.DialContext(nil, "tcp", "127.0.0.1:22"); err == nil || conn != nil {
				t.Fatalf("DialContext(nil) = (%v, %v), want nil conn and error", conn, err)
			}
		})
	}

	// Verify DialContext rejects nil ctx even when Client.Conn is non-nil.
	connectedLike := &SSHProxyDialer{Client: &cryptoSSH.Client{Conn: &monitoredTestConn{closed: make(chan struct{}), probeSeen: make(chan struct{})}}}
	//nolint:staticcheck // intentionally verifying nil context guard
	if conn, err := connectedLike.DialContext(nil, "tcp", "127.0.0.1:22"); err == nil || conn != nil {
		t.Fatalf("DialContext(nil) on connected-like client = (%v, %v), want nil conn and error", conn, err)
	}

	// Verify wrapChanConn fallback abort callback does not panic when Client.Conn == nil or receiver is nil.
	for _, tc := range []struct {
		name   string
		dialer *SSHProxyDialer
	}{
		{name: "nil_receiver", dialer: nilDialer},
		{name: "nil_client_conn", dialer: &SSHProxyDialer{Client: &cryptoSSH.Client{}}},
	} {
		c1, c2 := net.Pipe()
		wrapped := tc.dialer.wrapChanConn(c1)
		pcc, ok := wrapped.(*proxyChanConn)
		if !ok {
			_ = c1.Close()
			_ = c2.Close()
			t.Fatalf("%s: wrapChanConn did not return *proxyChanConn", tc.name)
		}
		if err := pcc.abortUpstream(wrapped); err != nil {
			t.Fatalf("%s: abortUpstream returned unexpected error: %v", tc.name, err)
		}
		_ = c1.Close()
		_ = c2.Close()
	}
}

func testP7W18bC18L1SyntheticPooledJump(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(khPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	bastionCfg := &ClientConfig{
		NodeID:   "bastion",
		Address:  "127.0.0.1",
		Port:     2200,
		User:     "jump",
		AuthType: "password",
		Password: "secret",
	}
	targetCfg := &ClientConfig{
		NodeID:    "app",
		Address:   "127.0.0.1",
		Port:      2201,
		User:      "ops",
		AuthType:  "password",
		Password:  "secret",
		ProxyJump: "bastion",
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = khPath
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	// Pre-populate a synthetic pooled bastion entry whose SSHClient has Conn == nil.
	plan := []connectionPlanNode{
		{name: "app", cfg: targetCfg},
		{name: "bastion", cfg: bastionCfg},
	}
	assignPlanDigests(plan)
	if _, err := conn.pool.Publish(plan[1].digest, &PooledClient{SSHClient: &cryptoSSH.Client{}}, nil, nil); err != nil {
		t.Fatalf("pool.Publish(bastion): %v", err)
	}

	if _, err := conn.connectPlan(t.Context(), plan); err == nil {
		t.Fatal("connectPlan via synthetic pooled jump with Conn == nil unexpectedly succeeded")
	}
}

func testP7W18bC18L1AgentRouterGuards(t *testing.T) {
	if r, err := getOrCreateAgentRouter(nil); err == nil || r != nil {
		t.Fatalf("getOrCreateAgentRouter(nil) = (%v, %v), want nil and error", r, err)
	}
	if r, err := getOrCreateAgentRouter(&cryptoSSH.Client{}); err == nil || r != nil {
		t.Fatalf("getOrCreateAgentRouter(&Client{}) = (%v, %v), want nil and error", r, err)
	}
}
