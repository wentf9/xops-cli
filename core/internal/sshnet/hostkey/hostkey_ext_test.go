package hostkey_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// 编译期断言 *hostkey.KnownHostsDB 完整实现 ports.HostTrustPort 契约。
var _ ports.HostTrustPort = (*hostkey.KnownHostsDB)(nil)

func newTestDB(t *testing.T, mutate func(*hostkey.Config)) (*hostkey.KnownHostsDB, pathalg.LocalDir) {
	t.Helper()
	base, err := pathalg.ParseLocalDir(t.TempDir())
	if err != nil {
		t.Fatalf("ParseLocalDir 失败: %v", err)
	}
	dir, err := base.JoinComponent("ssh")
	if err != nil {
		t.Fatalf("JoinComponent(ssh) 失败: %v", err)
	}
	rootFS := osfs.NewScopedRootFS()
	if err := rootFS.EnsureRoot(dir, 0o700); err != nil {
		t.Fatalf("EnsureRoot 失败: %v", err)
	}
	cfg := hostkey.Config{
		RootFS:     rootFS,
		DefaultDir: dir,
		HomeDir:    algebraic.Some(dir),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	db, err := hostkey.NewKnownHostsDB(cfg)
	if err != nil {
		t.Fatalf("NewKnownHostsDB 失败: %v", err)
	}
	return db, dir
}

func makeRealBlobKey(t *testing.T, algo string, payload []byte, comment string) ports.PublicKeyInfo {
	t.Helper()
	fp := inventory.KeyFingerprintFromSHA256(sha256.Sum256(payload))
	pk, err := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm:   algo,
		Fingerprint: fp,
		WireBlob:    payload,
		Comment:     comment,
	})
	if err != nil {
		t.Fatalf("NewPublicKeyInfo 失败: %v", err)
	}
	return pk
}

func writeRawKnownHosts(t *testing.T, dir pathalg.LocalDir, name, content string) {
	t.Helper()
	dest, err := pathalg.ParseLocalRootedDest(name)
	if err != nil {
		t.Fatalf("ParseLocalRootedDest(%q) 失败: %v", name, err)
	}
	err = osfs.NewScopedRootFS().WithRoot(dir, func(root ports.RootHandle) error {
		return root.AtomicReplace(dest, 0o600, func(w io.Writer) error {
			_, wErr := io.WriteString(w, content)
			return wErr
		})
	})
	if err != nil {
		t.Fatalf("写入 known_hosts 夹具失败: %v", err)
	}
}

func TestKnownHostsDB_TCKSuite(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("DefaultUnsetKnownHostsList", func(t *testing.T) {
		tck.RunHostTrustSuite(t, tck.HostTrustFixture{
			NewTrust: func(t *testing.T) ports.HostTrustPort {
				db, _ := newTestDB(t, nil)
				return db
			},
			KnownHosts: option.UnsetKnownHostsList(),
		})
	})
	t.Run("ExplicitUserKnownHostsFile", func(t *testing.T) {
		kh, err := option.ParseKnownHostsList([]string{"~/custom_known_hosts"})
		if err != nil {
			t.Fatalf("ParseKnownHostsList 失败: %v", err)
		}
		tck.RunHostTrustSuite(t, tck.HostTrustFixture{
			NewTrust: func(t *testing.T) ports.HostTrustPort {
				db, _ := newTestDB(t, nil)
				return db
			},
			KnownHosts: kh,
		})
	})
}

func TestKnownHostsDB_ValidationAndZeroFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zeroDB hostkey.KnownHostsDB
	ep := tck.MustEndpoint(t, "zero.example.test", 22)
	key := makeRealBlobKey(t, "ssh-ed25519", []byte("zero-key-wire-blob"), "")
	req, err := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: key, Mode: option.StrictHostKeyCheckingYes,
	})
	if err != nil {
		t.Fatalf("NewHostTrustRequest 失败: %v", err)
	}
	if _, err := zeroDB.VerifyHostKey(context.Background(), req); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 KnownHostsDB.VerifyHostKey 必须返回 ErrInvalidArgument，实际 %v", err)
	}
	if _, err := zeroDB.PreferredAlgorithms(context.Background(), ep, option.UnsetKnownHostsList()); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 PreferredAlgorithms 必须返回 ErrInvalidArgument，实际 %v", err)
	}
	if err := zeroDB.RecordHostKey(context.Background(), ep, key, option.UnsetKnownHostsList()); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 RecordHostKey 必须返回 ErrInvalidArgument，实际 %v", err)
	}
	dir, _ := pathalg.ParseLocalDir(t.TempDir())
	if _, err := hostkey.NewKnownHostsDB(hostkey.Config{DefaultDir: dir}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("nil RootFS 必须拒绝，实际 %v", err)
	}
	if _, err := hostkey.NewKnownHostsDB(hostkey.Config{RootFS: osfs.NewScopedRootFS(), DefaultDir: dir, HashHostnames: true}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("启用 HashHostnames 且缺少 Entropy 必须拒绝，实际 %v", err)
	}
}

func TestKnownHostsDB_HashedRevokedWildcardsAndIPv6Isolation(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	db, dir := newTestDB(t, func(cfg *hostkey.Config) {
		cfg.HashHostnames = true
		cfg.Entropy = tck.NewDeterministicEntropy(42)
	})

	// 1. 验证 HashHostnames=true 写入 |1|<salt>|<hmac-sha1> 并按端口严格隔离（含 IPv6）。
	epIPv6Def := tck.MustEndpoint(t, "2001:db8::1", 22)
	epIPv6Alt := tck.MustEndpoint(t, "2001:db8::1", 2222)
	key1 := makeRealBlobKey(t, "ssh-ed25519", []byte("ed25519-ipv6-22-blob"), "ipv6-default")
	key2 := makeRealBlobKey(t, "ecdsa-sha2-nistp256", []byte("ecdsa-ipv6-2222-blob"), "")

	if err := db.RecordHostKey(ctx, epIPv6Def, key1, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey(ipv6:22) 失败: %v", err)
	}
	// 幂等重复记录不得重复写入行。
	if err := db.RecordHostKey(ctx, epIPv6Def, key1, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("重复 RecordHostKey 失败: %v", err)
	}
	if err := db.RecordHostKey(ctx, epIPv6Alt, key2, option.UnsetKnownHostsList()); err != nil {
		t.Fatalf("RecordHostKey(ipv6:2222) 失败: %v", err)
	}

	dest, _ := pathalg.ParseLocalRootedDest("known_hosts")
	lim, _ := ports.NewReadLimits(1 << 20)
	var rawFile []byte
	if err := osfs.NewScopedRootFS().WithRoot(dir, func(root ports.RootHandle) error {
		var rErr error
		rawFile, rErr = root.ReadAllBounded(dest, lim)
		return rErr
	}); err != nil {
		t.Fatalf("读取落盘 known_hosts 失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(rawFile)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "|1|") || !strings.HasPrefix(lines[1], "|1|") {
		t.Fatalf("期望 2 行哈希 known_hosts 记录且无重复，实际:\n%s", string(rawFile))
	}

	verifyStatus := func(ep netaddr.Endpoint, key ports.PublicKeyInfo, want ports.HostTrustStatus) {
		t.Helper()
		req, err := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
			Endpoint: ep, Presented: key, Mode: option.StrictHostKeyCheckingYes,
		})
		if err != nil {
			t.Fatalf("NewHostTrustRequest 失败: %v", err)
		}
		chk, err := db.VerifyHostKey(ctx, req)
		if err != nil {
			t.Fatalf("VerifyHostKey 失败: %v", err)
		}
		if chk.Status() != want {
			t.Fatalf("VerifyHostKey(%s) status=%s, want %s (reason=%q)", ep, chk.Status(), want, chk.Reason())
		}
	}
	verifyStatus(epIPv6Def, key1, ports.HostTrustTrusted)
	verifyStatus(epIPv6Alt, key2, ports.HostTrustTrusted)
	verifyStatus(epIPv6Def, key2, ports.HostTrustMismatch)
	verifyStatus(epIPv6Alt, key1, ports.HostTrustMismatch)

	// 2. 验证 @revoked 优先于已信任记录、@cert-authority 不误判、通配与 ! 否定模式及 [host]:22 兼容。
	salt := []byte("01234567890123456789")
	mac := hmac.New(sha1.New, salt)
	_, _ = mac.Write([]byte("revoked.example.test"))
	hashedRevokedHost := fmt.Sprintf("|1|%s|%s", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	keyRev := makeRealBlobKey(t, "ssh-ed25519", []byte("revoked-key-blob"), "")
	keyWild := makeRealBlobKey(t, "ssh-ed25519", []byte("wild-key-blob"), "")
	keyCA := makeRealBlobKey(t, "ssh-ed25519", []byte("ca-key-blob"), "")
	b64 := base64.StdEncoding.EncodeToString
	fixture := strings.Join([]string{
		"# comment line",
		"malformed-line-ignored",
		"@unknown-marker host.test ssh-ed25519 " + b64(keyWild.WireBlob()),
		"@cert-authority *.example.test ssh-ed25519 " + b64(keyCA.WireBlob()),
		"revoked.example.test ssh-ed25519 " + b64(keyRev.WireBlob()),
		"@revoked " + hashedRevokedHost + " ssh-ed25519 " + b64(keyRev.WireBlob()),
		"*.wild.test,!deny.wild.test ssh-ed25519 " + b64(keyWild.WireBlob()),
		"[explicit22.test]:22 ssh-ed25519 " + b64(keyWild.WireBlob()),
	}, "\n") + "\n"
	writeRawKnownHosts(t, dir, "known_hosts", fixture)

	verifyStatus(tck.MustEndpoint(t, "revoked.example.test", 22), keyRev, ports.HostTrustRevoked)
	verifyStatus(tck.MustEndpoint(t, "app.wild.test", 22), keyWild, ports.HostTrustTrusted)
	verifyStatus(tck.MustEndpoint(t, "deny.wild.test", 22), keyWild, ports.HostTrustUnknown)
	verifyStatus(tck.MustEndpoint(t, "explicit22.test", 22), keyWild, ports.HostTrustTrusted)
	verifyStatus(tck.MustEndpoint(t, "explicit22.test", 2222), keyWild, ports.HostTrustUnknown)
	verifyStatus(tck.MustEndpoint(t, "ca-only.example.test", 22), keyCA, ports.HostTrustUnknown)

	// PreferredAlgorithms 不得包含同时被标记为 @revoked 的密钥算法（评审 #31 m1）。
	revAlgos, err := db.PreferredAlgorithms(ctx, tck.MustEndpoint(t, "revoked.example.test", 22), option.UnsetKnownHostsList())
	if err != nil {
		t.Fatalf("PreferredAlgorithms(revoked): %v", err)
	}
	if slices.Contains(revAlgos, keyRev.Algorithm()) {
		t.Fatalf("被 @revoked 吊销的密钥算法 %q 不应出现在 PreferredAlgorithms 中，实际 %v", keyRev.Algorithm(), revAlgos)
	}
	assertRevokedCAExcludedFromPreferredAlgos(t, ctx, db, dir, keyCA, keyWild)
}

func assertRevokedCAExcludedFromPreferredAlgos(
	t *testing.T,
	ctx context.Context,
	db *hostkey.KnownHostsDB,
	dir pathalg.LocalDir,
	keyCA, keyWild ports.PublicKeyInfo,
) {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString
	// 若 @cert-authority 公钥本身被 @revoked 吊销，PreferredAlgorithms 亦不得继续优先协商证书算法（评审 #45 [n1]）。
	revCAFixture := strings.Join([]string{
		"@cert-authority revoked-ca.test ssh-ed25519 " + b64(keyCA.WireBlob()),
		"@revoked revoked-ca.test ssh-ed25519 " + b64(keyCA.WireBlob()),
		"revoked-ca.test ssh-ed25519 " + b64(keyWild.WireBlob()),
	}, "\n") + "\n"
	writeRawKnownHosts(t, dir, "known_hosts_revca", revCAFixture)
	khRevCA, _ := option.ParseKnownHostsList([]string{dir.String() + "/known_hosts_revca"})
	caAlgos, err := db.PreferredAlgorithms(ctx, tck.MustEndpoint(t, "revoked-ca.test", 22), khRevCA)
	if err != nil {
		t.Fatalf("PreferredAlgorithms(revoked-ca): %v", err)
	}
	if !slices.Equal(caAlgos, []string{"ssh-ed25519"}) {
		t.Fatalf("吊销的 @cert-authority 不得输出证书算法，期望 [ssh-ed25519]，实际 %v", caAlgos)
	}
}

func TestKnownHostsDB_HomeDirPercentDoesNotCorruptTildeTemplate(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	base, err := pathalg.ParseLocalDir(t.TempDir())
	if err != nil {
		t.Fatalf("ParseLocalDir: %v", err)
	}
	// HomeDir 含字面 '%' 字符：先展开 %h 再展开 ~/，严禁将 HomeDir 中的 % 误当作令牌解析（评审 #31 m2）。
	homeWithPct, err := base.JoinComponent("home100%ops")
	if err != nil {
		t.Fatalf("JoinComponent: %v", err)
	}
	if err := osfs.NewScopedRootFS().EnsureRoot(homeWithPct, 0o700); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	db, err := hostkey.NewKnownHostsDB(hostkey.Config{
		RootFS:     osfs.NewScopedRootFS(),
		DefaultDir: homeWithPct,
		HomeDir:    algebraic.Some(homeWithPct),
	})
	if err != nil {
		t.Fatalf("NewKnownHostsDB: %v", err)
	}
	ep := tck.MustEndpoint(t, "pct.example.test", 22)
	key := makeRealBlobKey(t, "ssh-ed25519", []byte{7, 8, 9, 10}, "")
	writeRawKnownHosts(t, homeWithPct, "kh_pct.example.test", "pct.example.test "+key.Algorithm()+" "+base64.StdEncoding.EncodeToString(key.WireBlob())+"\n")
	khList, err := option.ParseKnownHostsList([]string{"~/kh_%h"})
	if err != nil {
		t.Fatalf("ParseKnownHostsList: %v", err)
	}
	req, _ := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: key, Mode: option.StrictHostKeyCheckingYes, KnownHosts: khList,
	})
	chk, err := db.VerifyHostKey(ctx, req)
	if err != nil || chk.Status() != ports.HostTrustTrusted {
		t.Fatalf("含 %% 的 HomeDir 展开 ~/kh_%%h 须成功信任，实际 status=%s err=%v", chk.Status(), err)
	}
}

func TestKnownHostsDB_SymlinkRejectedAndDisabledListAndSSHFP(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	sshfp := sim.NewSimSSHFPLookup()
	db, dir := newTestDB(t, func(cfg *hostkey.Config) {
		cfg.SSHFPLookup = sshfp
	})

	// 1. O_NOFOLLOW 软链拦截（INV-C5）。
	writeRawKnownHosts(t, dir, "real_kh", "h.test ssh-ed25519 AQID\n")
	linkDest, _ := pathalg.ParseLocalRootedDest("known_hosts")
	err := osfs.NewScopedRootFS().WithRoot(dir, func(root ports.RootHandle) error {
		return root.CreateSymlink(linkDest, "real_kh")
	})
	if err != nil {
		t.Fatalf("CreateSymlink 失败: %v", err)
	}
	ep := tck.MustEndpoint(t, "h.test", 22)
	key := makeRealBlobKey(t, "ssh-ed25519", []byte{1, 2, 3, 4}, "")
	req, _ := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: key, Mode: option.StrictHostKeyCheckingYes,
	})
	if _, err := db.VerifyHostKey(ctx, req); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("软链 known_hosts 必须失败关闭返回 ErrSymlinkRejected，实际 %v", err)
	}
	if err := db.RecordHostKey(ctx, ep, key, option.UnsetKnownHostsList()); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("向软链 known_hosts 写入必须失败关闭返回 ErrSymlinkRejected，实际 %v", err)
	}

	// 2. UserKnownHostsFile=none 时不读文件，验证 DNSSEC SSHFP 仅信任 Authenticated==true。
	disabledReq, _ := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: key, Mode: option.StrictHostKeyCheckingYes, KnownHosts: option.DisabledKnownHostsList(),
	})
	sum256 := sha256.Sum256(key.WireBlob())
	unauthRec, _ := ports.NewSSHFPRecord(ports.SSHFPRecordSpec{Algorithm: 4, FingerprintType: 2, Digest: sum256[:], Authenticated: false})
	sshfp.SetRecords(ep.Host(), unauthRec)
	chk, err := db.VerifyHostKey(ctx, disabledReq)
	if err != nil || chk.Status() != ports.HostTrustUnknown {
		t.Fatalf("未认证 SSHFP 绝不得自动信任，实际 status=%s err=%v", chk.Status(), err)
	}
	authRec, _ := ports.NewSSHFPRecord(ports.SSHFPRecordSpec{Algorithm: 4, FingerprintType: 2, Digest: sum256[:], Authenticated: true})
	sshfp.SetRecords(ep.Host(), authRec)
	chk, err = db.VerifyHostKey(ctx, disabledReq)
	if err != nil || chk.Status() != ports.HostTrustTrusted {
		t.Fatalf("DNSSEC 已认证 SSHFP 应返回 HostTrustTrusted，实际 status=%s err=%v", chk.Status(), err)
	}
	if err := db.RecordHostKey(ctx, ep, key, option.DisabledKnownHostsList()); err != nil {
		t.Fatalf("DisabledKnownHostsList RecordHostKey 应静默成功，实际 %v", err)
	}

	// 3. DNSSEC SSHFP 冲突、算法降级、SHA-1 兜底与 IP 字面量跳过（Fail-Closed）。
	assertSSHFPFailClosedCases(t, ctx, db, sshfp, ep, key, disabledReq, authRec)
}

func assertSSHFPFailClosedCases(
	t *testing.T,
	ctx context.Context,
	db *hostkey.KnownHostsDB,
	sshfp *sim.SimSSHFPLookup,
	ep netaddr.Endpoint,
	key ports.PublicKeyInfo,
	disabledReq ports.HostTrustRequest,
	authRec ports.SSHFPRecord,
) {
	t.Helper()
	wrongKey := makeRealBlobKey(t, "ssh-ed25519", []byte{9, 9, 9, 9}, "")
	reqWrong, _ := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: wrongKey, Mode: option.StrictHostKeyCheckingAcceptNew, KnownHosts: option.DisabledKnownHostsList(),
	})
	if chk, err := db.VerifyHostKey(ctx, reqWrong); err != nil || chk.Status() != ports.HostTrustMismatch {
		t.Fatalf("DNSSEC SSHFP 指纹冲突须返回 HostTrustMismatch，实际 status=%s err=%v", chk.Status(), err)
	}
	rsaKey := makeRealBlobKey(t, "ssh-rsa", []byte{5, 6, 7, 8}, "")
	reqDowngrade, _ := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: rsaKey, Mode: option.StrictHostKeyCheckingAcceptNew, KnownHosts: option.DisabledKnownHostsList(),
	})
	if chk, err := db.VerifyHostKey(ctx, reqDowngrade); err != nil || chk.Status() != ports.HostTrustMismatch {
		t.Fatalf("DNSSEC SSHFP 算法降级须返回 HostTrustMismatch，实际 status=%s err=%v", chk.Status(), err)
	}
	sum1 := sha1.Sum(key.WireBlob())
	authSHA1, _ := ports.NewSSHFPRecord(ports.SSHFPRecordSpec{Algorithm: 4, FingerprintType: 1, Digest: sum1[:], Authenticated: true})
	sshfp.SetRecords(ep.Host(), authSHA1)
	if chk, err := db.VerifyHostKey(ctx, disabledReq); err != nil || chk.Status() != ports.HostTrustTrusted {
		t.Fatalf("仅存在已认证 SHA-1 SSHFP 应匹配，实际 status=%s err=%v", chk.Status(), err)
	}
	wrongSum256 := sha256.Sum256(wrongKey.WireBlob())
	badSHA256, _ := ports.NewSSHFPRecord(ports.SSHFPRecordSpec{Algorithm: 4, FingerprintType: 2, Digest: wrongSum256[:], Authenticated: true})
	sshfp.SetRecords(ep.Host(), authSHA1, badSHA256)
	if chk, err := db.VerifyHostKey(ctx, disabledReq); err != nil || chk.Status() != ports.HostTrustMismatch {
		t.Fatalf("已认证 SHA-256 冲突不得被 SHA-1 绕过，实际 status=%s err=%v", chk.Status(), err)
	}
	epIP := tck.MustEndpoint(t, "198.51.100.77", 22)
	sshfp.SetRecords(epIP.Host(), authRec)
	reqIP, _ := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: epIP, Presented: key, Mode: option.StrictHostKeyCheckingYes, KnownHosts: option.DisabledKnownHostsList(),
	})
	if chk, err := db.VerifyHostKey(ctx, reqIP); err != nil || chk.Status() != ports.HostTrustUnknown {
		t.Fatalf("IP 字面量不得使用 DNS SSHFP，实际 status=%s err=%v", chk.Status(), err)
	}
}

func TestKnownHostsDB_ConcurrentRecordAndSidecarLockCleanup(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	db, dir := newTestDB(t, nil)

	const workers = 10
	endpoints := make([]netaddr.Endpoint, workers)
	keys := make([]ports.PublicKeyInfo, workers)
	for i := range workers {
		endpoints[i] = tck.MustEndpoint(t, fmt.Sprintf("node-%d.example.test", i), uint16(2200+i))
		keys[i] = makeRealBlobKey(t, "ssh-ed25519", fmt.Appendf(nil, "concurrent-key-payload-%d", i), "")
	}

	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		for i := range workers {
			ep, key := endpoints[i], keys[i]
			if gErr := n.Go(func(c context.Context) error { return recordAndVerifyHostKey(c, db, ep, key) }); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("并发 RecordHostKey/VerifyHostKey 失败: %v", err)
	}
	for i := range workers {
		assertHostKeyTrusted(t, ctx, db, endpoints[i], keys[i])
	}
	removed, err := db.CleanupSidecarLock(ctx, endpoints[0], option.UnsetKnownHostsList())
	if err != nil || !removed {
		t.Fatalf("CleanupSidecarLock 应安全清理旁路锁，实际 removed=%v err=%v", removed, err)
	}
	assertNoResidualTempOrLockFiles(t, dir)
}

func recordAndVerifyHostKey(ctx context.Context, db *hostkey.KnownHostsDB, ep netaddr.Endpoint, key ports.PublicKeyInfo) error {
	if err := db.RecordHostKey(ctx, ep, key, option.UnsetKnownHostsList()); err != nil {
		return err
	}
	req, err := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: key, Mode: option.StrictHostKeyCheckingYes,
	})
	if err != nil {
		return err
	}
	chk, err := db.VerifyHostKey(ctx, req)
	if err != nil {
		return err
	}
	if !chk.IsTrusted() {
		return fmt.Errorf("刚写入的密钥 %s 未命中信任", ep)
	}
	return nil
}

func assertHostKeyTrusted(t *testing.T, ctx context.Context, db *hostkey.KnownHostsDB, ep netaddr.Endpoint, key ports.PublicKeyInfo) {
	t.Helper()
	req, _ := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: key, Mode: option.StrictHostKeyCheckingYes,
	})
	chk, err := db.VerifyHostKey(ctx, req)
	if err != nil || !chk.IsTrusted() {
		t.Fatalf("并发落盘后 %s 丢失: status=%s err=%v", ep, chk.Status(), err)
	}
}

func assertNoResidualTempOrLockFiles(t *testing.T, dir pathalg.LocalDir) {
	t.Helper()
	if err := osfs.NewScopedRootFS().WithRoot(dir, func(root ports.RootHandle) error {
		entries, rErr := root.ReadDir(algebraic.None[pathalg.LocalRootedDest]())
		if rErr != nil {
			return rErr
		}
		for _, de := range entries {
			if strings.HasPrefix(de.Name(), ".xops-tmp-") || strings.HasSuffix(de.Name(), ".lock") {
				return fmt.Errorf("发现残留临时或锁文件: %s", de.Name())
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("目录残留校验失败: %v", err)
	}
}
