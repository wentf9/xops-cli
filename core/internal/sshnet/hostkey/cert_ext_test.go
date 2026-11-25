package hostkey_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

func genSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

func pubInfoFromSSHKey(t *testing.T, key ssh.PublicKey) ports.PublicKeyInfo {
	t.Helper()
	blob := key.Marshal()
	pk, err := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm:   key.Type(),
		Fingerprint: inventory.KeyFingerprintFromSHA256(sha256.Sum256(blob)),
		WireBlob:    blob,
	})
	if err != nil {
		t.Fatalf("NewPublicKeyInfo: %v", err)
	}
	return pk
}

func signTestCert(t *testing.T, ca ssh.Signer, hostPub ssh.PublicKey, certType uint32, principals []string, after, before uint64, critOpts map[string]string) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             hostPub,
		CertType:        certType,
		KeyId:           "host-cert-test",
		ValidPrincipals: principals,
		ValidAfter:      after,
		ValidBefore:     before,
		Permissions:     ssh.Permissions{CriticalOptions: critOpts},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	return cert
}

func verifyKey(t *testing.T, db *hostkey.KnownHostsDB, ep string, key ports.PublicKeyInfo) ports.HostTrustCheck {
	t.Helper()
	req, err := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint:  tck.MustEndpoint(t, ep, 22),
		Presented: key,
		Mode:      option.StrictHostKeyCheckingYes,
	})
	if err != nil {
		t.Fatalf("NewHostTrustRequest: %v", err)
	}
	chk, err := db.VerifyHostKey(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyHostKey: %v", err)
	}
	return chk
}

func TestKnownHostsDB_HostCertificatesAndRevokedTriCheck(t *testing.T) {
	defer goleak.VerifyNone(t)
	now := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	clk := sim.NewSimClock(now)
	db, dir := newTestDB(t, func(cfg *hostkey.Config) { cfg.Clock = clk })

	ca := genSSHSigner(t)
	otherCA := genSSHSigner(t)
	hostKey := genSSHSigner(t)
	revokedHostKey := genSSHSigner(t)
	revokedCA := genSSHSigner(t)

	caLine := fmt.Sprintf("@cert-authority *.ca.example.test %s", string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
	revCAAlsoCALine := fmt.Sprintf("@cert-authority revca.example.test %s", string(ssh.MarshalAuthorizedKey(revokedCA.PublicKey())))
	revHostLine := fmt.Sprintf("@revoked app.ca.example.test %s", string(ssh.MarshalAuthorizedKey(revokedHostKey.PublicKey())))
	revCALine := fmt.Sprintf("@revoked revca.example.test %s", string(ssh.MarshalAuthorizedKey(revokedCA.PublicKey())))
	writeRawKnownHosts(t, dir, "known_hosts", caLine+revCAAlsoCALine+revHostLine+revCALine)

	after := uint64(now.Add(-time.Hour).Unix())
	before := uint64(now.Add(time.Hour).Unix())

	// 1. 合法 CA 签发主机证书（精确 Principal 与空 Principal 均须受信任）且 PreferredAlgorithms 包含证书算法。
	validCert := signTestCert(t, ca, hostKey.PublicKey(), ssh.HostCert, []string{"app.ca.example.test"}, after, before, nil)
	if chk := verifyKey(t, db, "app.ca.example.test", pubInfoFromSSHKey(t, validCert)); !chk.IsTrusted() {
		t.Fatalf("合法 @cert-authority 主机证书应受信任，实际 %s (%s)", chk.Status(), chk.Reason())
	}
	wildcardPrincipalCert := signTestCert(t, ca, hostKey.PublicKey(), ssh.HostCert, nil, after, before, nil)
	if chk := verifyKey(t, db, "db.ca.example.test", pubInfoFromSSHKey(t, wildcardPrincipalCert)); !chk.IsTrusted() {
		t.Fatalf("空 ValidPrincipals 主机证书由 @cert-authority 模式授权应受信任，实际 %s (%s)", chk.Status(), chk.Reason())
	}
	algos, err := db.PreferredAlgorithms(context.Background(), tck.MustEndpoint(t, "app.ca.example.test", 22), option.UnsetKnownHostsList())
	if err != nil || !slices.Contains(algos, ssh.CertAlgoED25519v01) {
		t.Fatalf("PreferredAlgorithms 应包含主机证书算法，实际 %v err=%v", algos, err)
	}

	// 2. 过期、未生效、错 Principal、UserCert、含 CriticalOptions、非信任 CA、无 CA 均严禁放行。
	assertCertNotTrusted(t, db, "app.ca.example.test", signTestCert(t, ca, hostKey.PublicKey(), ssh.HostCert, []string{"app.ca.example.test"}, after, uint64(now.Add(-time.Minute).Unix()), nil), ports.HostTrustMismatch)
	assertCertNotTrusted(t, db, "app.ca.example.test", signTestCert(t, ca, hostKey.PublicKey(), ssh.HostCert, []string{"app.ca.example.test"}, uint64(now.Add(time.Minute).Unix()), before, nil), ports.HostTrustMismatch)
	assertCertNotTrusted(t, db, "app.ca.example.test", signTestCert(t, ca, hostKey.PublicKey(), ssh.HostCert, []string{"wrong.ca.example.test"}, after, before, nil), ports.HostTrustMismatch)
	assertCertNotTrusted(t, db, "app.ca.example.test", signTestCert(t, ca, hostKey.PublicKey(), ssh.UserCert, []string{"app.ca.example.test"}, after, before, nil), ports.HostTrustMismatch)
	assertCertNotTrusted(t, db, "app.ca.example.test", signTestCert(t, ca, hostKey.PublicKey(), ssh.HostCert, []string{"app.ca.example.test"}, after, before, map[string]string{"unknown-opt": "1"}), ports.HostTrustMismatch)
	assertCertNotTrusted(t, db, "app.ca.example.test", signTestCert(t, otherCA, hostKey.PublicKey(), ssh.HostCert, []string{"app.ca.example.test"}, after, before, nil), ports.HostTrustMismatch)
	assertCertNotTrusted(t, db, "noca.example.test", signTestCert(t, otherCA, hostKey.PublicKey(), ssh.HostCert, []string{"noca.example.test"}, after, before, nil), ports.HostTrustUnknown)

	// 3. @revoked 三重核验：被吊销底层主机公钥（自签或 CA 签）与被吊销 CA 均须命中 HostTrustRevoked。
	revokedHostWrapped := signTestCert(t, otherCA, revokedHostKey.PublicKey(), ssh.HostCert, []string{"app.ca.example.test"}, after, before, nil)
	assertCertNotTrusted(t, db, "app.ca.example.test", revokedHostWrapped, ports.HostTrustRevoked)
	revokedCASigned := signTestCert(t, revokedCA, hostKey.PublicKey(), ssh.HostCert, []string{"revca.example.test"}, after, before, nil)
	assertCertNotTrusted(t, db, "revca.example.test", revokedCASigned, ports.HostTrustRevoked)

	// 4. RecordHostKey 严禁 TOFU 落盘任何 *-cert-v01@openssh.com 主机证书。
	if rErr := db.RecordHostKey(context.Background(), tck.MustEndpoint(t, "app.ca.example.test", 22), pubInfoFromSSHKey(t, validCert), option.UnsetKnownHostsList()); !errors.Is(rErr, ports.ErrInvalidArgument) {
		t.Fatalf("RecordHostKey 必须拒绝原始 SSH 主机证书，实际 %v", rErr)
	}
}

func assertCertNotTrusted(t *testing.T, db *hostkey.KnownHostsDB, host string, cert *ssh.Certificate, want ports.HostTrustStatus) {
	t.Helper()
	chk := verifyKey(t, db, host, pubInfoFromSSHKey(t, cert))
	if chk.Status() != want {
		t.Fatalf("host=%s 期望状态 %s，实际 %s (%s)", host, want, chk.Status(), chk.Reason())
	}
}

// TestKnownHostsDB_ExplicitExternalParentDirWorksOnInheritedTempDir 验证显式外部 UserKnownHostsFile
// 指向已存在外部目录（含原生 Windows 继承 DACL 的 TempDir）时可正常写入受保护文件，且仍拦截软链目录。
func TestKnownHostsDB_ExplicitExternalParentDirWorksOnInheritedTempDir(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	db, _ := newTestDB(t, nil)

	// 故意直接使用原始 t.TempDir() 作为外部父目录（区别于 db.defaultDir）。
	extDir, err := pathalg.ParseLocalDir(t.TempDir())
	if err != nil {
		t.Fatalf("ParseLocalDir: %v", err)
	}
	extList, err := option.ParseKnownHostsList([]string{extDir.String() + "/ext_known_hosts"})
	if err != nil {
		t.Fatalf("ParseKnownHostsList: %v", err)
	}
	ep := tck.MustEndpoint(t, "ext.example.test", 22)
	key := makeRealBlobKey(t, "ssh-ed25519", []byte("external-kh-payload"), "")
	if err := db.RecordHostKey(ctx, ep, key, extList); err != nil {
		t.Fatalf("显式外部 UserKnownHostsFile 写入失败: %v", err)
	}
	req, _ := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: key, Mode: option.StrictHostKeyCheckingYes, KnownHosts: extList,
	})
	chk, err := db.VerifyHostKey(ctx, req)
	if err != nil || !chk.IsTrusted() {
		t.Fatalf("显式外部 UserKnownHostsFile 核验失败: status=%s err=%v", chk.Status(), err)
	}

	// 验证指向软链外部目录仍严格失败关闭。
	rootFS := osfs.NewScopedRootFS()
	realSub, _ := pathalg.ParseLocalRootedDest("realdir")
	linkSub, _ := pathalg.ParseLocalRootedDest("linkdir")
	if err := rootFS.WithRoot(extDir, func(root ports.RootHandle) error {
		if mErr := root.MkdirAll(realSub, 0o700); mErr != nil {
			return mErr
		}
		return root.CreateSymlink(linkSub, "realdir")
	}); err != nil {
		t.Fatalf("构造软链目录夹具失败: %v", err)
	}
	linkList, _ := option.ParseKnownHostsList([]string{extDir.String() + "/linkdir/kh"})
	if err := db.RecordHostKey(ctx, ep, key, linkList); !errors.Is(err, ports.ErrSymlinkRejected) {
		t.Fatalf("显式软链父目录必须返回 ErrSymlinkRejected，实际 %v", err)
	}
}
