package tck

import (
	"bytes"
	"context"
	"errors"
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"testing"
)

// SecretVaultFixture 描述 SecretVault 契约测试夹具。
type SecretVaultFixture struct {
	// NewVault 返回全新、已解锁的空白 SecretVault 实例。
	NewVault func(t *testing.T) ports.SecretVault
	// NewLockedVault 返回处于锁定状态的 SecretVault（可选；提供时验证 ErrVaultLocked 失败关闭）。
	NewLockedVault func(t *testing.T) ports.SecretVault
}

// KeySignerFixture 描述 KeySignerPort 契约测试夹具。
type KeySignerFixture struct {
	// NewSigner 返回预置至少 1 把可用签名密钥的 KeySignerPort。
	NewSigner func(t *testing.T) ports.KeySignerPort
	// Auth 指定用于 ListPublicKeys 的有效认证规格。
	Auth inventory.AuthMethod
	// KeyPath 与 Passphrase 指定用于 InspectPrivateKeyFingerprint 的合法私钥路径（可选）。
	KeyPath    algebraic.Option[inventory.KeyPathSpec]
	Passphrase algebraic.Option[secret.Ref]
}

// HostTrustFixture 描述 HostTrustPort 契约测试夹具。
type HostTrustFixture struct {
	// NewTrust 返回空白的主机密钥信任库适配器。
	NewTrust func(t *testing.T) ports.HostTrustPort
	// KnownHosts 指定测试使用的 known_hosts 列表（可为空列表）。
	KnownHosts option.KnownHostsList
}

// RunSecretVaultSuite 验证 SecretVault 全部作用域借用、常量时间回读校验、删除、锁定与并发契约。
// 严格遵循 ADR-011 / Plan §4.6：全部 secret.WithBytes 均内嵌于各自 t.Run 回调内，零 box.Use 明文消费。
func RunSecretVaultSuite(t *testing.T, fx SecretVaultFixture) {
	t.Helper()
	requireTrue(t, fx.NewVault != nil, "SecretVaultFixture.NewVault 不能为 nil")
	t.Run("ValidationAndMissingKey", func(t *testing.T) {
		vault := fx.NewVault(t)
		ref := MustRef(t, "tck-store", "missing-item")
		var nilCtx context.Context
		var zeroRef secret.Ref
		var zeroBox secret.SecretBox
		requireErrIs(t, vault.WithSecret(nilCtx, ref, func(*secret.SecretBox) error { return nil }), ports.ErrNilContext, "WithSecret(nil ctx)")
		requireErrIs(t, vault.WithSecret(context.Background(), ref, nil), ports.ErrNilCallback, "WithSecret(nil fn)")
		requireErr(t, vault.WithSecret(context.Background(), zeroRef, func(*secret.SecretBox) error { return nil }), "WithSecret(zero ref)")
		requireErrIs(t, vault.WithSecret(context.Background(), ref, func(*secret.SecretBox) error { return nil }), ports.ErrSecretNotFound, "WithSecret(missing)")
		requireErr(t, vault.PutAndVerify(context.Background(), ref, nil), "PutAndVerify(nil box)")
		requireErr(t, vault.PutAndVerify(context.Background(), ref, &zeroBox), "PutAndVerify(zero box)")
		requireErrIs(t, vault.Delete(nilCtx, ref), ports.ErrNilContext, "Delete(nil ctx)")
		requireErr(t, vault.Delete(context.Background(), zeroRef), "Delete(zero ref)")
		requireErrIs(t, vault.Delete(context.Background(), ref), ports.ErrSecretNotFound, "Delete(missing)")
		err := secret.WithBytes([]byte(TestSecretTokenA), func(box *secret.SecretBox) error {
			requireErrIs(t, vault.PutAndVerify(nilCtx, ref, box), ports.ErrNilContext, "PutAndVerify(nil ctx)")
			requireErr(t, vault.PutAndVerify(context.Background(), zeroRef, box), "PutAndVerify(zero ref)")
			return nil
		})
		requireNoErr(t, err, "WithBytes(validation)")
	})
	t.Run("PutVerifyReadOverwriteAndDelete", func(t *testing.T) {
		ctx := context.Background()
		vault := fx.NewVault(t)
		ref := MustRef(t, "tck-store", "cred-1")
		requireNoErr(t, secret.WithBytes([]byte(TestSecretTokenA), func(src *secret.SecretBox) error {
			requireNoErr(t, vault.PutAndVerify(ctx, ref, src), "PutAndVerify(A)")
			return vault.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
				requireTrue(t, got.IsValid() && got.Len() == len(TestSecretTokenA) && got.Equal(src), "回读 SecretBox 须有效且常量时间相等")
				return nil
			})
		}), "PutAndVerify(A)+Read")
		// 验证回调错误原样透传。
		sentinel := errors.New("tck callback sentinel")
		err := vault.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
			requireTrue(t, got.IsValid(), "错误透传回调中 SecretBox 须有效")
			return sentinel
		})
		requireErrIs(t, err, sentinel, "WithSecret 须原样透传回调错误")
		// 覆盖写入 B 并确认与 A 不等、与 B 相等。
		requireNoErr(t, secret.WithBytes([]byte(TestSecretTokenB), func(srcB *secret.SecretBox) error {
			requireNoErr(t, vault.PutAndVerify(ctx, ref, srcB), "PutAndVerify(B)")
			return secret.WithBytes([]byte(TestSecretTokenA), func(srcA *secret.SecretBox) error {
				return vault.WithSecret(ctx, ref, func(got *secret.SecretBox) error {
					requireTrue(t, got.Equal(srcB) && !got.Equal(srcA), "覆盖后必须匹配新值且不匹配旧值")
					return nil
				})
			})
		}), "Overwrite(B)")
		requireNoErr(t, vault.Delete(ctx, ref), "Delete")
		requireErrIs(t, vault.WithSecret(ctx, ref, func(*secret.SecretBox) error { return nil }), ports.ErrSecretNotFound, "删除后 WithSecret 须返回 ErrSecretNotFound")
		requireErrIs(t, vault.Delete(ctx, ref), ports.ErrSecretNotFound, "重复 Delete 须返回 ErrSecretNotFound")
	})
	t.Run("ConcurrentScopedReads", func(t *testing.T) {
		verifyConcurrentVaultReads(t, fx.NewVault)
	})
	if fx.NewLockedVault != nil {
		t.Run("LockedVaultFailsClosed", func(t *testing.T) {
			verifyLockedVaultFailsClosed(t, fx.NewLockedVault)
		})
	}
}
func verifyConcurrentVaultReads(t *testing.T, newVault func(t *testing.T) ports.SecretVault) {
	t.Helper()
	defer VerifyNoLeaks(t)
	ctx := context.Background()
	vault := newVault(t)
	ref := MustRef(t, "tck-store", "shared-cred")
	requireNoErr(t, secret.WithBytes([]byte(TestSecretTokenA), func(src *secret.SecretBox) error {
		return vault.PutAndVerify(ctx, ref, src)
	}), "seed concurrent secret")
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		for range 6 {
			if gErr := n.Go(func(c context.Context) error {
				return secret.WithBytes([]byte(TestSecretTokenA), func(expected *secret.SecretBox) error {
					return vault.WithSecret(c, ref, func(got *secret.SecretBox) error {
						if !got.IsValid() || !got.Equal(expected) {
							return ports.ErrSecretVerifyFailed
						}
						return nil
					})
				})
			}); gErr != nil {
				return gErr
			}
		}
		return nil
	})
	requireNoErr(t, err, "并发 WithSecret 借用")
}
func verifyLockedVaultFailsClosed(t *testing.T, newLocked func(t *testing.T) ports.SecretVault) {
	t.Helper()
	ctx := context.Background()
	locked := newLocked(t)
	ref := MustRef(t, "tck-store", "locked-cred")
	requireErrIs(t, locked.WithSecret(ctx, ref, func(*secret.SecretBox) error { return nil }), ports.ErrVaultLocked, "锁定态 WithSecret")
	requireErrIs(t, locked.Delete(ctx, ref), ports.ErrVaultLocked, "锁定态 Delete")
	err := secret.WithBytes([]byte(TestSecretTokenA), func(box *secret.SecretBox) error {
		requireErrIs(t, locked.PutAndVerify(ctx, ref, box), ports.ErrVaultLocked, "锁定态 PutAndVerify")
		return nil
	})
	requireNoErr(t, err, "锁定态 WithBytes")
}

// RunKeySignerSuite 验证 KeySignerPort 的公钥列举、签名输出与私钥指纹核验契约。
func RunKeySignerSuite(t *testing.T, fx KeySignerFixture) {
	t.Helper()
	requireTrue(t, fx.NewSigner != nil && fx.Auth != nil && fx.Auth.IsValid(), "KeySignerFixture 缺少有效 Signer 或 Auth")
	t.Run("ListSignAndInspect", func(t *testing.T) {
		ctx := context.Background()
		signer := fx.NewSigner(t)
		var nilCtx context.Context
		var zeroFP inventory.KeyFingerprint
		_, err := signer.ListPublicKeys(nilCtx, fx.Auth)
		requireErrIs(t, err, ports.ErrNilContext, "ListPublicKeys(nil ctx)")
		_, err = signer.ListPublicKeys(ctx, nil)
		requireErr(t, err, "ListPublicKeys(nil auth)")
		keys, err := signer.ListPublicKeys(ctx, fx.Auth)
		requireNoErr(t, err, "ListPublicKeys")
		requireTrue(t, len(keys) > 0 && keys[0].IsValid(), "ListPublicKeys 至少应返回 1 把有效公钥")
		_, err = signer.Sign(nilCtx, keys[0].Fingerprint(), keys[0].Algorithm(), []byte("challenge"))
		requireErrIs(t, err, ports.ErrNilContext, "Sign(nil ctx)")
		_, err = signer.Sign(ctx, zeroFP, keys[0].Algorithm(), []byte("challenge"))
		requireErr(t, err, "Sign(zero fp)")
		sig, err := signer.Sign(ctx, keys[0].Fingerprint(), keys[0].Algorithm(), []byte("ssh-tck-challenge"))
		requireNoErr(t, err, "Sign")
		requireTrue(t, sig.IsValid() && len(sig.Blob()) > 0, "Sign 必须产出有效 Signature")
		if kp, ok := fx.KeyPath.Get(); ok {
			fp, iErr := signer.InspectPrivateKeyFingerprint(ctx, kp, fx.Passphrase)
			requireNoErr(t, iErr, "InspectPrivateKeyFingerprint")
			requireTrue(t, fp.IsValid(), "InspectPrivateKeyFingerprint 须返回有效指纹")
		}
	})
}

// RunHostTrustSuite 验证 HostTrustPort 的首次未知、记录信任、指纹冲突检测与按 Endpoint(Host,Port) 隔离契约（INV-E2）。
func RunHostTrustSuite(t *testing.T, fx HostTrustFixture) {
	t.Helper()
	requireTrue(t, fx.NewTrust != nil, "HostTrustFixture.NewTrust 不能为 nil")
	t.Run("UnknownRecordTrustedMismatchAndPortIsolation", func(t *testing.T) {
		ctx := context.Background()
		trust := fx.NewTrust(t)
		ep22 := MustEndpoint(t, "host.example.test", 22)
		ep2222 := MustEndpoint(t, "host.example.test", 2222)
		keyA := MustPublicKey(t, TestFingerprintA, 0x01)
		keyB := MustPublicKey(t, TestFingerprintB, 0x02)
		var nilCtx context.Context
		var zeroReq ports.HostTrustRequest
		_, err := trust.VerifyHostKey(nilCtx, zeroReq)
		requireErrIs(t, err, ports.ErrNilContext, "VerifyHostKey(nil ctx)")
		_, err = trust.VerifyHostKey(ctx, zeroReq)
		requireErr(t, err, "VerifyHostKey(zero req)")
		reqA, err := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
			Endpoint: ep22, Presented: keyA, Mode: option.StrictHostKeyCheckingYes, KnownHosts: fx.KnownHosts,
		})
		requireNoErr(t, err, "NewHostTrustRequest(A)")
		chk, err := trust.VerifyHostKey(ctx, reqA)
		requireNoErr(t, err, "VerifyHostKey(unknown)")
		requireTrue(t, chk.Status() == ports.HostTrustUnknown && !chk.IsTrusted(), "未记录端点必须返回 HostTrustUnknown")
		requireNoErr(t, trust.RecordHostKey(ctx, ep22, keyA, fx.KnownHosts), "RecordHostKey")
		chk, err = trust.VerifyHostKey(ctx, reqA)
		requireNoErr(t, err, "VerifyHostKey(trusted)")
		requireTrue(t, chk.IsTrusted() && chk.Status() == ports.HostTrustTrusted, "记录后相同密钥须返回 HostTrustTrusted")
		algos, err := trust.PreferredAlgorithms(ctx, ep22, fx.KnownHosts)
		requireNoErr(t, err, "PreferredAlgorithms")
		requireTrue(t, len(algos) > 0 && bytes.Equal([]byte(algos[0]), []byte(keyA.Algorithm())), "PreferredAlgorithms 应包含已记录算法")
		reqB, err := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
			Endpoint: ep22, Presented: keyB, Mode: option.StrictHostKeyCheckingYes, KnownHosts: fx.KnownHosts,
		})
		requireNoErr(t, err, "NewHostTrustRequest(mismatch)")
		chk, err = trust.VerifyHostKey(ctx, reqB)
		requireNoErr(t, err, "VerifyHostKey(mismatch)")
		requireTrue(t, chk.Status() == ports.HostTrustMismatch && !chk.IsTrusted(), "指纹冲突必须返回 HostTrustMismatch")
		// INV-E2：同主机不同端口必须严格隔离，不得复用 22 端口的信任记录。
		reqOtherPort, err := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
			Endpoint: ep2222, Presented: keyA, Mode: option.StrictHostKeyCheckingYes, KnownHosts: fx.KnownHosts,
		})
		requireNoErr(t, err, "NewHostTrustRequest(port2222)")
		chk, err = trust.VerifyHostKey(ctx, reqOtherPort)
		requireNoErr(t, err, "VerifyHostKey(port2222)")
		requireTrue(t, chk.Status() == ports.HostTrustUnknown && !chk.IsTrusted(), "同主机不同端口不得复用信任记录 (INV-E2)")
	})
}
