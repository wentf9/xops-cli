package keysigner_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"testing"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/keysigner"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// 编译期接口断言：确保 *keysigner.KeySigner 完整满足 ports.KeySignerPort 契约。
var _ ports.KeySignerPort = (*keysigner.KeySigner)(nil)

func makeEd25519Fixture(t *testing.T, passphrase string) (ssh.Signer, []byte, []byte, ports.PublicKeyInfo) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	plainBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	plainPEM := pem.EncodeToMemory(plainBlock)
	var encPEM []byte
	if passphrase != "" {
		encBlock, eErr := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
		if eErr != nil {
			t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", eErr)
		}
		encPEM = pem.EncodeToMemory(encBlock)
	}
	pub, err := keysigner.PublicKeyInfoFromSSH(s.PublicKey())
	if err != nil {
		t.Fatalf("PublicKeyInfoFromSSH: %v", err)
	}
	return s, plainPEM, encPEM, pub
}

func writeKeyFile(t *testing.T, dir pathalg.LocalDir, name string, data []byte) inventory.KeyPathSpec {
	t.Helper()
	dest, err := pathalg.ParseLocalRootedDest(name)
	if err != nil {
		t.Fatalf("ParseLocalRootedDest(%s): %v", name, err)
	}
	if err := osfs.NewScopedRootFS().WithRoot(dir, func(root ports.RootHandle) error {
		return root.AtomicReplace(dest, 0o600, func(w io.Writer) error {
			_, wErr := w.Write(data)
			return wErr
		})
	}); err != nil {
		t.Fatalf("AtomicReplace(%s): %v", name, err)
	}
	kp, err := inventory.ParseKeyPathSpec(dir.String() + "/" + name)
	if err != nil {
		t.Fatalf("ParseKeyPathSpec: %v", err)
	}
	return kp
}

func TestKeySigner_TCKSuite_PlainEncryptedAndAgent(t *testing.T) {
	defer goleak.VerifyNone(t)
	t.Run("PlainPrivateKey", runPlainKeySignerTCK)
	t.Run("EncryptedPrivateKeyWithVault", runEncryptedKeySignerTCK)
	t.Run("AgentFallback", runAgentKeySignerTCK)
}

func runPlainKeySignerTCK(t *testing.T) {
	dir, err := pathalg.ParseLocalDir(t.TempDir())
	if err != nil {
		t.Fatalf("ParseLocalDir: %v", err)
	}
	_, plainPEM, _, _ := makeEd25519Fixture(t, "")
	kp := writeKeyFile(t, dir, "id_plain", plainPEM)
	auth, err := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kp), algebraic.None[inventory.KeyPassphraseBinding](), nil)
	if err != nil {
		t.Fatalf("NewAuthPrivateKey: %v", err)
	}
	tck.RunKeySignerSuite(t, tck.KeySignerFixture{
		NewSigner: func(st *testing.T) ports.KeySignerPort {
			ks, sErr := keysigner.NewKeySigner(keysigner.Config{
				ReadFS:  osfs.NewOperatorReadFS(),
				Entropy: tck.NewDeterministicEntropy(7),
			})
			if sErr != nil {
				st.Fatalf("NewKeySigner: %v", sErr)
			}
			return ks
		},
		Auth:       auth,
		KeyPath:    algebraic.Some(kp),
		Passphrase: algebraic.None[secret.Ref](),
	})
}

func runEncryptedKeySignerTCK(t *testing.T) {
	ctx := context.Background()
	dir, err := pathalg.ParseLocalDir(t.TempDir())
	if err != nil {
		t.Fatalf("ParseLocalDir: %v", err)
	}
	_, _, encPEM, pub := makeEd25519Fixture(t, "top-secret-pass")
	kp := writeKeyFile(t, dir, "id_enc", encPEM)
	vault := sim.NewSimVault(sim.NewSeededRand(17))
	passRef := tck.MustRef(t, "sim", "enc-key-pass")
	if err := secret.WithBytes([]byte("top-secret-pass"), func(box *secret.SecretBox) error {
		return vault.PutAndVerify(ctx, passRef, box)
	}); err != nil {
		t.Fatalf("PutAndVerify: %v", err)
	}
	bind, err := inventory.NewKeyPassphraseBinding(passRef, pub.Fingerprint())
	if err != nil {
		t.Fatalf("NewKeyPassphraseBinding: %v", err)
	}
	auth, err := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kp), algebraic.Some(bind), nil)
	if err != nil {
		t.Fatalf("NewAuthPrivateKey: %v", err)
	}
	tck.RunKeySignerSuite(t, tck.KeySignerFixture{
		NewSigner: func(st *testing.T) ports.KeySignerPort {
			ks, sErr := keysigner.NewKeySigner(keysigner.Config{
				ReadFS: osfs.NewOperatorReadFS(),
				Vault:  vault,
			})
			if sErr != nil {
				st.Fatalf("NewKeySigner: %v", sErr)
			}
			return ks
		},
		Auth:       auth,
		KeyPath:    algebraic.Some(kp),
		Passphrase: algebraic.Some(passRef),
	})
}

func runAgentKeySignerTCK(t *testing.T) {
	_, _, _, pub := makeEd25519Fixture(t, "")
	ag := sim.NewSimSSHAgent(pub)
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	if err != nil {
		t.Fatalf("NewAuthAgent: %v", err)
	}
	tck.RunKeySignerSuite(t, tck.KeySignerFixture{
		NewSigner: func(st *testing.T) ports.KeySignerPort {
			ks, sErr := keysigner.NewKeySigner(keysigner.Config{Agent: ag})
			if sErr != nil {
				st.Fatalf("NewKeySigner: %v", sErr)
			}
			return ks
		},
		Auth: auth,
	})
}

func TestKeySigner_ValidationCertAndINVF1FailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 零值与空依赖配置严格失败关闭。
	var zeroKS keysigner.KeySigner
	var zeroFP inventory.KeyFingerprint
	if _, err := zeroKS.Sign(ctx, zeroFP, "ssh-ed25519", []byte("x")); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 KeySigner.Sign 须返回 ErrInvalidArgument，实际 %v", err)
	}
	if _, err := keysigner.NewKeySigner(keysigner.Config{}); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("空依赖 NewKeySigner 须返回 ErrInvalidArgument，实际 %v", err)
	}

	dir, _ := pathalg.ParseLocalDir(t.TempDir())
	signer, plainPEM, encPEM, pub := makeEd25519Fixture(t, "real-pass")
	caSigner, _, _, _ := makeEd25519Fixture(t, "")
	kpPlain := writeKeyFile(t, dir, "id_plain", plainPEM)
	kpEnc := writeKeyFile(t, dir, "id_enc", encPEM)

	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "ks-cert",
		ValidPrincipals: []string{"ops"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	_ = writeKeyFile(t, dir, "id_plain-cert.pub", ssh.MarshalAuthorizedKey(cert))
	cp, err := inventory.ParseCertPathSpec(dir.String() + "/id_plain-cert.pub")
	if err != nil {
		t.Fatalf("ParseCertPathSpec: %v", err)
	}

	vault := sim.NewSimVault(sim.NewSeededRand(29))
	passRef := tck.MustRef(t, "sim", "ks-pass")
	_ = secret.WithBytes([]byte("real-pass"), func(box *secret.SecretBox) error {
		return vault.PutAndVerify(ctx, passRef, box)
	})
	ks, err := keysigner.NewKeySigner(keysigner.Config{
		ReadFS: osfs.NewOperatorReadFS(),
		Vault:  vault,
	})
	if err != nil {
		t.Fatalf("NewKeySigner: %v", err)
	}

	// 1. 私钥附带匹配证书时，ListPublicKeys 返回证书公钥，Sign 产出可被证书公钥验签的有效签名。
	authCert, err := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kpPlain), algebraic.None[inventory.KeyPassphraseBinding](), []inventory.CertPathSpec{cp})
	if err != nil {
		t.Fatalf("NewAuthPrivateKey(cert): %v", err)
	}
	keys, err := ks.ListPublicKeys(ctx, authCert)
	if err != nil || len(keys) != 1 || keys[0].Algorithm() != ssh.CertAlgoED25519v01 {
		t.Fatalf("期望返回绑定证书的 ssh-ed25519-cert-v01@openssh.com 公钥，实际 keys=%+v err=%v", keys, err)
	}
	sig, err := ks.Sign(ctx, keys[0].Fingerprint(), keys[0].Algorithm(), []byte("verify-me"))
	if err != nil {
		t.Fatalf("Sign(cert): %v", err)
	}
	parsedCertPub, err := ssh.ParsePublicKey(keys[0].WireBlob())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if err := parsedCertPub.Verify([]byte("verify-me"), &ssh.Signature{Format: sig.Format(), Blob: sig.Blob()}); err != nil {
		t.Fatalf("证书签名验签失败: %v", err)
	}

	// 2. INV-F1 口令指纹绑定失配必须失败关闭。
	wrongFP, _ := inventory.ParseKeyFingerprint(tck.TestFingerprintA)
	badBind, _ := inventory.NewKeyPassphraseBinding(passRef, wrongFP)
	authBad, _ := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kpEnc), algebraic.Some(badBind), nil)
	if _, err := ks.ListPublicKeys(ctx, authBad); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("INV-F1 指纹失配须返回 ErrAuthFailed，实际 %v", err)
	}

	// 3. InspectPrivateKeyFingerprint：无口令读取加密私钥失败，提供正确口令返回真实指纹。
	if _, err := ks.InspectPrivateKeyFingerprint(ctx, kpEnc, algebraic.None[secret.Ref]()); !errors.Is(err, ports.ErrAuthFailed) {
		t.Fatalf("无口令核验加密私钥须返回 ErrAuthFailed，实际 %v", err)
	}
	gotFP, err := ks.InspectPrivateKeyFingerprint(ctx, kpEnc, algebraic.Some(passRef))
	if err != nil || !gotFP.Equal(pub.Fingerprint()) {
		t.Fatalf("InspectPrivateKeyFingerprint(enc) got=%s want=%s err=%v", gotFP, pub.Fingerprint(), err)
	}
}
