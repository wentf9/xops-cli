package adapter

import (
	"context"
	"crypto/subtle"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// unchangedSecret compares transient authentication material with an existing
// reference without retaining another plaintext copy in the adapter.
func (a *SSHAdapter) unchangedSecret(ctx context.Context, ref *credential.Ref, value string) (bool, error) {
	if value == "" || ref == nil || ref.IsEmpty() || a.credentialResolver == nil {
		return false, nil
	}
	stored, err := a.credentialResolver.Resolve(ctx, *ref)
	defer stored.Zero()
	if err != nil {
		return false, fmt.Errorf("compare stored credential before recording: %w", err)
	}
	return subtle.ConstantTimeCompare(stored.Value, []byte(value)) == 1, nil
}

func (a *SSHAdapter) newAuthenticationMaterial(ctx context.Context, nodeID, password, keyPath, passphrase string) (string, string, error) {
	if a.credentialService == nil || a.credentialResolver == nil {
		return password, passphrase, nil
	}
	snapshot, err := a.cfgProvider.ResolveConnection(nodeID)
	if err != nil {
		return "", "", fmt.Errorf("resolve authentication before recording: %w", err)
	}
	same, err := a.unchangedSecret(ctx, snapshot.Identity.LoginPasswordRef, password)
	if err != nil {
		return "", "", err
	}
	if same {
		password = ""
	}
	if keyPath == "" || keyPath == snapshot.Identity.KeyPath {
		same, err = a.unchangedSecret(ctx, snapshot.Identity.PassphraseRef, passphrase)
		if err != nil {
			return "", "", err
		}
		if same {
			// A key file can be replaced at the same path. Keep the write if
			// its fingerprint changed, even when its passphrase stayed equal.
			target, bindErr := config.BindPrivateKeyFingerprint(a.cfgProvider.Snapshot(), credential.Target{Kind: credential.KindPassphrase, KeyPath: snapshot.Identity.KeyPath}, []byte(passphrase))
			if bindErr != nil {
				return "", "", bindErr
			}
			if target.KeyFingerprint == snapshot.Identity.KeyFingerprint {
				passphrase = ""
			}
		}
	}
	return password, passphrase, nil
}
