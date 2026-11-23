package utils

import (
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W16c_L4_16_M2_BuildAuthCredentialTargetPreservesAutoAndHybrid(t *testing.T) {
	t.Parallel()

	for _, hybrid := range []string{"auto", "otp", "keyboard-interactive"} {
		pwTarget := buildNodeAuthTarget("n1", credential.KindLoginPassword, "", hybrid)
		if pwTarget.AuthType != "" || pwTarget.ClearKeyPath {
			t.Fatalf("buildNodeAuthTarget(password, %q) = %+v, want empty AuthType and ClearKeyPath=false", hybrid, pwTarget)
		}
		ppTarget := buildNodeAuthTarget("n1", credential.KindPassphrase, "", hybrid)
		if ppTarget.AuthType != "" {
			t.Fatalf("buildNodeAuthTarget(passphrase, %q) = %+v, want empty AuthType", hybrid, ppTarget)
		}
	}

	keyToPW := buildNodeAuthTarget("n1", credential.KindLoginPassword, "", "key")
	if keyToPW.AuthType != "password" || !keyToPW.ClearKeyPath {
		t.Fatalf("buildNodeAuthTarget(password, key) = %+v, want AuthType=password ClearKeyPath=true", keyToPW)
	}
	pwToKey := buildNodeAuthTarget("n1", credential.KindPassphrase, "", "password")
	if pwToKey.AuthType != "key" {
		t.Fatalf("buildNodeAuthTarget(passphrase, password) = %+v, want AuthType=key", pwToKey)
	}
}

func TestP7W16c_L4_16_M2_PreparePassphraseTargetAndDisplacedRefs(t *testing.T) {
	t.Parallel()

	pwRef := &credential.Ref{StoreID: "file", ItemID: "pw-1"}
	ppRef := &credential.Ref{StoreID: "file", ItemID: "pp-1"}

	for _, hybrid := range []string{"auto", "otp", "keyboard-interactive"} {
		ident := models.Identity{User: "ops", AuthType: hybrid, LoginPasswordRef: pwRef.Clone()}
		target, err := preparePassphraseTarget(credential.Target{NodeID: "n1"}, ident, "/tmp/id_ed25519", "")
		if err != nil {
			t.Fatalf("preparePassphraseTarget(%q): %v", hybrid, err)
		}
		if target.AuthType != hybrid {
			t.Fatalf("preparePassphraseTarget(%q).AuthType = %q, want %q", hybrid, target.AuthType, hybrid)
		}
		if displaced := collectDisplacedCrossKindRefs(target, ident, ident.PassphraseRef); len(displaced) != 0 {
			t.Fatalf("hybrid %q unexpectedly displaced refs: %+v", hybrid, displaced)
		}
	}

	pwIdent := models.Identity{User: "ops", AuthType: "password", LoginPasswordRef: pwRef.Clone()}
	keyTarget, err := preparePassphraseTarget(credential.Target{NodeID: "n1"}, pwIdent, "/tmp/id_ed25519", "")
	if err != nil {
		t.Fatalf("preparePassphraseTarget(password): %v", err)
	}
	if keyTarget.AuthType != "key" {
		t.Fatalf("preparePassphraseTarget(password).AuthType = %q, want key", keyTarget.AuthType)
	}
	displacedPW := collectDisplacedCrossKindRefs(keyTarget, pwIdent, pwIdent.PassphraseRef)
	if len(displacedPW) != 1 || displacedPW[0] != *pwRef {
		t.Fatalf("displaced refs for password->key = %+v, want [%v]", displacedPW, *pwRef)
	}

	keyIdent := models.Identity{User: "ops", AuthType: "key", PassphraseRef: ppRef.Clone()}
	pwTarget := credential.Target{NodeID: "n1", Kind: credential.KindLoginPassword, AuthType: "password", ClearKeyPath: true}
	displacedPP := collectDisplacedCrossKindRefs(pwTarget, keyIdent, keyIdent.LoginPasswordRef)
	if len(displacedPP) != 1 || displacedPP[0] != *ppRef {
		t.Fatalf("displaced refs for key->password = %+v, want [%v]", displacedPP, *ppRef)
	}
}
