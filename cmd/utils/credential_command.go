package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	"golang.org/x/term"
)

// CredentialTargetScope controls how a credential command resolves its target argument.
type CredentialTargetScope int

const (
	CredentialScopeIdentity CredentialTargetScope = iota
	CredentialScopeNode
	CredentialScopeAuto
)

// CredentialCommandOptions holds flags for setting or deleting a credential.
type CredentialCommandOptions struct {
	Scope           CredentialTargetScope
	KindStr         string
	StoreID         string
	RuleName        string
	PasswordStdin   bool
	PassphraseStdin bool
	KindPassword    bool
	KindPassphrase  bool
	KindTOTP        bool
	KindSudo        bool
	ChallengeRule   string
	ForceNode       bool
	ForceIdentity   bool
}

// RegisterSetFlags registers flags for a credential set command.
func (o *CredentialCommandOptions) RegisterSetFlags(cmd *cobra.Command) {
	o.registerCommonFlags(cmd)
	cmd.Flags().StringVar(&o.StoreID, "store", "", i18n.T("flag_credential_store"))
	cmd.Flags().BoolVar(&o.PasswordStdin, "password-stdin", false, i18n.T("flag_password_stdin"))
	cmd.Flags().BoolVar(&o.PassphraseStdin, "passphrase-stdin", false, i18n.T("flag_passphrase_stdin"))
	cmd.MarkFlagsMutuallyExclusive("password-stdin", "passphrase-stdin")
}

// RegisterDeleteFlags registers flags for a credential delete command.
func (o *CredentialCommandOptions) RegisterDeleteFlags(cmd *cobra.Command) {
	o.registerCommonFlags(cmd)
}

func (o *CredentialCommandOptions) registerCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.KindStr, "kind", "login_password", i18n.T("flag_credential_kind"))
	cmd.Flags().StringVar(&o.RuleName, "rule", "", i18n.T("flag_credential_rule"))
	cmd.Flags().BoolVar(&o.KindPassword, "password", false, i18n.T("flag_cred_kind_password"))
	cmd.Flags().BoolVar(&o.KindPassphrase, "passphrase", false, i18n.T("flag_cred_kind_passphrase"))
	cmd.Flags().BoolVar(&o.KindTOTP, "totp", false, i18n.T("flag_cred_kind_totp"))
	cmd.Flags().BoolVar(&o.KindSudo, "sudo", false, i18n.T("flag_cred_kind_sudo"))
	cmd.Flags().StringVar(&o.ChallengeRule, "challenge", "", i18n.T("flag_cred_kind_challenge"))
	cmd.MarkFlagsMutuallyExclusive("kind", "password", "passphrase", "totp", "sudo", "challenge")
	cmd.MarkFlagsMutuallyExclusive("challenge", "rule")

	if o.Scope == CredentialScopeAuto {
		cmd.Flags().BoolVarP(&o.ForceNode, "node", "N", false, i18n.T("flag_cred_target_node"))
		cmd.Flags().BoolVarP(&o.ForceIdentity, "identity", "I", false, i18n.T("flag_cred_target_identity"))
		cmd.MarkFlagsMutuallyExclusive("node", "identity")
	}
}

func (o *CredentialCommandOptions) isIdentityOnly() bool {
	return o.Scope == CredentialScopeIdentity || o.ForceIdentity
}

func (o *CredentialCommandOptions) resolveKindAndRule() (credential.Kind, string, error) {
	rule := o.RuleName
	var kind credential.Kind
	switch {
	case o.KindPassword:
		kind = credential.KindLoginPassword
	case o.KindPassphrase:
		kind = credential.KindPassphrase
	case o.KindTOTP:
		kind = credential.KindTOTPSecret
	case o.KindSudo:
		kind = credential.KindPrivilegePassword
	case o.ChallengeRule != "":
		kind = credential.KindChallengeAnswer
		rule = o.ChallengeRule
	default:
		kind = credential.Kind(o.KindStr)
	}

	if o.isIdentityOnly() && kind == credential.KindPrivilegePassword {
		return "", "", fmt.Errorf("invalid credential kind %q for identity: must be login_password, passphrase, totp_secret, or challenge_answer", kind)
	}
	if err := kind.Validate(); err != nil {
		if o.isIdentityOnly() {
			return "", "", fmt.Errorf("invalid credential kind %q: must be login_password, passphrase, totp_secret, or challenge_answer", kind)
		}
		return "", "", fmt.Errorf("invalid credential kind %q: must be login_password, passphrase, privilege_password, totp_secret, or challenge_answer", kind)
	}
	if kind == credential.KindChallengeAnswer && strings.TrimSpace(rule) == "" {
		return "", "", errors.New(i18n.T("err_rule_required_for_challenge"))
	}
	return kind, rule, nil
}

type resolvedCredentialTarget struct {
	isNode          bool
	nodeID          string
	identityID      string
	identity        models.Identity
	oldRef          *credential.Ref
	expectedVersion string
	target          credential.Target
}

func (o *CredentialCommandOptions) shouldUseNodeTarget(repo *config.Repository, view config.ConfigView, query string, kind credential.Kind) (bool, error) {
	if o.Scope == CredentialScopeNode || o.ForceNode || kind == credential.KindPrivilegePassword {
		return true, nil
	}
	if o.Scope == CredentialScopeIdentity || o.ForceIdentity {
		return false, nil
	}
	nodeID, nodeErr := repo.ResolveSelector(query)
	isSavedNode := nodeErr == nil && nodeID != "" && view.NodeRefs[nodeID].ID != ""
	_, isIdentity := view.Configuration.Identities.Get(query)
	if isSavedNode && isIdentity && query != nodeID {
		return false, fmt.Errorf("target %q matches both node %q and identity %q; specify --node or --identity", query, nodeID, query)
	}
	if isSavedNode {
		return true, nil
	}
	if isIdentity {
		return false, nil
	}
	if nodeErr != nil {
		return false, nodeErr
	}
	return false, fmt.Errorf("target %q not found in nodes or identities", query)
}

func (o *CredentialCommandOptions) resolveTarget(repo *config.Repository, view config.ConfigView, query string, kind credential.Kind, ruleName string) (resolvedCredentialTarget, error) {
	useNode, err := o.shouldUseNodeTarget(repo, view, query, kind)
	if err != nil {
		return resolvedCredentialTarget{}, err
	}
	if !useNode {
		return resolveIdentityCredentialTarget(view, query, kind, ruleName)
	}
	return resolveNodeCredentialTarget(repo, view, query, kind, ruleName)
}

func resolveIdentityCredentialTarget(view config.ConfigView, query string, kind credential.Kind, ruleName string) (resolvedCredentialTarget, error) {
	ident, ok := view.Configuration.Identities.Get(query)
	if !ok {
		return resolvedCredentialTarget{}, fmt.Errorf("%s", i18n.Tf("identity_err_not_found", map[string]any{"Name": query}))
	}
	ref, ok := view.IdentityRefs[query]
	if !ok {
		return resolvedCredentialTarget{}, fmt.Errorf("resolve identity %q reference: %w", query, config.ErrIdentityNotFound)
	}
	if kind == credential.KindChallengeAnswer {
		if err := validateChallengeRule(ident, ruleName, query); err != nil {
			return resolvedCredentialTarget{}, err
		}
	}
	return resolvedCredentialTarget{
		isNode:          false,
		identityID:      query,
		identity:        ident,
		oldRef:          findIdentityOldRef(kind, ident, ruleName),
		expectedVersion: string(ref.Version[:]),
		target: credential.Target{
			IdentityID: query,
			Kind:       kind,
			RuleName:   ruleName,
		},
	}, nil
}

func resolveNodeCredentialTarget(repo *config.Repository, view config.ConfigView, query string, kind credential.Kind, ruleName string) (resolvedCredentialTarget, error) {
	nodeID, err := repo.ResolveSelector(query)
	if err != nil {
		return resolvedCredentialTarget{}, fmt.Errorf("resolve node %q: %w", query, err)
	}
	if nodeID == "" || view.NodeRefs[nodeID].ID == "" {
		return resolvedCredentialTarget{}, fmt.Errorf("节点 %s 不存在", query)
	}
	snap, err := repo.ResolveConnection(nodeID)
	if err != nil {
		return resolvedCredentialTarget{}, fmt.Errorf("resolve node %q connection: %w", nodeID, err)
	}
	if snap.UpdateRef == nil {
		return resolvedCredentialTarget{}, fmt.Errorf("node %q is read-only", nodeID)
	}

	if kind == credential.KindPrivilegePassword {
		return resolvedCredentialTarget{
			isNode:          true,
			nodeID:          nodeID,
			identity:        snap.Identity,
			oldRef:          snap.Node.PrivilegePasswordRef,
			expectedVersion: string(snap.UpdateRef.SudoVersion[:]),
			target: credential.Target{
				NodeID: nodeID,
				Kind:   kind,
			},
		}, nil
	}

	if kind == credential.KindChallengeAnswer {
		if err := validateChallengeRule(snap.Identity, ruleName, nodeID); err != nil {
			return resolvedCredentialTarget{}, err
		}
	}

	target := buildNodeAuthTarget(nodeID, kind, ruleName, snap.Identity.AuthType)
	return resolvedCredentialTarget{
		isNode:          true,
		nodeID:          nodeID,
		identity:        snap.Identity,
		oldRef:          findIdentityOldRef(kind, snap.Identity, ruleName),
		expectedVersion: string(snap.UpdateRef.AuthVersion[:]),
		target:          target,
	}, nil
}

func buildNodeAuthTarget(nodeID string, kind credential.Kind, ruleName, currentAuthType string) credential.Target {
	target := credential.Target{
		NodeID:   nodeID,
		Kind:     kind,
		RuleName: ruleName,
	}
	isMFA := currentAuthType == "keyboard-interactive" || currentAuthType == "otp"
	switch kind {
	case credential.KindLoginPassword:
		target.ClearLegacyLoginPassword = true
		if !isMFA {
			target.AuthType = "password"
			target.ClearKeyPath = true
			target.ClearLegacyPassphrase = true
		}
	case credential.KindPassphrase:
		target.ClearLegacyPassphrase = true
		if !isMFA {
			target.AuthType = "key"
		}
	}
	return target
}

// RunSet executes a credential set command.
func (o *CredentialCommandOptions) RunSet(cmd *cobra.Command, query string) error {
	kind, ruleName, err := o.resolveKindAndRule()
	if err != nil {
		return err
	}

	_, repo, cfg, err := GetConfigStore()
	if err != nil {
		return err
	}
	resolved, err := o.resolveTarget(repo, repo.View(), query, kind, ruleName)
	if err != nil {
		return err
	}

	if kind == credential.KindPassphrase && resolved.identity.KeyPath == "" {
		return fmt.Errorf("private-key path is required before setting a passphrase")
	}

	secretStr, err := resolveSecretInput(cmd.InOrStdin(), o.PasswordStdin || o.PassphraseStdin, string(kind))
	if err != nil {
		return err
	}

	if kind == credential.KindTOTPSecret {
		totpCfg, err := coreauth.ParseTOTPSecret(secretStr)
		if err != nil {
			return fmt.Errorf("invalid TOTP secret: %w", err)
		}
		clear(totpCfg.Secret)
	}

	targetStore := defaultTargetStore(o.StoreID, cfg)
	svc, err := GetCredentialService(repo, cfg)
	if err != nil {
		return fmt.Errorf("initialize credential service: %w", err)
	}

	target := resolved.target
	if kind == credential.KindPassphrase {
		target.KeyPath = resolved.identity.KeyPath
		target, err = config.BindPrivateKeyFingerprint(cfg, target, []byte(secretStr))
		if err != nil {
			return err
		}
	}

	secret := credential.NewSecret([]byte(secretStr))
	defer secret.Zero()
	newRef, _, err := svc.Rotate(cmd.Context(), target, resolved.expectedVersion, resolved.oldRef, targetStore, secret)
	if err != nil {
		return fmt.Errorf("rotate credential in store failed: %w", err)
	}

	if resolved.isNode {
		logger.PrintSuccessf("Set credential for node %q (kind: %s, store: %s, itemID: %s)", resolved.nodeID, kind, targetStore, newRef.ItemID)
	} else {
		logger.PrintSuccessf("Set credential for identity %q (kind: %s, store: %s, itemID: %s)", resolved.identityID, kind, targetStore, newRef.ItemID)
	}
	return nil
}

func defaultTargetStore(storeID string, cfg *config.Configuration) string {
	if storeID != "" {
		return storeID
	}
	if cfg.Credential != nil && cfg.Credential.DefaultStore != "" {
		return cfg.Credential.DefaultStore
	}
	return "none"
}

// RunDelete executes a credential delete command.
func (o *CredentialCommandOptions) RunDelete(cmd *cobra.Command, query string) error {
	kind, ruleName, err := o.resolveKindAndRule()
	if err != nil {
		return err
	}

	_, repo, cfg, err := GetConfigStore()
	if err != nil {
		return err
	}
	resolved, err := o.resolveTarget(repo, repo.View(), query, kind, ruleName)
	if err != nil {
		return err
	}

	svc, err := GetCredentialService(repo, cfg)
	if err != nil {
		return fmt.Errorf("initialize credential service: %w", err)
	}

	targetLabel, entityType := resolved.identityID, "identity"
	if resolved.isNode {
		targetLabel, entityType = resolved.nodeID, "node"
	}

	if resolved.oldRef != nil && !resolved.oldRef.IsEmpty() {
		if _, err := svc.Delete(cmd.Context(), resolved.target, resolved.expectedVersion, *resolved.oldRef); err != nil {
			return fmt.Errorf("delete credential for %s %q: %w", entityType, targetLabel, err)
		}
	} else {
		updater := repo.AsConfigUpdater()
		if _, _, err := updater.ApplyCredentialRefAtVersion(cmd.Context(), resolved.target, resolved.expectedVersion, nil); err != nil {
			return fmt.Errorf("clear credential for %s %q: %w", entityType, targetLabel, err)
		}
	}

	logger.PrintSuccessf("Successfully deleted %s credential for %s %q", kind, entityType, targetLabel)
	return nil
}

func resolveSecretInput(r io.Reader, stdin bool, kindStr string) (string, error) {
	if stdin {
		return ReadSecretFromReader(r)
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		prompt := fmt.Sprintf("Enter %s: ", kindStr)
		return ReadPasswordFromTerminal(prompt)
	}
	return "", errors.New("terminal is not interactive, please provide secret via --password-stdin")
}

func validateChallengeRule(ident models.Identity, ruleName, targetName string) error {
	if ident.KeyboardInteractive != nil {
		for _, r := range ident.KeyboardInteractive.Rules {
			if r.Name == ruleName {
				return nil
			}
		}
	}
	return fmt.Errorf("challenge rule %q not found in %q", ruleName, targetName)
}

func findIdentityOldRef(kind credential.Kind, ident models.Identity, ruleName string) *credential.Ref {
	switch kind {
	case credential.KindLoginPassword:
		return ident.LoginPasswordRef
	case credential.KindPassphrase:
		return ident.PassphraseRef
	case credential.KindTOTPSecret:
		if ident.OTP != nil {
			return ident.OTP.TOTPSecretRef
		}
	case credential.KindChallengeAnswer:
		if ident.KeyboardInteractive != nil {
			for _, r := range ident.KeyboardInteractive.Rules {
				if r.Name == ruleName {
					return r.SecretRef
				}
			}
		}
	}
	return nil
}
