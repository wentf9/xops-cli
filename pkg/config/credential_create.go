package config

import (
	"context"
	"fmt"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

// credentialCreateUpdater publishes a new node bundle only after the service
// has stored and verified its secret. Recovery inspects refs without replaying
// creation, using the same repository updater as ordinary credential writes.
type credentialCreateUpdater struct {
	*RepositoryConfigUpdater
	nodeID   string
	node     models.Node
	host     models.Host
	identity models.Identity
}

// NodeCredentialCreate binds an authentication credential to atomic node creation.
// An empty expected version denotes an absent node; CreateNodeContext checks
// absence and referenced-record conflicts under the durable transaction lock.
func (r *Repository) NodeCredentialCreate(nodeID string, node models.Node, host models.Host, identity models.Identity) credential.ConfigUpdater {
	return &credentialCreateUpdater{RepositoryConfigUpdater: NewRepositoryConfigUpdater(r),
		nodeID: nodeID, node: cloneNode(node), host: cloneHost(host), identity: cloneIdentity(identity)}
}

func (u *credentialCreateUpdater) ApplyCredentialRefAtVersion(ctx context.Context, target credential.Target, expectedVersion string, newRef *credential.Ref) (credential.MutationOutcome, string, error) {
	if u.nodeID == "" || target.NodeID != u.nodeID || target.IdentityID != "" || expectedVersion != "" {
		return credential.MutationOutcome{}, "", fmt.Errorf("%w: credential target does not match node creation", coreauth.ErrConfigConflict)
	}
	if (target.Kind != credential.KindLoginPassword && target.Kind != credential.KindPassphrase) || newRef == nil || newRef.IsEmpty() {
		return credential.MutationOutcome{}, "", fmt.Errorf("%w: node creation requires an authentication credential reference", coreauth.ErrInvalidRef)
	}
	if err := newRef.Validate(); err != nil {
		return credential.MutationOutcome{}, "", err
	}
	identity := cloneIdentity(u.identity)
	if target.Kind == credential.KindLoginPassword {
		identity.Password = ""
		identity.LoginPasswordRef = newRef.Clone()
	} else {
		identity.Passphrase = ""
		identity.PassphraseRef = newRef.Clone()
	}
	applyIdentityCredentialMetadata(&identity, target)
	mutation, err := u.repo.CreateNodeContext(ctx, u.nodeID, u.node, u.host, identity)
	return credential.MutationOutcome{Applied: mutation.Outcome.Applied, Durable: mutation.Outcome.Durable}, mutation.AuthVersion, adaptConfigError(err)
}

// identityCredentialCreateUpdater publishes a new identity only after the
// credential service has stored and verified its secret.
type identityCredentialCreateUpdater struct {
	*RepositoryConfigUpdater
	identityID string
	identity   models.Identity
}

// IdentityCredentialCreate binds an authentication credential to atomic identity
// creation. An empty expected version denotes an absent identity; creation checks
// absence under the durable transaction lock and publishes the identity with its
// credential reference in one atomic commit.
func (r *Repository) IdentityCredentialCreate(identityID string, identity models.Identity) credential.ConfigUpdater {
	return &identityCredentialCreateUpdater{
		RepositoryConfigUpdater: NewRepositoryConfigUpdater(r),
		identityID:              identityID,
		identity:                cloneIdentity(identity),
	}
}

func (u *identityCredentialCreateUpdater) ApplyCredentialRefAtVersion(ctx context.Context, target credential.Target, expectedVersion string, newRef *credential.Ref) (credential.MutationOutcome, string, error) {
	if u.identityID == "" || target.IdentityID != u.identityID || target.NodeID != "" || expectedVersion != "" {
		return credential.MutationOutcome{}, "", fmt.Errorf("%w: credential target does not match identity creation", coreauth.ErrConfigConflict)
	}
	if (target.Kind != credential.KindLoginPassword && target.Kind != credential.KindPassphrase) || newRef == nil || newRef.IsEmpty() {
		return credential.MutationOutcome{}, "", fmt.Errorf("%w: identity creation requires an authentication credential reference", coreauth.ErrInvalidRef)
	}
	if err := newRef.Validate(); err != nil {
		return credential.MutationOutcome{}, "", err
	}
	identity := cloneIdentity(u.identity)
	if target.Kind == credential.KindLoginPassword {
		identity.Password = ""
		identity.LoginPasswordRef = newRef.Clone()
	} else {
		identity.Passphrase = ""
		identity.PassphraseRef = newRef.Clone()
	}
	applyIdentityCredentialMetadata(&identity, target)
	var version Version
	result, err := u.repo.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		if _, exists := cfg.Identities.Get(u.identityID); exists {
			return fmt.Errorf("create identity %q: %w", u.identityID, ErrConfigConflict)
		}
		cfg.Identities.Set(u.identityID, cloneIdentity(identity))
		var verErr error
		version, verErr = identityEntityVersion(cfg, u.identityID)
		return verErr
	})
	if !result.Applied {
		return credential.MutationOutcome{}, "", adaptConfigError(err)
	}
	return credential.MutationOutcome{Applied: result.Applied, Durable: result.Durable}, string(version[:]), adaptConfigError(err)
}
