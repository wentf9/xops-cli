package config

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

// credentialEditUpdater commits the displayed inventory edit with the ref in
// one repository transaction. Recovery only checks the final target and refs;
// it never replays edits, so no inventory fields or secrets enter the journal.
type credentialEditUpdater struct {
	*RepositoryConfigUpdater
	nodeRef     NodeRef
	identityRef IdentityRef
	nodeID      string
	node        models.Node
	host        models.Host
	identity    models.Identity
}

// IdentityCredentialEdit binds a credential transaction to an exact identity
// edit. The returned updater retains defensive copies for a single operation.
func (r *Repository) IdentityCredentialEdit(ref IdentityRef, identity models.Identity) credential.ConfigUpdater {
	return &credentialEditUpdater{RepositoryConfigUpdater: NewRepositoryConfigUpdater(r), identityRef: ref, identity: cloneIdentity(identity)}
}

// NodeCredentialEdit binds a credential transaction to an exact node bundle,
// including renames and private copies of shared hosts and identities.
func (r *Repository) NodeCredentialEdit(ref NodeRef, nodeID string, node models.Node, host models.Host, identity models.Identity) credential.ConfigUpdater {
	return &credentialEditUpdater{RepositoryConfigUpdater: NewRepositoryConfigUpdater(r), nodeRef: ref, nodeID: nodeID,
		node: cloneNode(node), host: cloneHost(host), identity: cloneIdentity(identity)}
}

func (u *credentialEditUpdater) ApplyCredentialRefAtVersion(ctx context.Context, target credential.Target, expectedVersion string, newRef *credential.Ref) (credential.MutationOutcome, string, error) {
	if target.Kind != credential.KindLoginPassword && target.Kind != credential.KindPassphrase {
		return credential.MutationOutcome{}, "", fmt.Errorf("%w: inventory edit requires an authentication credential", credential.ErrInvalidRef)
	}
	if newRef != nil {
		if err := newRef.Validate(); err != nil {
			return credential.MutationOutcome{}, "", err
		}
	}
	if err := u.validateTarget(target, expectedVersion); err != nil {
		return credential.MutationOutcome{}, "", err
	}
	identity := cloneIdentity(u.identity)
	if target.Kind == credential.KindLoginPassword {
		identity.LoginPasswordRef = newRef.Clone()
		identity.Password = ""
	} else {
		identity.PassphraseRef = newRef.Clone()
		identity.Passphrase = ""
	}
	applyIdentityCredentialMetadata(&identity, target)
	var version Version
	result, err := u.repo.commitResultContext(ctx, anyRevision, func(cfg *Configuration) error {
		var err error
		if u.nodeRef.ID != "" {
			if err := replaceNodeAtRef(cfg, u.nodeRef, u.nodeID, u.node, u.host, identity); err != nil {
				return err
			}
			version, err = nodeAuthVersion(cfg, u.nodeID)
		} else {
			if err := ensureIdentityRef(cfg, u.identityRef); err != nil {
				return err
			}
			cfg.Identities.Set(u.identityRef.ID, identity)
			version, err = identityEntityVersion(cfg, u.identityRef.ID)
		}
		return err
	})
	if !result.Applied {
		return credential.MutationOutcome{}, "", adaptConfigError(err)
	}
	return credential.MutationOutcome{Applied: result.Applied, Durable: result.Durable}, string(version[:]), adaptConfigError(err)
}

func (u *credentialEditUpdater) validateTarget(target credential.Target, expectedVersion string) error {
	if u.nodeRef.ID != "" {
		if u.nodeID != "" && target.NodeID == u.nodeID && target.IdentityID == "" && expectedVersion == string(u.nodeRef.Version[:]) {
			return nil
		}
	} else if u.identityRef.ID != "" && target.IdentityID == u.identityRef.ID && target.NodeID == "" && expectedVersion == string(u.identityRef.Version[:]) {
		return nil
	}
	return fmt.Errorf("%w: credential target does not match the displayed inventory edit", credential.ErrConfigConflict)
}
