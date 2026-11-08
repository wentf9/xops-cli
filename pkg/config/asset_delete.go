package config

import (
	"context"
	"fmt"
	"slices"

	coreauth "github.com/wentf9/xops-cli/core/auth"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

// DeleteNodesWithCredentialsContext atomically removes selected assets, then
// cleans up their now-unreferenced credentials through a recoverable journal.
func (r *Repository) DeleteNodesWithCredentialsContext(ctx context.Context, refs []NodeRef, service *credential.Service) error {
	refs = slices.Clone(refs)
	cfg := r.Snapshot()
	if err := ensureNodeRefs(cfg, refs); err != nil {
		return err
	}
	var credentials []credential.Ref
	for _, ref := range refs {
		node, _ := cfg.Nodes.Get(ref.ID)
		credentials = appendCredentialRefs(credentials, node.PrivilegePasswordRef)
		if identity, ok := cfg.Identities.Get(node.IdentityRef); ok {
			credentials = appendIdentityCredentialRefs(credentials, identity)
		}
	}
	return deleteAssetsWithCredentials(ctx, service, credentials, func(ctx context.Context) (MutationOutcome, error) {
		return r.deleteNodesAtRefsWithOutcome(ctx, refs)
	})
}

// ReplaceNodeWithCredentialsContext atomically replaces a node bundle and,
// when its identity reference changes, cleans up any now-unreferenced
// credentials from the previous identity through a recoverable journal.
func (r *Repository) ReplaceNodeWithCredentialsContext(ctx context.Context, ref NodeRef, nodeID string, node models.Node, host models.Host, identity models.Identity, service *credential.Service) error {
	cfg := r.Snapshot()
	if err := ensureNodeRefs(cfg, []NodeRef{ref}); err != nil {
		return err
	}
	var credentials []credential.Ref
	if oldNode, ok := cfg.Nodes.Get(ref.ID); ok && oldNode.IdentityRef != node.IdentityRef {
		if oldIdentity, ok := cfg.Identities.Get(oldNode.IdentityRef); ok {
			credentials = appendIdentityCredentialRefs(credentials, oldIdentity)
		}
	}
	return deleteAssetsWithCredentials(ctx, service, credentials, func(ctx context.Context) (MutationOutcome, error) {
		outcome, _, err := r.replaceNodeAtRefWithOutcome(ctx, ref, nodeID, node, host, identity)
		return outcome, err
	})
}

// DeleteIdentityWithCredentialsContext also retains the existing restriction
// that an identity referenced by any node cannot be deleted.
func (r *Repository) DeleteIdentityWithCredentialsContext(ctx context.Context, ref IdentityRef, service *credential.Service) error {
	cfg := r.Snapshot()
	if err := ensureIdentityRef(cfg, ref); err != nil {
		return err
	}
	identity, _ := cfg.Identities.Get(ref.ID)
	refs := appendIdentityCredentialRefs(nil, identity)
	return deleteAssetsWithCredentials(ctx, service, refs, func(ctx context.Context) (MutationOutcome, error) {
		return r.DeleteIdentityAtRefContext(ctx, ref)
	})
}

func appendIdentityCredentialRefs(refs []credential.Ref, identity models.Identity) []credential.Ref {
	refs = appendCredentialRefs(refs, identity.LoginPasswordRef, identity.PassphraseRef)
	if identity.OTP != nil {
		refs = appendCredentialRefs(refs, identity.OTP.TOTPSecretRef)
	}
	if identity.KeyboardInteractive != nil {
		for _, r := range identity.KeyboardInteractive.Rules {
			refs = appendCredentialRefs(refs, r.SecretRef)
		}
	}
	return refs
}

func appendCredentialRefs(refs []credential.Ref, candidates ...*credential.Ref) []credential.Ref {
	for _, ref := range candidates {
		if ref != nil && !ref.IsEmpty() {
			refs = append(refs, *ref)
		}
	}
	return refs
}

func deleteAssetsWithCredentials(ctx context.Context, service *credential.Service, refs []credential.Ref, commit func(context.Context) (MutationOutcome, error)) error {
	if len(refs) == 0 {
		_, err := commit(ctx)
		return err
	}
	if service == nil {
		return fmt.Errorf("%w: asset deletion requires a credential cleanup service", coreauth.ErrCredentialStoreUnavailable)
	}
	_, err := service.DeleteAssets(ctx, refs, func(ctx context.Context) (credential.MutationOutcome, error) {
		outcome, err := commit(ctx)
		return credential.MutationOutcome{Applied: outcome.Applied, Durable: outcome.Durable}, err
	})
	return err
}
