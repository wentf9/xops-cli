package config

import (
	"context"
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/pkg/credential"
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
		identity, _ := cfg.Identities.Get(node.IdentityRef)
		credentials = appendCredentialRefs(credentials, node.PrivilegePasswordRef, identity.LoginPasswordRef, identity.PassphraseRef)
	}
	return deleteAssetsWithCredentials(ctx, service, credentials, func(ctx context.Context) (MutationOutcome, error) {
		return r.deleteNodesAtRefsWithOutcome(ctx, refs)
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
	refs := appendCredentialRefs(nil, identity.LoginPasswordRef, identity.PassphraseRef)
	return deleteAssetsWithCredentials(ctx, service, refs, func(ctx context.Context) (MutationOutcome, error) {
		return r.DeleteIdentityAtRefContext(ctx, ref)
	})
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
		return fmt.Errorf("%w: asset deletion requires a credential cleanup service", credential.ErrCredentialStoreUnavailable)
	}
	_, err := service.DeleteAssets(ctx, refs, func(ctx context.Context) (credential.MutationOutcome, error) {
		outcome, err := commit(ctx)
		return credential.MutationOutcome{Applied: outcome.Applied, Durable: outcome.Durable}, err
	})
	return err
}
