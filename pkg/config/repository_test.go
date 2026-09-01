package config

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/pkg/models"
)

var errRepositoryPersist = errors.New("persist configuration")

type repositoryTestStore struct {
	mu     sync.Mutex
	result PersistResult
	err    error
	saves  int
}

func createIdentity(repository *Repository, identityID string, identity models.Identity) error {
	_, err := repository.CreateIdentityContext(context.Background(), identityID, identity)
	return err
}

func createNode(repository *Repository, nodeID string, node models.Node, host models.Host, identity models.Identity) error {
	_, err := repository.CreateNodeContext(context.Background(), nodeID, node, host, identity)
	return err
}

func (s *repositoryTestStore) Load() (*Configuration, error) {
	return cloneConfiguration(nil), nil
}

func (s *repositoryTestStore) Save(*Configuration) error {
	return s.err
}

func (s *repositoryTestStore) save(*Configuration) (PersistResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	return s.result, s.err
}

func TestRepository_DoesNotPublishPreReplaceFailure(t *testing.T) {
	store := &repositoryTestStore{err: errRepositoryPersist}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	err = createIdentity(repository, "new", models.Identity{User: "new"})
	if !errors.Is(err, errRepositoryPersist) {
		t.Fatalf("AddIdentity() error = %v, want %v", err, errRepositoryPersist)
	}
	if _, ok := repository.ListIdentities()["new"]; ok {
		t.Fatal("AddIdentity() published a state that was not persisted")
	}
	if got := repository.Revision(); got != 0 {
		t.Fatalf("Revision() = %d, want 0", got)
	}
}

func TestRepository_PublishesAppliedUndurableState(t *testing.T) {
	store := &repositoryTestStore{
		result: PersistResult{Applied: true},
		err:    errRepositoryPersist,
	}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	err = createIdentity(repository, "new", models.Identity{User: "new"})
	var durabilityErr *DurabilityError
	if !errors.As(err, &durabilityErr) {
		t.Fatalf("AddIdentity() error = %v, want DurabilityError", err)
	}
	if !errors.Is(err, errRepositoryPersist) {
		t.Fatalf("AddIdentity() error = %v, want wrapped persist error", err)
	}
	if _, ok := repository.ListIdentities()["new"]; !ok {
		t.Fatal("AddIdentity() did not publish the applied state")
	}
	if got := repository.Revision(); got != 1 {
		t.Fatalf("Revision() = %d, want 1", got)
	}
}

func TestRepositoryCreateNodeReturnsRefAfterAppliedUndurableWrite(t *testing.T) {
	store := &repositoryTestStore{
		result: PersistResult{Applied: true},
		err:    errRepositoryPersist,
	}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	mutation, err := repository.CreateNodeContext(t.Context(), "temporary", models.Node{
		HostRef:     "temporary-host",
		IdentityRef: "temporary-identity",
	}, models.Host{Address: "192.0.2.20", Port: 22}, models.Identity{User: "root"})
	var durabilityErr *DurabilityError
	if !errors.As(err, &durabilityErr) {
		t.Fatalf("CreateNodeContext() error = %v, want DurabilityError", err)
	}
	if !mutation.Outcome.Applied || mutation.Outcome.Durable {
		t.Fatalf("mutation outcome = %+v, want applied and undurable", mutation.Outcome)
	}
	if mutation.Ref.ID != "temporary" || mutation.Ref.Version == (Version{}) {
		t.Fatalf("mutation ref = %+v, want applied node ref", mutation.Ref)
	}
}

func TestRepositoryReplaceNodeAtRefCopiesSharedHostAndIdentity(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	initial := newTestProvider().Snapshot()
	host, _ := initial.Hosts.Get("host-web")
	host.Alias = nil
	initial.Hosts.Set("host-web", host)
	repository, err := NewRepositoryWithoutOpenSSH(initial, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	baseNode, baseHost, baseIdentity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("resolve base node: %v", err)
	}
	if _, err := repository.CreateNodeContext(t.Context(), "peer", models.Node{
		HostRef:     baseNode.HostRef,
		IdentityRef: baseNode.IdentityRef,
	}, baseHost, baseIdentity); err != nil {
		t.Fatalf("create peer node: %v", err)
	}

	ref := repository.View().NodeRefs["web-server"]
	baseHost.Address = "192.0.2.99"
	baseIdentity.Password = "new-password"
	baseIdentity.AuthType = "password"
	if err := repository.ReplaceNodeAtRefContext(t.Context(), ref, "web-server", baseNode, baseHost, baseIdentity); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext() error = %v", err)
	}

	updated, _, updatedIdentity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("resolve updated node: %v", err)
	}
	peer, peerHost, peerIdentity, err := repository.Resolve("peer")
	if err != nil {
		t.Fatalf("resolve peer node: %v", err)
	}
	if updated.HostRef == peer.HostRef || updated.IdentityRef == peer.IdentityRef {
		t.Fatalf("updated node still shares mutable references: updated=%+v peer=%+v", updated, peer)
	}
	if peerHost.Address == baseHost.Address || peerIdentity.Password == updatedIdentity.Password {
		t.Fatalf("node edit changed peer shared values: host=%+v identity=%+v", peerHost, peerIdentity)
	}
}

func TestRepositoryReplaceNodeAtRefDoesNotOverwriteNewSharedReferences(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	peerNode := models.Node{HostRef: "peer-host", IdentityRef: "peer-identity"}
	peerHost := models.Host{Address: "192.0.2.20", Port: 22}
	peerIdentity := models.Identity{User: "deploy", AuthType: "password", Password: "peer-password"}
	if _, err := repository.CreateNodeContext(t.Context(), "peer", peerNode, peerHost, peerIdentity); err != nil {
		t.Fatalf("CreateNodeContext() error = %v", err)
	}

	node, host, identity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	node.HostRef = peerNode.HostRef
	node.IdentityRef = peerNode.IdentityRef
	host.Address = "192.0.2.99"
	identity.User = "admin"
	identity.Password = "replacement-password"
	identity.AuthType = "password"
	if err := repository.ReplaceNodeAtRefContext(t.Context(), repository.View().NodeRefs["web-server"], "web-server", node, host, identity); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext() error = %v", err)
	}

	updated, updatedHost, updatedIdentity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("resolve updated node: %v", err)
	}
	peer, actualPeerHost, actualPeerIdentity, err := repository.Resolve("peer")
	if err != nil {
		t.Fatalf("resolve peer node: %v", err)
	}
	if updated.HostRef == peer.HostRef || updated.IdentityRef == peer.IdentityRef {
		t.Fatalf("replacement reused peer mutable refs: updated=%+v peer=%+v", updated, peer)
	}
	if updatedHost.Address != "192.0.2.99" || updatedIdentity.Password != "replacement-password" {
		t.Fatalf("updated node values = host=%+v identity=%+v", updatedHost, updatedIdentity)
	}
	if actualPeerHost.Address != peerHost.Address || actualPeerIdentity.Password != peerIdentity.Password {
		t.Fatalf("replacement changed peer values: host=%+v identity=%+v", actualPeerHost, actualPeerIdentity)
	}
}

func TestRepositoryDeleteNodeAtRefDoesNotDeleteReplacement(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	stale := repository.View().NodeRefs["web-server"]
	if _, err := repository.UpdateNodeTagsContext(t.Context(), []string{"web-server"}, []string{"changed"}, true); err != nil {
		t.Fatalf("update node tags: %v", err)
	}
	if _, err := repository.DeleteNodeAtRefContext(t.Context(), stale); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("DeleteNodeAtRefContext() error = %v, want ErrConfigConflict", err)
	}
	if _, exists := repository.GetNode("web-server"); !exists {
		t.Fatal("conditional delete removed a changed node")
	}
}

func TestRepositoryReplaceNodeRejectsEmptyRef(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	node, host, identity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if err := repository.ReplaceNodeAtRefContext(t.Context(), NodeRef{}, "web-server", node, host, identity); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("ReplaceNodeAtRefContext() error = %v, want ErrConfigConflict", err)
	}
}

func TestRepositoryUpdateAuthAtVersionRejectsConcurrentCredentialEdit(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	connection, err := repository.ResolveConnection("web-server")
	if err != nil {
		t.Fatalf("ResolveConnection() error = %v", err)
	}
	if connection.UpdateRef == nil {
		t.Fatal("ResolveConnection() returned no update reference for persisted node")
	}
	authVersion := string(connection.UpdateRef.AuthVersion[:])
	view := repository.View()
	identity, _ := view.Configuration.Identities.Get("id-admin")
	identity.Password = "user-password"
	identity.AuthType = "password"
	if _, err := repository.ReplaceIdentityAtRefContext(t.Context(), view.IdentityRefs["id-admin"], identity); err != nil {
		t.Fatalf("replace shared identity: %v", err)
	}

	err = repository.UpdateAuthAtVersionContext(t.Context(), "web-server", authVersion, "discovered-password", "", "")
	if !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("UpdateAuthAtVersionContext() error = %v, want ErrConfigConflict", err)
	}
	_, _, finalIdentity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("resolve final node: %v", err)
	}
	if finalIdentity.Password != "user-password" {
		t.Fatalf("stale discovery overwrote user credential: %+v", finalIdentity)
	}
}

func TestRepositoryUpdateAuthAtVersionCopiesSharedIdentity(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	initial := newTestProvider().Snapshot()
	host, _ := initial.Hosts.Get("host-web")
	host.Alias = nil
	initial.Hosts.Set("host-web", host)
	repository, err := NewRepositoryWithoutOpenSSH(initial, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	node, host, identity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("resolve node: %v", err)
	}
	if _, err := repository.CreateNodeContext(t.Context(), "peer", models.Node{HostRef: node.HostRef, IdentityRef: node.IdentityRef}, host, identity); err != nil {
		t.Fatalf("create peer node: %v", err)
	}
	connection, err := repository.ResolveConnection("web-server")
	if err != nil {
		t.Fatalf("ResolveConnection() error = %v", err)
	}
	if connection.UpdateRef == nil {
		t.Fatal("ResolveConnection() returned no update reference for persisted node")
	}
	authVersion := string(connection.UpdateRef.AuthVersion[:])
	if err := repository.UpdateAuthAtVersionContext(t.Context(), "web-server", authVersion, "discovered-password", "", ""); err != nil {
		t.Fatalf("UpdateAuthAtVersionContext() error = %v", err)
	}
	updated, _, updatedIdentity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("resolve updated node: %v", err)
	}
	peer, _, peerIdentity, err := repository.Resolve("peer")
	if err != nil {
		t.Fatalf("resolve peer node: %v", err)
	}
	if updated.IdentityRef == peer.IdentityRef || updatedIdentity.Password != "discovered-password" || peerIdentity.Password == "discovered-password" {
		t.Fatalf("discovery did not isolate shared identity: updated=%+v peer=%+v", updated, peer)
	}
}

func TestRepositoryUpdateAuthAtVersionRejectsIdentityRebinding(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	connection, err := repository.ResolveConnection("web-server")
	if err != nil {
		t.Fatalf("ResolveConnection() error = %v", err)
	}
	if connection.UpdateRef == nil {
		t.Fatal("ResolveConnection() returned no update reference for persisted node")
	}
	authVersion := string(connection.UpdateRef.AuthVersion[:])
	node, host, identity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	node.IdentityRef = "replacement-identity"
	if _, err := repository.CreateIdentityContext(t.Context(), node.IdentityRef, identity); err != nil {
		t.Fatalf("CreateIdentityContext() error = %v", err)
	}
	if err := repository.ReplaceNodeAtRefContext(t.Context(), repository.View().NodeRefs["web-server"], "web-server", node, host, identity); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext() error = %v", err)
	}
	if err := repository.UpdateAuthAtVersionContext(t.Context(), "web-server", authVersion, "discovered-password", "", ""); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("UpdateAuthAtVersionContext() error = %v, want ErrConfigConflict", err)
	}
}

func TestRepository_RejectsChangedNodeRef(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	ref := repository.View().NodeRefs["web-server"]
	node, host, identity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if _, err := repository.UpdateNodeTagsContext(t.Context(), []string{"web-server"}, []string{"changed"}, true); err != nil {
		t.Fatalf("UpdateNodeTags() error = %v", err)
	}
	err = repository.ReplaceNodeAtRefContext(t.Context(), ref, "web-server", node, host, identity)
	if !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("ReplaceNodeAtRef() error = %v, want ErrConfigConflict", err)
	}
}

func TestRepository_RenameRejectsExistingDestination(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	if err := createNode(repository, "existing", models.Node{HostRef: "host-existing", IdentityRef: "id-existing"}, models.Host{Address: "192.0.2.1", Port: 22}, models.Identity{User: "root"}); err != nil {
		t.Fatalf("CreateNodeContext() error = %v", err)
	}
	node, host, identity, err := repository.Resolve("web-server")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	err = repository.ReplaceNodeAtRefContext(t.Context(), repository.View().NodeRefs["web-server"], "existing", node, host, identity)
	if err == nil {
		t.Fatal("ReplaceNode() error = nil, want destination conflict")
	}
	if _, ok := repository.GetNode("web-server"); !ok {
		t.Fatal("ReplaceNode() removed source after a failed rename")
	}
}

func TestRepository_ConcurrentCommitsRetainBothChanges(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	var workers sync.WaitGroup
	workers.Add(2)
	for _, identityID := range []string{"one", "two"} {
		go func() {
			defer workers.Done()
			if addErr := createIdentity(repository, identityID, models.Identity{User: identityID}); addErr != nil {
				t.Errorf("AddIdentity(%q) error = %v", identityID, addErr)
			}
		}()
	}
	workers.Wait()

	identities := repository.ListIdentities()
	for _, identityID := range []string{"one", "two"} {
		if _, ok := identities[identityID]; !ok {
			t.Fatalf("concurrent commit lost identity %q", identityID)
		}
	}
}

func TestRepository_ConcurrentFileRepositoriesRetainBothChanges(t *testing.T) {
	store, initial := newTestStoreAndConfig(t)
	if err := store.Save(initial); err != nil {
		t.Fatalf("initialize file store: %v", err)
	}
	leftSnapshot, err := store.Load()
	if err != nil {
		t.Fatalf("load left repository snapshot: %v", err)
	}
	rightStore := NewDefaultStore(store.(*defaultStore).Path, store.(*defaultStore).KeyPath)
	rightSnapshot, err := rightStore.Load()
	if err != nil {
		t.Fatalf("load right repository snapshot: %v", err)
	}
	left, err := NewRepositoryWithoutOpenSSH(leftSnapshot, store)
	if err != nil {
		t.Fatalf("create left repository: %v", err)
	}
	right, err := NewRepositoryWithoutOpenSSH(rightSnapshot, rightStore)
	if err != nil {
		t.Fatalf("create right repository: %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	for repository, identityID := range map[*Repository]string{left: "left", right: "right"} {
		go func() {
			defer workers.Done()
			<-start
			errs <- createIdentity(repository, identityID, models.Identity{User: identityID})
		}()
	}
	close(start)
	workers.Wait()
	close(errs)
	for commitErr := range errs {
		if commitErr != nil {
			t.Errorf("concurrent repository commit error = %v", commitErr)
		}
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load final configuration: %v", err)
	}
	for _, identityID := range []string{"left", "right"} {
		if _, exists := loaded.Identities.Get(identityID); !exists {
			t.Fatalf("concurrent repositories lost identity %q", identityID)
		}
	}
}

func TestRepository_NodeRefRejectsCrossProcessSameNodeChange(t *testing.T) {
	store, initial := newTestStoreAndConfig(t)
	if err := store.Save(initial); err != nil {
		t.Fatalf("initialize file store: %v", err)
	}
	leftSnapshot, err := store.Load()
	if err != nil {
		t.Fatalf("load left snapshot: %v", err)
	}
	rightStore := NewDefaultStore(store.(*defaultStore).Path, store.(*defaultStore).KeyPath)
	rightSnapshot, err := rightStore.Load()
	if err != nil {
		t.Fatalf("load right snapshot: %v", err)
	}
	left, err := NewRepositoryWithoutOpenSSH(leftSnapshot, store)
	if err != nil {
		t.Fatalf("create left repository: %v", err)
	}
	right, err := NewRepositoryWithoutOpenSSH(rightSnapshot, rightStore)
	if err != nil {
		t.Fatalf("create right repository: %v", err)
	}
	ref := left.View().NodeRefs["n1"]
	if _, err := right.UpdateNodeTagsContext(t.Context(), []string{"n1"}, []string{"changed"}, true); err != nil {
		t.Fatalf("change node in right repository: %v", err)
	}
	node, host, identity, err := left.Resolve("n1")
	if err != nil {
		t.Fatalf("resolve left node: %v", err)
	}
	node.SudoMode = models.SudoModeSudo
	if err := left.ReplaceNodeAtRefContext(t.Context(), ref, "n1", node, host, identity); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("ReplaceNodeAtRef() error = %v, want ErrConfigConflict", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load final configuration: %v", err)
	}
	finalNode, _ := loaded.Nodes.Get("n1")
	if !slices.Contains(finalNode.Tags, "changed") || finalNode.SudoMode == models.SudoModeSudo {
		t.Fatalf("same-node conflict overwrote newer state: %+v", finalNode)
	}
}

func TestRepository_NodeRefMergesCrossProcessUnrelatedChange(t *testing.T) {
	store, initial := newTestStoreAndConfig(t)
	if err := store.Save(initial); err != nil {
		t.Fatalf("initialize file store: %v", err)
	}
	leftSnapshot, err := store.Load()
	if err != nil {
		t.Fatalf("load left snapshot: %v", err)
	}
	rightStore := NewDefaultStore(store.(*defaultStore).Path, store.(*defaultStore).KeyPath)
	rightSnapshot, err := rightStore.Load()
	if err != nil {
		t.Fatalf("load right snapshot: %v", err)
	}
	left, err := NewRepositoryWithoutOpenSSH(leftSnapshot, store)
	if err != nil {
		t.Fatalf("create left repository: %v", err)
	}
	right, err := NewRepositoryWithoutOpenSSH(rightSnapshot, rightStore)
	if err != nil {
		t.Fatalf("create right repository: %v", err)
	}
	ref := left.View().NodeRefs["n1"]
	if err := createIdentity(right, "unrelated", models.Identity{User: "unrelated"}); err != nil {
		t.Fatalf("add unrelated identity in right repository: %v", err)
	}
	node, host, identity, err := left.Resolve("n1")
	if err != nil {
		t.Fatalf("resolve left node: %v", err)
	}
	node.SudoMode = models.SudoModeSudo
	if err := left.ReplaceNodeAtRefContext(t.Context(), ref, "n1", node, host, identity); err != nil {
		t.Fatalf("ReplaceNodeAtRef() failed after unrelated change: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load final configuration: %v", err)
	}
	if _, exists := loaded.Identities.Get("unrelated"); !exists {
		t.Fatal("unrelated concurrent identity was lost")
	}
	finalNode, _ := loaded.Nodes.Get("n1")
	if finalNode.SudoMode != models.SudoModeSudo {
		t.Fatalf("node update was not applied: %+v", finalNode)
	}
}

func TestRepositoryUpdateAuthContextHonorsCanceledLockWait(t *testing.T) {
	store, initial := newTestStoreAndConfig(t)
	if err := store.Save(initial); err != nil {
		t.Fatalf("initialize file store: %v", err)
	}
	locked, err := acquireConfigLock(context.Background(), store.(*defaultStore).Path)
	if err != nil {
		t.Fatalf("acquire test configuration lock: %v", err)
	}
	defer func() {
		if closeErr := locked.Close(); closeErr != nil {
			t.Errorf("release test configuration lock: %v", closeErr)
		}
	}()

	repository, err := NewRepositoryWithoutOpenSSH(initial, store)
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	connection, versionErr := repository.ResolveConnection("n1")
	if versionErr != nil {
		t.Fatalf("ResolveConnection() error = %v", versionErr)
	}
	if connection.UpdateRef == nil {
		t.Fatal("ResolveConnection() returned no update reference for persisted node")
	}
	authVersion := string(connection.UpdateRef.AuthVersion[:])
	err = repository.UpdateAuthAtVersionContext(ctx, "n1", authVersion, "new-password", "", "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("UpdateAuthContext() error = %v, want context.Canceled", err)
	}
}

func TestRepositoryCreateNodeContextHonorsCanceledContext(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = repository.CreateNodeContext(ctx, "new", models.Node{HostRef: "host-new", IdentityRef: "identity-new"}, models.Host{Address: "192.0.2.10", Port: 22}, models.Identity{User: "root"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateNodeContext() error = %v, want context.Canceled", err)
	}
	if _, exists := repository.GetNode("new"); exists {
		t.Fatal("CreateNodeContext() published a node after cancellation")
	}
}

func TestRepositoryCreateNodeContextHonorsCanceledInProcessWait(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	repository.commitMu.Lock()
	defer repository.commitMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = repository.CreateNodeContext(ctx, "new", models.Node{HostRef: "host-new", IdentityRef: "identity-new"}, models.Host{Address: "192.0.2.10", Port: 22}, models.Identity{User: "root"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateNodeContext() error = %v, want context.Canceled", err)
	}
}

func TestRepository_ImportOpenSSHHostsCommitsOnce(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	result, err := repository.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{
		{
			Name:     "first",
			Host:     models.Host{Address: "192.0.2.10", Port: 22},
			Identity: models.Identity{User: "root"},
			Node:     models.Node{},
		},
		{
			Name:     "second",
			Host:     models.Host{Address: "192.0.2.11", Port: 22},
			Identity: models.Identity{User: "root"},
			Node:     models.Node{},
		},
	})
	if err != nil {
		t.Fatalf("ImportOpenSSHHosts() error = %v", err)
	}
	if result.Imported != 2 || result.Skipped != 0 {
		t.Fatalf("ImportOpenSSHHosts() = %+v, want two imported hosts", result)
	}
	if _, ok := repository.GetNode("first"); !ok {
		t.Fatal("first imported node is missing")
	}
	if _, ok := repository.GetNode("second"); !ok {
		t.Fatal("second imported node is missing")
	}
	store.mu.Lock()
	saves := store.saves
	store.mu.Unlock()
	if saves != 1 {
		t.Fatalf("store saves = %d, want 1", saves)
	}
}

func TestRepository_ImportOpenSSHHostsSkipsAliasConflictAndResolvesProxyJump(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	result, err := repository.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{
		{
			Name:     "conflict",
			Host:     models.Host{Address: "192.0.2.10", Port: 22},
			Identity: models.Identity{User: "root"},
			Node:     models.Node{Alias: []string{"ws1"}},
		},
		{
			Name:     "jump",
			Host:     models.Host{Address: "bastion.example.com", Port: 2222},
			Identity: models.Identity{User: "ops"},
			Node:     models.Node{Alias: []string{"jump"}},
		},
		{
			Name:     "app",
			Host:     models.Host{Address: "192.0.2.11", Port: 22},
			Identity: models.Identity{User: "deploy"},
			Node:     models.Node{Alias: []string{"app"}, ProxyJump: "ops@bastion.example.com:2222"},
		},
	})
	if err != nil {
		t.Fatalf("ImportOpenSSHHosts() error = %v", err)
	}
	if result.Imported != 2 || result.Skipped != 1 || len(result.Issues) != 1 {
		t.Fatalf("ImportOpenSSHHosts() = %+v, want two imports and one conflict issue", result)
	}
	if result.Issues[0].Name != "conflict" {
		t.Fatalf("conflict issue name = %q, want conflict", result.Issues[0].Name)
	}
	if _, exists := repository.GetNode("conflict"); exists {
		t.Fatal("conflicting OpenSSH node was imported")
	}
	app, exists := repository.GetNode("app")
	if !exists {
		t.Fatal("app OpenSSH node is missing")
	}
	if app.ProxyJump != "jump" {
		t.Fatalf("app ProxyJump = %q, want jump", app.ProxyJump)
	}
}

func TestRepository_DeleteNodesAtRefsRejectsChangedSelectionWithoutPartialDelete(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	ref := repository.View().NodeRefs["web-server"]
	if _, err := repository.UpdateNodeTagsContext(t.Context(), []string{"web-server"}, []string{"changed"}, true); err != nil {
		t.Fatalf("UpdateNodeTags() error = %v", err)
	}

	err = repository.DeleteNodesAtRefsContext(t.Context(), []NodeRef{ref})
	if !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("DeleteNodesAtRefs() error = %v, want ErrConfigConflict", err)
	}
	if _, ok := repository.GetNode("web-server"); !ok {
		t.Fatal("DeleteNodesAtRefs() deleted node after a stale-selection conflict")
	}
}

func TestRepository_UpdateNodeTagsIntentMergesSelectionOnce(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	if err := createNode(repository, "second", models.Node{HostRef: "second-host", IdentityRef: "second-id"}, models.Host{Address: "192.0.2.2", Port: 22}, models.Identity{User: "root"}); err != nil {
		t.Fatalf("CreateNodeContext() error = %v", err)
	}
	store.mu.Lock()
	savesBefore := store.saves
	store.mu.Unlock()

	if _, err := repository.UpdateNodeTagsContext(t.Context(), []string{"web-server", "second"}, []string{"blue", "green", "blue"}, true); err != nil {
		t.Fatalf("UpdateNodeTags() error = %v", err)
	}
	for nodeID, wantTags := range map[string][]string{
		"web-server": {"production", "web", "blue", "green"},
		"second":     {"blue", "green"},
	} {
		node, ok := repository.GetNode(nodeID)
		if !ok {
			t.Fatalf("GetNode(%q) = missing", nodeID)
		}
		if got, want := node.Tags, wantTags; !equalStrings(got, want) {
			t.Fatalf("node %q tags = %v, want %v", nodeID, got, want)
		}
	}
	store.mu.Lock()
	savesAfter := store.saves
	store.mu.Unlock()
	if got := savesAfter - savesBefore; got != 1 {
		t.Fatalf("tag batch saves = %d, want 1", got)
	}
}

func TestRepositoryUpdateNodeTagsRejectsInvalidBatchWithoutPartialChange(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	if _, err := repository.UpdateNodeTagsContext(t.Context(), []string{"web-server", "missing"}, []string{"blue"}, true); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("UpdateNodeTags() error = %v, want ErrNodeNotFound", err)
	}
	node, exists := repository.GetNode("web-server")
	if !exists {
		t.Fatal("web-server is missing")
	}
	if slices.Contains(node.Tags, "blue") {
		t.Fatal("UpdateNodeTags() modified a valid node before rejecting the invalid batch")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
