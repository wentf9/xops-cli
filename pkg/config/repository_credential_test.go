package config

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

type mockPersistStore struct {
	mu      sync.Mutex
	cfg     *Configuration
	result  PersistResult
	err     error
	syncErr error
}

func (m *mockPersistStore) Load() (*Configuration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneConfiguration(m.cfg), nil
}

func (m *mockPersistStore) Save(c *Configuration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cloneConfiguration(c)
	return m.err
}

func (m *mockPersistStore) save(c *Configuration) (PersistResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cloneConfiguration(c)
	return m.result, m.err
}

func (m *mockPersistStore) IsDurable() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.result.Durable
}

func (m *mockPersistStore) Sync(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.syncErr != nil {
		return m.syncErr
	}
	if !m.result.Durable {
		if m.err != nil {
			return m.err
		}
		return errors.New("storage durability sync not completed")
	}
	return nil
}

func TestRepository_UpdateNodeCredentialRef_SharedIdentityFork(t *testing.T) {
	store := &mockPersistStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}

	ctx := context.Background()

	// 1. 创建共享 Identity 和两个引用该 Identity 的 Node
	sharedID := "shared-admin"
	sharedIdentity := models.Identity{
		User:     "root",
		AuthType: "password",
		Password: "initial-password",
	}
	if err := createIdentity(repo, sharedID, sharedIdentity); err != nil {
		t.Fatalf("create shared identity failed: %v", err)
	}

	if err := createNode(repo, "node-1", models.Node{IdentityRef: sharedID, HostRef: "h1"}, models.Host{Address: "1.1.1.1", Port: 22}, sharedIdentity); err != nil {
		t.Fatalf("create node-1 failed: %v", err)
	}
	if err := createNode(repo, "node-2", models.Node{IdentityRef: sharedID, HostRef: "h2"}, models.Host{Address: "1.1.1.2", Port: 22}, sharedIdentity); err != nil {
		t.Fatalf("create node-2 failed: %v", err)
	}

	// 获取 node-1 初始版本
	connSnap1, err := repo.ResolveConnection("node-1")
	if err != nil {
		t.Fatalf("ResolveConnection(node-1) failed: %v", err)
	}
	initialAuthVer1 := string(connSnap1.UpdateRef.AuthVersion[:])

	// 2. 为 node-1 轮换密码凭据
	newRef := &credential.Ref{
		StoreID: "system",
		ItemID:  "item-new-pwd-1",
	}
	outcome, newVer, err := repo.UpdateNodeCredentialRefAtVersionContext(
		ctx,
		"node-1",
		initialAuthVer1,
		credential.KindLoginPassword,
		newRef,
	)
	if err != nil {
		t.Fatalf("UpdateNodeCredentialRefAtVersionContext failed: %v", err)
	}
	if !outcome.Applied || !outcome.Durable {
		t.Fatalf("expected outcome Applied and Durable, got %+v", outcome)
	}
	if newVer == initialAuthVer1 {
		t.Fatalf("expected committed version to differ from initial version")
	}

	// 3. 验证 node-1 的 IdentityRef 已自动分裂为私有副本
	node1, _, identity1, err := repo.Resolve("node-1")
	if err != nil {
		t.Fatalf("resolve node-1 failed: %v", err)
	}
	if node1.IdentityRef == sharedID {
		t.Fatalf("expected node-1 IdentityRef to be forked from %q, but got %q", sharedID, node1.IdentityRef)
	}
	if identity1.LoginPasswordRef == nil || *identity1.LoginPasswordRef != *newRef {
		t.Fatalf("expected node-1 LoginPasswordRef to be %v, got %v", newRef, identity1.LoginPasswordRef)
	}
	if identity1.Password != "" {
		t.Fatalf("expected node-1 plaintext password to be cleared, got %q", identity1.Password)
	}

	// 4. 验证 node-2 仍保持引用原始 shared-admin，且原始 shared-admin 不受影响
	node2, _, identity2, err := repo.Resolve("node-2")
	if err != nil {
		t.Fatalf("resolve node-2 failed: %v", err)
	}
	if node2.IdentityRef != sharedID {
		t.Fatalf("expected node-2 IdentityRef to remain %q, got %q", sharedID, node2.IdentityRef)
	}
	if identity2.LoginPasswordRef != nil {
		t.Fatalf("expected shared identity LoginPasswordRef to be nil, got %v", identity2.LoginPasswordRef)
	}
	if identity2.Password != "initial-password" {
		t.Fatalf("expected shared identity password to be preserved, got %q", identity2.Password)
	}
}

func TestRepository_UpdateNodeCredentialRef_CASConflict(t *testing.T) {
	store := &mockPersistStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	ctx := context.Background()

	if err := createIdentity(repo, "id-1", models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create identity failed: %v", err)
	}
	if err := createNode(repo, "node-cas", models.Node{IdentityRef: "id-1", HostRef: "h1"}, models.Host{Address: "1.1.1.1", Port: 22}, models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create node failed: %v", err)
	}

	fakeConflictVersion := string(make([]byte, 32))
	newRef := &credential.Ref{StoreID: "system", ItemID: "item-cas-fail"}

	outcome, _, err := repo.UpdateNodeCredentialRefAtVersionContext(
		ctx,
		"node-cas",
		fakeConflictVersion,
		credential.KindLoginPassword,
		newRef,
	)
	if !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("expected ErrConfigConflict, got %v", err)
	}
	if outcome.Applied {
		t.Fatalf("expected outcome.Applied == false on CAS conflict")
	}
}

func TestRepository_UpdateNodeCredentialRef_PrivilegePassword(t *testing.T) {
	store := &mockPersistStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	ctx := context.Background()

	if err := createIdentity(repo, "id-sudo", models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create identity failed: %v", err)
	}
	if err := createNode(repo, "node-sudo", models.Node{
		IdentityRef: "id-sudo",
		HostRef:     "h1",
		SudoMode:    models.SudoModeSudo,
		SuPwd:       "old-plaintext-supwd",
	}, models.Host{Address: "1.1.1.1", Port: 22}, models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create node failed: %v", err)
	}

	nodeBefore, _ := repo.GetNode("node-sudo")
	cfgSnap := repo.Snapshot()
	initialSudoVer, err := nodeSudoVersion(cfgSnap, "node-sudo")
	if err != nil {
		t.Fatalf("nodeSudoVersion failed: %v", err)
	}

	privRef := &credential.Ref{StoreID: "system", ItemID: "item-sudo-secret"}
	outcome, newVer, err := repo.UpdateNodeCredentialRefAtVersionContext(
		ctx,
		"node-sudo",
		string(initialSudoVer[:]),
		credential.KindPrivilegePassword,
		privRef,
	)
	if err != nil {
		t.Fatalf("UpdateNodeCredentialRefAtVersionContext failed: %v", err)
	}
	if !outcome.Applied || !outcome.Durable {
		t.Fatalf("expected outcome Applied and Durable, got %+v", outcome)
	}
	if newVer == string(initialSudoVer[:]) {
		t.Fatalf("expected new sudo version to change")
	}

	nodeAfter, _ := repo.GetNode("node-sudo")
	if nodeAfter.PrivilegePasswordRef == nil || *nodeAfter.PrivilegePasswordRef != *privRef {
		t.Fatalf("expected PrivilegePasswordRef %v, got %v", privRef, nodeAfter.PrivilegePasswordRef)
	}
	if nodeAfter.SuPwd != "" {
		t.Fatalf("expected plaintext SuPwd to be cleared, got %q", nodeAfter.SuPwd)
	}
	if nodeAfter.IdentityRef != nodeBefore.IdentityRef {
		t.Fatalf("PrivilegePassword update must not fork IdentityRef")
	}
}

func TestRepository_UpdateIdentityCredentialRef(t *testing.T) {
	store := &mockPersistStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	ctx := context.Background()

	idName := "id-direct"
	if err := createIdentity(repo, idName, models.Identity{
		User:       "deployer",
		AuthType:   "key",
		Passphrase: "old-passphrase",
	}); err != nil {
		t.Fatalf("create identity failed: %v", err)
	}

	cfgSnap := repo.Snapshot()
	initVer, err := identityEntityVersion(cfgSnap, idName)
	if err != nil {
		t.Fatalf("identityEntityVersion failed: %v", err)
	}

	// 1. 尝试使用 KindPrivilegePassword 更新 Identity，必须报错
	_, _, err = repo.UpdateIdentityCredentialRefAtVersionContext(
		ctx,
		idName,
		string(initVer[:]),
		credential.KindPrivilegePassword,
		&credential.Ref{StoreID: "system", ItemID: "invalid"},
	)
	if err == nil {
		t.Fatal("expected error updating identity with KindPrivilegePassword, got nil")
	}

	// 2. 正常更新 PassphraseRef
	passRef := &credential.Ref{StoreID: "pass", ItemID: "ssh-deployer"}
	outcome, newVer, err := repo.UpdateIdentityCredentialRefAtVersionContext(
		ctx,
		idName,
		string(initVer[:]),
		credential.KindPassphrase,
		passRef,
	)
	if err != nil {
		t.Fatalf("UpdateIdentityCredentialRefAtVersionContext failed: %v", err)
	}
	if !outcome.Applied || !outcome.Durable {
		t.Fatalf("expected outcome Applied and Durable, got %+v", outcome)
	}

	idUpdated, ok := repo.Snapshot().Identities.Get(idName)
	if !ok {
		t.Fatalf("identity %q not found in snapshot", idName)
	}
	if idUpdated.PassphraseRef == nil || *idUpdated.PassphraseRef != *passRef {
		t.Fatalf("expected PassphraseRef %v, got %v", passRef, idUpdated.PassphraseRef)
	}
	if idUpdated.Passphrase != "" {
		t.Fatalf("expected plaintext passphrase to be cleared, got %q", idUpdated.Passphrase)
	}
	if newVer == string(initVer[:]) {
		t.Fatalf("expected version to change")
	}
}

func TestRepository_CheckRefUnreferenced(t *testing.T) {
	store := &mockPersistStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	ctx := context.Background()

	refLogin := credential.Ref{StoreID: "system", ItemID: "pwd-ref-1"}
	refPassphrase := credential.Ref{StoreID: "pass", ItemID: "key-ref-2"}
	refSudo := credential.Ref{StoreID: "system", ItemID: "sudo-ref-3"}
	refUnused := credential.Ref{StoreID: "system", ItemID: "unused-ref-4"}

	// 初始状态，所有 ref 均未被引用
	for _, ref := range []credential.Ref{refLogin, refPassphrase, refSudo, refUnused} {
		unref, err := repo.CheckRefUnreferenced(ctx, ref)
		if err != nil || !unref {
			t.Fatalf("expected %s to be unreferenced initially, got unref=%v, err=%v", ref, unref, err)
		}
	}

	// 创建带引用的 Identity 和 Node
	refIdentity := models.Identity{
		User:             "test",
		LoginPasswordRef: &refLogin,
		PassphraseRef:    &refPassphrase,
	}
	if err := createIdentity(repo, "id-ref", refIdentity); err != nil {
		t.Fatalf("create identity failed: %v", err)
	}
	if err := createNode(repo, "node-ref", models.Node{
		IdentityRef:          "id-ref",
		HostRef:              "h1",
		PrivilegePasswordRef: &refSudo,
	}, models.Host{Address: "1.1.1.1", Port: 22}, refIdentity); err != nil {
		t.Fatalf("create node failed: %v", err)
	}

	// 验证被引用的 ref 返回 false
	for _, ref := range []credential.Ref{refLogin, refPassphrase, refSudo} {
		unref, err := repo.CheckRefUnreferenced(ctx, ref)
		if err != nil || unref {
			t.Fatalf("expected %s to be referenced, got unref=%v, err=%v", ref, unref, err)
		}
	}

	// 未使用的 ref 依然返回 true
	unref, err := repo.CheckRefUnreferenced(ctx, refUnused)
	if err != nil || !unref {
		t.Fatalf("expected unused ref to be unreferenced, got unref=%v, err=%v", unref, err)
	}
}

func TestRepository_DurabilityError_Handling(t *testing.T) {
	store := &mockPersistStore{
		result: PersistResult{Applied: true, Durable: true},
	}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	ctx := context.Background()

	if err := createIdentity(repo, "id-dur", models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create identity failed: %v", err)
	}
	if err := createNode(repo, "node-dur", models.Node{IdentityRef: "id-dur", HostRef: "h1"}, models.Host{Address: "1.1.1.1", Port: 22}, models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create node failed: %v", err)
	}

	// 注入耐久性错误
	durErr := errors.New("parent directory fsync failure")
	store.result = PersistResult{Applied: true, Durable: false}
	store.err = durErr

	newRef := &credential.Ref{StoreID: "system", ItemID: "item-dur"}
	outcome, _, err := repo.UpdateNodeCredentialRefAtVersionContext(
		ctx,
		"node-dur",
		"",
		credential.KindLoginPassword,
		newRef,
	)

	var targetDurErr *DurabilityError
	if !errors.As(err, &targetDurErr) {
		t.Fatalf("expected *DurabilityError, got %v", err)
	}
	if !outcome.Applied {
		t.Fatalf("expected outcome.Applied == true on DurabilityError")
	}
	if outcome.Durable {
		t.Fatalf("expected outcome.Durable == false on DurabilityError")
	}

	// 快照中应当已经反映了更新
	node, _, id, err := repo.Resolve("node-dur")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if id.LoginPasswordRef == nil || *id.LoginPasswordRef != *newRef {
		t.Fatalf("expected node-dur LoginPasswordRef to be applied, got %v (node=%+v)", id.LoginPasswordRef, node)
	}
}

func TestRepository_AsConfigUpdater(t *testing.T) {
	store := &mockPersistStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	ctx := context.Background()

	if err := createIdentity(repo, "id-adapter", models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create identity failed: %v", err)
	}
	if err := createNode(repo, "node-adapter", models.Node{IdentityRef: "id-adapter", HostRef: "h1"}, models.Host{Address: "1.1.1.1", Port: 22}, models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create node failed: %v", err)
	}

	updater := repo.AsConfigUpdater()
	ref := &credential.Ref{StoreID: "system", ItemID: "adapter-ref"}

	// 通过 updater 更新 Node
	targetNode := credential.Target{
		NodeID: "node-adapter",
		Kind:   credential.KindLoginPassword,
	}
	outcome, newVer, err := updater.ApplyCredentialRefAtVersion(ctx, targetNode, "", ref)
	if err != nil {
		t.Fatalf("ApplyCredentialRefAtVersion for node failed: %v", err)
	}
	if !outcome.Applied || !outcome.Durable || newVer == "" {
		t.Fatalf("unexpected outcome: %+v, version: %q", outcome, newVer)
	}

	// 验证 CheckRefUnreferenced
	unref, err := updater.CheckRefUnreferenced(ctx, *ref)
	if err != nil || unref {
		t.Fatalf("expected referenced, got unref=%v, err=%v", unref, err)
	}

	// 通过 updater 解除引用
	outcome, _, err = updater.ApplyCredentialRefAtVersion(ctx, targetNode, "", nil)
	if err != nil {
		t.Fatalf("ApplyCredentialRefAtVersion delete failed: %v", err)
	}
	if !outcome.Applied {
		t.Fatalf("expected outcome.Applied == true")
	}

	unref, err = updater.CheckRefUnreferenced(ctx, *ref)
	if err != nil || !unref {
		t.Fatalf("expected unreferenced after deletion, got unref=%v, err=%v", unref, err)
	}
}

func TestRepositoryConfigUpdater_CASConflict_ErrorContract(t *testing.T) {
	store := &mockPersistStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	ctx := context.Background()

	if err := createIdentity(repo, "id-contract", models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create identity failed: %v", err)
	}
	if err := createNode(repo, "node-contract", models.Node{IdentityRef: "id-contract", HostRef: "h1"}, models.Host{Address: "1.1.1.1", Port: 22}, models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create node failed: %v", err)
	}

	updater := repo.AsConfigUpdater()
	wrongVersion := string(make([]byte, 32))
	targetNode := credential.Target{
		NodeID: "node-contract",
		Kind:   credential.KindLoginPassword,
	}
	ref := &credential.Ref{StoreID: "system", ItemID: "item-cas"}

	outcome, _, err := updater.ApplyCredentialRefAtVersion(ctx, targetNode, wrongVersion, ref)
	if err == nil {
		t.Fatalf("expected error on CAS mismatch, got nil")
	}
	if outcome.Applied {
		t.Fatalf("expected outcome.Applied == false on CAS conflict")
	}

	// 【核心契约验证】：必须同时满足 errors.Is(err, credential.ErrConfigConflict) 和 errors.Is(err, ErrConfigConflict)
	if !errors.Is(err, credential.ErrConfigConflict) {
		t.Fatalf("expected errors.Is(err, credential.ErrConfigConflict) to be true, got: %v", err)
	}
	if !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("expected errors.Is(err, config.ErrConfigConflict) to be true, got: %v", err)
	}
}

type memoryPersistStore struct {
	mu      sync.Mutex
	cfg     *Configuration
	loadErr error
	result  *PersistResult
	syncErr error
}

func (m *memoryPersistStore) Load() (*Configuration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return cloneConfiguration(m.cfg), nil
}

func (m *memoryPersistStore) Save(c *Configuration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cloneConfiguration(c)
	return nil
}

func (m *memoryPersistStore) save(c *Configuration) (PersistResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cloneConfiguration(c)
	if m.result != nil {
		return *m.result, m.syncErr
	}
	return PersistResult{Applied: true, Durable: true}, nil
}

func (m *memoryPersistStore) IsDurable() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.result != nil {
		return m.result.Durable
	}
	return true
}

func (m *memoryPersistStore) Sync(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.syncErr != nil {
		return m.syncErr
	}
	if m.result != nil && !m.result.Durable {
		return errors.New("storage durability sync failed")
	}
	return nil
}

func TestRepository_CheckRefUnreferenced_ReloadsDiskConfiguration(t *testing.T) {
	diskStore := &memoryPersistStore{cfg: cloneConfiguration(nil)}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), diskStore)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	ctx := context.Background()

	ref := credential.Ref{StoreID: "system", ItemID: "item-disk-ref"}

	// 初始状态下未引用
	unref, err := repo.CheckRefUnreferenced(ctx, ref)
	if err != nil || !unref {
		t.Fatalf("expected initially unreferenced, got unref=%v, err=%v", unref, err)
	}

	// 模拟外部并发写入：直接在底层持久化 store 中注入对该 ref 的引用（repo 内存快照中没有）
	diskStore.mu.Lock()
	diskStore.cfg.Identities.Set("external-id", models.Identity{
		User:             "ext-user",
		LoginPasswordRef: &ref,
	})
	diskStore.mu.Unlock()

	// 重新调用 repo.CheckRefUnreferenced：必须从磁盘重新加载最新权威配置，发现被引用，返回 unref = false
	unref, err = repo.CheckRefUnreferenced(ctx, ref)
	if err != nil {
		t.Fatalf("CheckRefUnreferenced failed: %v", err)
	}
	if unref {
		t.Fatalf("expected unref == false because authoritative disk configuration holds reference!")
	}

	// 模拟磁盘加载失败：必须返回错误，严禁放行删除
	diskStore.mu.Lock()
	diskStore.loadErr = errors.New("disk I/O error")
	diskStore.mu.Unlock()

	_, err = repo.CheckRefUnreferenced(ctx, ref)
	if err == nil {
		t.Fatalf("expected error when disk configuration fails to load, got nil")
	}
}

func TestRepository_ConfirmRefDurable_RequiresStorageSync(t *testing.T) {
	store := &mockPersistStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}
	ctx := context.Background()

	if err := createIdentity(repo, "id-sync", models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create identity failed: %v", err)
	}
	if err := createNode(repo, "node-sync", models.Node{IdentityRef: "id-sync", HostRef: "h1"}, models.Host{Address: "1.1.1.1", Port: 22}, models.Identity{User: "user1"}); err != nil {
		t.Fatalf("create node failed: %v", err)
	}

	target := credential.Target{NodeID: "node-sync", Kind: credential.KindLoginPassword}
	newRef := &credential.Ref{StoreID: "system", ItemID: "item-sync"}

	// 1. 注入 Applied=true, Durable=false（rename 成功但目录 sync 失败）
	durErr := errors.New("directory sync failed")
	store.result = PersistResult{Applied: true, Durable: false}
	store.err = durErr

	// 执行写入，返回 DurabilityError
	updater := repo.AsConfigUpdater()
	outcome, _, err := updater.ApplyCredentialRefAtVersion(ctx, target, "", newRef)
	if err == nil {
		t.Fatalf("expected DurabilityError, got nil")
	}
	if !outcome.Applied || outcome.Durable {
		t.Fatalf("expected Applied=true, Durable=false, got %+v", outcome)
	}

	// 【核心红线断言 1】：即使配置中已可读到该引用，由于持久化层未完成同步，ConfirmRefDurable 绝对不能返回 true！
	durable, confErr := updater.ConfirmRefDurable(ctx, target, newRef)
	if durable {
		t.Fatalf("ConfirmRefDurable must NOT return true when storage durability sync failed!")
	}
	if confErr == nil {
		t.Fatalf("expected error when storage durability sync is incomplete, got nil")
	}

	// 2. 模拟持久化层成功完成文件/目录同步
	store.result = PersistResult{Applied: true, Durable: true}
	store.err = nil

	// 【核心红线断言 2】：持久化层同步成功后，方可确认 Durable
	durable, confErr = updater.ConfirmRefDurable(ctx, target, newRef)
	if confErr != nil {
		t.Fatalf("ConfirmRefDurable failed unexpectedly: %v", confErr)
	}
	if !durable {
		t.Fatalf("expected ConfirmRefDurable to return true after storage sync succeeded")
	}
}

func TestRepository_CheckRefUnreferenced_MultipleRepositoriesStaleSnapshot(t *testing.T) {
	// 共享底层的持久化 Store
	sharedStore := &memoryPersistStore{cfg: cloneConfiguration(nil)}

	repo1, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), sharedStore)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH repo1 failed: %v", err)
	}

	ctx := context.Background()
	oldRef := credential.Ref{StoreID: "system", ItemID: "old-ref-stale"}
	newRef := credential.Ref{StoreID: "system", ItemID: "new-ref-active"}

	sharedIdentity := models.Identity{User: "user1", LoginPasswordRef: &oldRef}
	if err := createIdentity(repo1, "id-shared", sharedIdentity); err != nil {
		t.Fatalf("create identity failed: %v", err)
	}
	if err := createNode(repo1, "node-shared", models.Node{IdentityRef: "id-shared", HostRef: "h1"}, models.Host{Address: "1.1.1.1", Port: 22}, sharedIdentity); err != nil {
		t.Fatalf("create node failed: %v", err)
	}

	// 此时创建 repo2（模拟另一个进程或并发实例），两者的内存快照此时均包含 oldRef
	repo2, err := NewRepositoryWithoutOpenSSH(repo1.provider.Snapshot(), sharedStore)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH repo2 failed: %v", err)
	}

	// repo1 执行轮换，将引用更新为 newRef 并持久化落盘
	target := credential.Target{NodeID: "node-shared", Kind: credential.KindLoginPassword}
	outcome, _, err := repo1.AsConfigUpdater().ApplyCredentialRefAtVersion(ctx, target, "", &newRef)
	if err != nil || !outcome.Durable {
		t.Fatalf("ApplyCredentialRefAtVersion on repo1 failed: %v", err)
	}

	// 验证磁盘上权威配置中已无 oldRef 引用
	sharedStore.mu.Lock()
	diskHasOld := isRefReferencedIn(sharedStore.cfg, oldRef)
	sharedStore.mu.Unlock()
	if diskHasOld {
		t.Fatalf("disk configuration should no longer have oldRef")
	}

	// 此时 repo2 的内存快照仍然是旧的（包含 oldRef）
	// 【核心红线断言】：repo2 必须识别到本进程没有未落盘修改，磁盘权威配置已无 oldRef，
	// 内存快照中的引用属于过期快照（stale snapshot），返回 unref == true，绝不能误判为仍然引用！
	unref, err := repo2.CheckRefUnreferenced(ctx, oldRef)
	if err != nil {
		t.Fatalf("CheckRefUnreferenced on repo2 failed: %v", err)
	}
	if !unref {
		t.Fatalf("CRITICAL BUG: stale in-memory snapshot caused CheckRefUnreferenced to return false when authoritative disk removed the reference!")
	}
}

type inMemoryCredStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (s *inMemoryCredStore) Get(_ context.Context, ref credential.Ref) (credential.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[ref.ItemID]
	if !ok {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}
	return credential.Secret{Value: bytes.Clone(v)}, nil
}

func (s *inMemoryCredStore) Put(_ context.Context, ref credential.Ref, sec credential.Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[ref.ItemID] = bytes.Clone(sec.Value)
	return nil
}

func (s *inMemoryCredStore) Delete(_ context.Context, ref credential.Ref) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[ref.ItemID]; !ok {
		return credential.ErrCredentialNotFound
	}
	delete(s.data, ref.ItemID)
	return nil
}

func setupSharedNodesAndIdentities(t *testing.T, repo *Repository, oldRef credential.Ref) {
	t.Helper()
	identityA := models.Identity{User: "userA", LoginPasswordRef: &oldRef}
	if err := createIdentity(repo, "id-A", identityA); err != nil {
		t.Fatalf("create id-A failed: %v", err)
	}
	identityB := models.Identity{User: "userB", LoginPasswordRef: &oldRef}
	if err := createIdentity(repo, "id-B", identityB); err != nil {
		t.Fatalf("create id-B failed: %v", err)
	}
	if err := createNode(repo, "node-A", models.Node{IdentityRef: "id-A", HostRef: "h1"}, models.Host{Address: "1.1.1.1", Port: 22}, identityA); err != nil {
		t.Fatalf("create node-A failed: %v", err)
	}
	if err := createNode(repo, "node-B", models.Node{IdentityRef: "id-B", HostRef: "h2"}, models.Host{Address: "1.1.1.2", Port: 22}, identityB); err != nil {
		t.Fatalf("create node-B failed: %v", err)
	}
}

func setupTestCredentialEnvironment(
	t *testing.T,
	repo *Repository,
	oldRef, newRef credential.Ref,
) (*credential.Service, *inMemoryCredStore, *credential.JournalStore) {
	t.Helper()
	credStore := &inMemoryCredStore{data: map[string][]byte{
		oldRef.ItemID: []byte("old-secret-content"),
		newRef.ItemID: []byte("new-secret-content"),
	}}
	reg := credential.NewRegistry()
	if err := reg.Register("mock-store", credStore); err != nil {
		t.Fatalf("reg.Register failed: %v", err)
	}
	journalStore, err := credential.NewJournalStore(filepath.Join(t.TempDir(), "journals"))
	if err != nil {
		t.Fatalf("NewJournalStore failed: %v", err)
	}

	cleanupEntry := &credential.JournalEntry{
		ID:         credential.GenerateJournalID(),
		Op:         credential.OpRotate,
		Stage:      credential.StageCleanup,
		TargetNode: "node-A",
		TargetKind: credential.KindLoginPassword,
		NewRef:     &newRef,
		OldRef:     &oldRef,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	if err := journalStore.RecordIntent(cleanupEntry); err != nil {
		t.Fatalf("RecordIntent failed: %v", err)
	}
	if err := journalStore.MarkCleanup(cleanupEntry.ID); err != nil {
		t.Fatalf("MarkCleanup failed: %v", err)
	}

	svcA, err := credential.NewService(reg, journalStore, repo.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatalf("NewService svcA failed: %v", err)
	}
	return svcA, credStore, journalStore
}

func assertGCBlockedUnderUndurableStorage(
	t *testing.T,
	ctx context.Context,
	svcA *credential.Service,
	repoA *Repository,
	oldRef credential.Ref,
	credStore *inMemoryCredStore,
	journalStore *credential.JournalStore,
) {
	t.Helper()
	// 【核心红线测试 1】：CheckRefUnreferenced 必须在存储层核验持久化，由于 sync 失败，必须返回 false 和错误！
	unref, checkErr := repoA.CheckRefUnreferenced(ctx, oldRef)
	if unref {
		t.Fatalf("CRITICAL BUG: repoA.CheckRefUnreferenced must NOT return true when storage durability sync failed!")
	}
	if checkErr == nil {
		t.Fatalf("expected checkErr when storage sync failed, got nil")
	}

	// 【核心红线测试 2】：svcA.Recover 执行 GC，绝不能删除旧凭据，绝不能丢弃清理 journal！
	res, err := svcA.Recover(ctx)
	if err != nil {
		t.Fatalf("svcA.Recover failed: %v", err)
	}
	if len(res) != 1 || res[0].Action != credential.RecoveryActionScheduledForGC {
		t.Fatalf("expected RecoveryActionScheduledForGC, got %+v", res)
	}

	// 【核心红线断言 3】：旧凭据绝对不能被删除！
	credStore.mu.Lock()
	_, oldStillExists := credStore.data[oldRef.ItemID]
	credStore.mu.Unlock()
	if !oldStillExists {
		t.Fatalf("CRITICAL DISASTER: old credential was DELETED while durability was uncertain across repositories!")
	}

	// 【核心红线断言 4】：待清理 journal 绝对不能被丢弃！
	pendingEntries, _ := journalStore.ListPending()
	if len(pendingEntries) != 1 {
		t.Fatalf("CRITICAL DISASTER: cleanup journal was discarded while durability was uncertain, count=%d", len(pendingEntries))
	}
	if pendingEntries[0].Stage != credential.StageCleanup {
		t.Fatalf("expected stage to be preserved as StageCleanup, got %s", pendingEntries[0].Stage)
	}
}

func assertGCCleansUpAfterDurabilityConfirmed(
	t *testing.T,
	ctx context.Context,
	svcA *credential.Service,
	oldRef credential.Ref,
	credStore *inMemoryCredStore,
	journalStore *credential.JournalStore,
) {
	t.Helper()
	res, err := svcA.Recover(ctx)
	if err != nil {
		t.Fatalf("svcA.Recover failed: %v", err)
	}
	if len(res) != 1 || res[0].Action != credential.RecoveryActionCommittedCleaned {
		t.Fatalf("expected RecoveryActionCommittedCleaned, got %+v", res)
	}

	credStore.mu.Lock()
	_, oldStillExistsAfter := credStore.data[oldRef.ItemID]
	credStore.mu.Unlock()
	if oldStillExistsAfter {
		t.Fatalf("old credential should be deleted after durability confirmed")
	}

	pendingAfter, _ := journalStore.ListPending()
	if len(pendingAfter) != 0 {
		t.Fatalf("journal should be removed after cleanup, count=%d", len(pendingAfter))
	}
}

func TestCrossRepository_UndurableUnbind_PreservesCredentialAndJournalDuringGC(t *testing.T) {
	ctx := context.Background()

	// 1. 共享底层存储，模拟跨进程/跨实例存储层
	sharedStore := &memoryPersistStore{cfg: cloneConfiguration(nil)}

	repoA, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), sharedStore)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH repoA failed: %v", err)
	}

	oldRef := credential.Ref{StoreID: "mock-store", ItemID: "old-shared-secret"}
	newRefA := credential.Ref{StoreID: "mock-store", ItemID: "new-secret-nodeA"}

	setupSharedNodesAndIdentities(t, repoA, oldRef)

	// 2. 模拟 node-A 已经完成了轮换，更新为 newRefA，旧凭据 oldRef 进入待清理 journal
	targetA := credential.Target{NodeID: "node-A", Kind: credential.KindLoginPassword}
	outcomeA, _, err := repoA.AsConfigUpdater().ApplyCredentialRefAtVersion(ctx, targetA, "", &newRefA)
	if err != nil || !outcomeA.Durable {
		t.Fatalf("ApplyCredentialRefAtVersion on repoA failed: %v", err)
	}

	// 此时创建 repoB（模拟另一个进程或并发实例启动，其快照同步自共享存储中的最新状态）
	repoB, err := NewRepositoryWithoutOpenSSH(repoA.provider.Snapshot(), sharedStore)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH repoB failed: %v", err)
	}

	svcA, credStore, journalStore := setupTestCredentialEnvironment(t, repoA, oldRef, newRefA)

	// 执行初始 GC：此时 node-B 依然引用 oldRef，必须保留凭据和 journal
	res1, err := svcA.Recover(ctx)
	if err != nil || len(res1) != 1 || res1[0].Action != credential.RecoveryActionScheduledForGC {
		t.Fatalf("expected initial GC to schedule for GC, got res=%+v err=%v", res1, err)
	}

	// 3. 模拟步骤 2：Repository B 解除最后一个引用（解绑 node-B 对 oldRef 的引用）
	// rename 成功（配置已更新，不再包含 oldRef），但目录 sync 失败！
	targetB := credential.Target{NodeID: "node-B", Kind: credential.KindLoginPassword}
	sharedStore.mu.Lock()
	sharedStore.result = &PersistResult{Applied: true, Durable: false}
	sharedStore.syncErr = errors.New("parent directory sync failed")
	sharedStore.mu.Unlock()

	outcomeB, _, err := repoB.AsConfigUpdater().ApplyCredentialRefAtVersion(ctx, targetB, "", nil)
	if err == nil {
		t.Fatalf("expected DurabilityError for repoB mutation, got nil")
	}
	if !outcomeB.Applied || outcomeB.Durable {
		t.Fatalf("expected Applied=true, Durable=false for repoB mutation, got %+v", outcomeB)
	}

	// 4. 模拟步骤 3：Repository A 执行 GC（自身没有 hasUndurableWrite 标记）
	if repoA.hasUndurableWrite.Load() {
		t.Fatalf("repoA must NOT have hasUndurableWrite set")
	}
	assertGCBlockedUnderUndurableStorage(t, ctx, svcA, repoA, oldRef, credStore, journalStore)

	// 5. 模拟存储层完成持久化同步（恢复 Durable 状态）
	sharedStore.mu.Lock()
	sharedStore.result = &PersistResult{Applied: true, Durable: true}
	sharedStore.syncErr = nil
	sharedStore.mu.Unlock()

	assertGCCleansUpAfterDurabilityConfirmed(t, ctx, svcA, oldRef, credStore, journalStore)
}
