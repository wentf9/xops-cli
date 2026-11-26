package inventory_test

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/sim"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

// countingStore 统计 Load 次数并可配置 CommitCAS 阶段触发 panic（验证 Committing panic 恢复路径）。
type countingStore struct {
	base          ports.InventoryStore
	loadHits      atomic.Int32
	panicOnCommit atomic.Bool
}

func (s *countingStore) Load(ctx context.Context) (ports.InventorySnapshot, error) {
	s.loadHits.Add(1)
	return s.base.Load(ctx)
}
func (s *countingStore) CommitCAS(ctx context.Context, expected ports.Revision, next inventory.Graph) (ports.DurabilityOutcome, error) {
	if s.panicOnCommit.Load() {
		panic("store-commit-boom")
	}
	return s.base.CommitCAS(ctx, expected, next)
}

// countingUI 统计 PromptSecret 调用次数（验证拒绝/Halted 门控前零交互）。
type countingUI struct {
	base       ports.InteractionPort
	promptHits atomic.Int32
}

func (c *countingUI) CanInteract() bool { return c.base.CanInteract() }
func (c *countingUI) Confirm(ctx context.Context, req ports.ConfirmRequest) (security.Verdict, error) {
	return c.base.Confirm(ctx, req)
}
func (c *countingUI) PromptApproval(ctx context.Context, env security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	return c.base.PromptApproval(ctx, env)
}
func (c *countingUI) PromptText(ctx context.Context, req ports.TextPromptRequest) (string, error) {
	return c.base.PromptText(ctx, req)
}

//xops:syncclosure
//xops:borrowed
func (c *countingUI) PromptSecret(ctx context.Context, req ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	c.promptHits.Add(1)
	return c.base.PromptSecret(ctx, req, func(box *secret.SecretBox) error { return fn(box) })
}

// unencryptedAwareKeySigner 既支持加密私钥也支持无口令私钥核验，并统计被核验路径清单。
type unencryptedAwareKeySigner struct {
	base      *passphraseCheckingKeySigner
	plainFPs  map[string]inventory.KeyFingerprint
	inspected map[string]int
}

func (*unencryptedAwareKeySigner) ListPublicKeys(context.Context, inventory.AuthMethod) ([]ports.PublicKeyInfo, error) {
	return nil, nil
}
func (*unencryptedAwareKeySigner) Sign(context.Context, inventory.KeyFingerprint, string, []byte) (ports.Signature, error) {
	return zeroTest[ports.Signature](), ports.ErrSignerUnavailable
}
func (u *unencryptedAwareKeySigner) InspectPrivateKeyFingerprint(ctx context.Context, kp inventory.KeyPathSpec, passRef algebraic.Option[secret.Ref]) (inventory.KeyFingerprint, error) {
	u.inspected[kp.String()]++
	if !passRef.IsSome() {
		if fp, ok := u.plainFPs[kp.String()]; ok {
			return fp, nil
		}
		return zeroTest[inventory.KeyFingerprint](), ports.ErrNotFound
	}
	return u.base.InspectPrivateKeyFingerprint(ctx, kp, passRef)
}

func mustNewInvStream(t *testing.T, rng *sim.SeededRand) *events.OperationStream {
	t.Helper()
	tid, err := security.NewTraceIDFrom(rng)
	if err != nil {
		t.Fatalf("NewTraceIDFrom: %v", err)
	}
	oid, err := security.NewOperationIDFrom(rng)
	if err != nil {
		t.Fatalf("NewOperationIDFrom: %v", err)
	}
	s, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: tid, OperationID: oid, OperationBuffer: 32,
	})
	if err != nil {
		t.Fatalf("NewOperationStream: %v", err)
	}
	return s
}

func assertInvStreamCompleted(t *testing.T, ctx context.Context, stream *events.OperationStream, wantOK bool, wantCode string, wantOutcomeSome bool) {
	t.Helper()
	ce := requireCompletedEvent(t, ctx, stream)
	if ce.Succeeded() != wantOK {
		t.Fatalf("OperationCompletedEvent.Succeeded()=%v, want %v (code=%q)", ce.Succeeded(), wantOK, ce.Code())
	}
	if wantCode != "" && !strings.EqualFold(ce.Code(), wantCode) {
		t.Fatalf("OperationCompletedEvent.Code()=%q, want %q", ce.Code(), wantCode)
	}
	if wantOutcomeSome && !ce.Outcome().IsSome() {
		t.Fatalf("期望终态事件携带 OutcomeUnknown，实际为空")
	}
}

func requireCompletedEvent(t *testing.T, ctx context.Context, stream *events.OperationStream) *events.OperationCompletedEvent {
	t.Helper()
	var got *events.OperationCompletedEvent
	for ev, err := range stream.All(ctx) {
		if err != nil {
			t.Fatalf("stream.All: %v", err)
		}
		if ce, ok := ev.(*events.OperationCompletedEvent); ok {
			got = ce
		}
	}
	if got == nil {
		t.Fatalf("OperationStream 缺失 OperationCompletedEvent")
	}
	return got
}

func TestPendingEnrollment_LockFreeProbeObservation(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)

	stagedRef := mustTestRef(t, "lockfree-ref")
	putTestSecret(t, h.vault, stagedRef, "lockfree-secret")
	authPwd, err := inventory.NewAuthPassword(stagedRef)
	if err != nil {
		t.Fatalf("NewAuthPassword: %v", err)
	}
	host := mustTestHost(t, "h-lf", "198.51.100.120", 22)
	ident := mustTestIdentity(t, "id-lf", "ops", authPwd)
	node := mustTestNode(t, "n-lf", "h-lf", "id-lf", nil, nil, algebraic.None[secret.Ref](), nil)
	wantFP := mustTestFP(t, 12)

	res, err := h.svc.WithPendingEnrollment(ctx, ucinv.PendingEnrollmentRequest{
		Host: algebraic.Some(host), Identity: algebraic.Some(ident), Node: node, PinnedRefs: []secret.Ref{stagedRef},
	}, func(c context.Context, lease *ucinv.PendingEnrollmentLease) error {
		// probeFn 期间锁必须已释放：重入观测全部 lease 访问器与 ActivePendingSecretRefs 绝不自死锁！
		fp, pErr := lease.Probe(c, func(context.Context) (inventory.KeyFingerprint, error) {
			if !lease.IsValid() || lease.Phase() != fsm.PendingEnrollPhaseProbing || !lease.LeaseID().IsValid() ||
				!lease.TargetNode().Equal(node.ID()) || len(lease.PinnedRefs()) != 1 || len(h.svc.ActivePendingSecretRefs()) != 1 {
				t.Fatalf("Probe 回调内无锁观测租约状态失配: phase=%s pins=%d", lease.Phase(), len(lease.PinnedRefs()))
			}
			return wantFP, nil
		})
		if pErr != nil || !fp.Equal(wantFP) {
			return pErr
		}
		_, cErr := lease.Commit(c)
		return cErr
	})
	if err != nil || res.Phase() != fsm.PendingEnrollPhaseEnrolled {
		t.Fatalf("无锁 Probe 首连登记失败: phase=%s err=%v", res.Phase(), err)
	}
}

func TestPendingEnrollment_FailClosedTerminalsCancelPanicAndStream(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)
	if _, err := h.svc.CreateHost(ctx, ucinv.HostMutationRequest{Host: mustTestHost(t, "h-fc", "198.51.100.121", 22)}); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: mustTestIdentity(t, "id-fc", "ops", mustAgentAuth(t))}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	// 1. 探测期 ctx 取消 -> WithoutCancel 仍必须彻底清理暂存凭据并进入 Aborted（绝不进 Uncertain）。
	assertPendingCanceledProbeStillCleansUp(t, ctx, h)
	// 2. 回调未 Commit 正常返回 nil -> 必须失败关闭返回 ErrEnrollmentAborted，审计与事件流均不得报成功。
	assertPendingUncommittedNilReturnFailsClosed(t, ctx, h)
	// 3. Cancel 期间 Vault 删除失败 -> Cancel 必须返回 ErrEnrollmentUncertain，保留钉住并上报 OutcomeUnknown。
	assertPendingCancelCleanupFailReturnsUncertain(t, ctx, h)
	// 4. Staged panic 与 CommitCAS(Committing) panic 均发射失败终态事件，且 Committing panic 进 Uncertain 保留钉住。
	assertPendingCommitPanicEntersUncertain(t, ctx, h)
}

func assertPendingCanceledProbeStillCleansUp(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	ref := mustTestRef(t, "fc-cancel-probe")
	putTestSecret(t, h.vault, ref, "cancel-probe-secret")
	node := mustTestNode(t, "n-fc-cancel", "h-fc", "id-fc", nil, nil, algebraic.None[secret.Ref](), nil)
	cCtx, cancel := context.WithCancel(ctx)
	res, err := h.svc.WithPendingEnrollment(cCtx, ucinv.PendingEnrollmentRequest{
		Node: node, PinnedRefs: []secret.Ref{ref},
	}, func(sc context.Context, lease *ucinv.PendingEnrollmentLease) error {
		_, pErr := lease.Probe(sc, func(context.Context) (inventory.KeyFingerprint, error) {
			cancel()
			return zeroTest[inventory.KeyFingerprint](), cCtx.Err()
		})
		return pErr
	})
	if !errors.Is(err, ucinv.ErrEnrollmentAborted) || res.Phase() != fsm.PendingEnrollPhaseAborted {
		t.Fatalf("Probe 取消后应清理进入 Aborted: phase=%s err=%v", res.Phase(), err)
	}
	if _, exists := h.vault.CiphertextFor(ref); exists || len(h.svc.ActivePendingSecretRefs()) != 0 {
		t.Fatalf("Probe 取消后必须通过 WithoutCancel 删除暂存凭据并释放钉住")
	}
}

func assertPendingUncommittedNilReturnFailsClosed(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	ref := mustTestRef(t, "fc-uncommitted")
	putTestSecret(t, h.vault, ref, "uncommitted-secret")
	node := mustTestNode(t, "n-fc-uncommit", "h-fc", "id-fc", nil, nil, algebraic.None[secret.Ref](), nil)
	stream := mustNewInvStream(t, h.rng)
	res, err := h.svc.WithPendingEnrollment(ctx, ucinv.PendingEnrollmentRequest{
		Node: node, PinnedRefs: []secret.Ref{ref}, OperationStream: stream,
	}, func(context.Context, *ucinv.PendingEnrollmentLease) error {
		return nil // 故意不调用 Commit 直接返回 nil
	})
	if !errors.Is(err, ucinv.ErrEnrollmentAborted) || res.Phase() != fsm.PendingEnrollPhaseAborted {
		t.Fatalf("未提交直接返回 nil 必须失败关闭返回 ErrEnrollmentAborted: phase=%s err=%v", res.Phase(), err)
	}
	entries := h.cluster.Entries()
	if last := entries[len(entries)-1]; last.Outcome() == ports.AuditOutcomeSucceeded {
		t.Fatalf("未提交退出绝不可写入 AuditOutcomeSucceeded")
	}
	assertInvStreamCompleted(t, ctx, stream, false, "inventory_error", false)
}

func assertPendingCancelCleanupFailReturnsUncertain(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	ref := mustTestRef(t, "fc-cancel-fail")
	putTestSecret(t, h.vault, ref, "cancel-fail-secret")
	node := mustTestNode(t, "n-fc-cancelfail", "h-fc", "id-fc", nil, nil, algebraic.None[secret.Ref](), nil)
	stream := mustNewInvStream(t, h.rng)
	var cancelRet error
	res, err := h.svc.WithPendingEnrollment(ctx, ucinv.PendingEnrollmentRequest{
		Node: node, PinnedRefs: []secret.Ref{ref}, OperationStream: stream,
	}, func(c context.Context, lease *ucinv.PendingEnrollmentLease) error {
		h.vault.Faults().InjectOnce("vault.delete", io.ErrUnexpectedEOF)
		cancelRet = lease.Cancel(c, "operator cancel")
		return cancelRet
	})
	if !errors.Is(cancelRet, ucinv.ErrEnrollmentUncertain) || !errors.Is(err, ucinv.ErrEnrollmentUncertain) || res.Phase() != fsm.PendingEnrollPhaseUncertain {
		t.Fatalf("Cancel 清理失败必须返回 ErrEnrollmentUncertain: cancelRet=%v err=%v phase=%s", cancelRet, err, res.Phase())
	}
	if len(h.svc.ActivePendingSecretRefs()) == 0 {
		t.Fatalf("Cancel 转入 Uncertain 时必须保留凭据钉住")
	}
	entries := h.cluster.Entries()
	if last := entries[len(entries)-1]; last.Outcome() != ports.AuditOutcomeUnknown {
		t.Fatalf("Cancel 转入 Uncertain 必须写入 AuditOutcomeUnknown，实际=%s", last.Outcome())
	}
	assertInvStreamCompleted(t, ctx, stream, false, "", true)
}

func assertPendingCommitPanicEntersUncertain(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	pStore := &countingStore{base: h.store}
	pStore.panicOnCommit.Store(true)
	svc, err := ucinv.NewService(ucinv.ServiceConfig{
		Store: pStore, Gate: h.gate, Vault: h.vault, VaultControl: h.vault,
		Clock: h.clock, Entropy: h.rng.Fork(), KnownStores: []string{testStoreName},
	})
	if err != nil {
		t.Fatalf("NewService(pStore): %v", err)
	}
	ref := mustTestRef(t, "fc-commit-panic")
	putTestSecret(t, h.vault, ref, "commit-panic-secret")
	node := mustTestNode(t, "n-fc-cpanic", "h-fc", "id-fc", nil, nil, algebraic.None[secret.Ref](), nil)
	stream := mustNewInvStream(t, h.rng)
	var rec any
	func() {
		defer func() { rec = recover() }()
		_, _ = svc.WithPendingEnrollment(ctx, ucinv.PendingEnrollmentRequest{
			Node: node, PinnedRefs: []secret.Ref{ref}, OperationStream: stream,
		}, func(c context.Context, lease *ucinv.PendingEnrollmentLease) error {
			if _, pErr := lease.Probe(c, func(context.Context) (inventory.KeyFingerprint, error) { return mustTestFP(t, 33), nil }); pErr != nil {
				return pErr
			}
			_, cErr := lease.Commit(c)
			return cErr
		})
	}()
	if rec != "store-commit-boom" {
		t.Fatalf("CommitCAS panic 应原样传播，实际=%v", rec)
	}
	if pins := svc.ActivePendingSecretRefs(); len(pins) != 1 || !pins[0].Ref.Equal(ref) {
		t.Fatalf("CommitCAS panic 须经 Committing->Uncertain 保留钉住防 GC，实际=%v", pins)
	}
	entries := h.cluster.Entries()
	if last := entries[len(entries)-1]; last.Outcome() != ports.AuditOutcomeUnknown {
		t.Fatalf("CommitCAS panic 必须上报 AuditOutcomeUnknown，实际=%s", last.Outcome())
	}
	assertInvStreamCompleted(t, ctx, stream, false, "panic", true)
}

func TestImport_CrossNamespaceOpenSSHAndCustomMaxJumpDepth(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. 空库导入：bundle 内 bundle-app -> OpenSSH osh-bastion -> bundle 内 bundle-jump 必须预检与落盘双双通过！
	oshBastion := mustVirtualHost(t, "osh-bastion", "198.51.100.200", 22, "ops", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "bundle-jump")))
	h := newInvHarness(t, nil, oshBastion)
	hJump := mustTestHost(t, "h-bjump", "198.51.100.201", 22)
	hApp := mustTestHost(t, "h-bapp", "198.51.100.202", 22)
	idOps := mustTestIdentity(t, "id-bops", "ops", mustAgentAuth(t))
	nJump := mustTestNode(t, "bundle-jump", "h-bjump", "id-bops", nil, nil, algebraic.None[secret.Ref](), nil)
	nApp := mustTestNode(t, "bundle-app", "h-bapp", "id-bops", nil, mustProxyJump(t, "osh-bastion"), algebraic.None[secret.Ref](), nil)
	bundle, err := inventory.NewImportBundle(inventory.ImportBundleSpec{
		SourceFormat: "custom",
		Hosts:        []inventory.Host{hJump, hApp},
		Identities:   []inventory.Identity{idOps},
		Nodes:        []inventory.Node{nJump, nApp},
	})
	if err != nil {
		t.Fatalf("NewImportBundle: %v", err)
	}
	prev, err := h.svc.PlanImport(ctx, ucinv.ImportSourceRequest{Bundle: algebraic.Some(bundle)})
	if err != nil || prev.Report().HasConflicts() {
		t.Fatalf("空库导入跨命名空间 OpenSSH ProxyJump 不应误报冲突: conflicts=%d entries=%+v err=%v", prev.Report().ConflictCount, prev.Report().Entries, err)
	}
	appRes, err := h.svc.ApplyImport(ctx, ucinv.ApplyImportRequest{Source: ucinv.ImportSourceRequest{Bundle: algebraic.Some(bundle)}})
	if err != nil || !appRes.Applied() {
		t.Fatalf("空库导入跨命名空间 OpenSSH ProxyJump ApplyImport 失败: err=%v", err)
	}

	// 2. 自定义 MaxJumpDepth=1：在空库上导入 2 跳链 (d-n3 -> d-n2 -> d-n1)，PlanImport 与 ApplyImport(DryRun/Apply) 均须一致报冲突！
	emptyStore, err := sim.NewSimInventoryStore(inventory.EmptyGraph())
	if err != nil {
		t.Fatalf("NewSimInventoryStore: %v", err)
	}
	shallowSvc, err := ucinv.NewService(ucinv.ServiceConfig{
		Store: emptyStore, Gate: h.gate, Vault: h.vault, VaultControl: h.vault,
		Clock: h.clock, Entropy: h.rng.Fork(), MaxJumpDepth: 1, KnownStores: []string{testStoreName},
	})
	if err != nil {
		t.Fatalf("NewService(MaxJumpDepth=1): %v", err)
	}
	n1 := mustTestNode(t, "d-n1", "h-bjump", "id-bops", nil, nil, algebraic.None[secret.Ref](), nil)
	n2 := mustTestNode(t, "d-n2", "h-bjump", "id-bops", nil, mustProxyJump(t, "d-n1"), algebraic.None[secret.Ref](), nil)
	n3 := mustTestNode(t, "d-n3", "h-bjump", "id-bops", nil, mustProxyJump(t, "d-n2"), algebraic.None[secret.Ref](), nil)
	deepBundle, err := inventory.NewImportBundle(inventory.ImportBundleSpec{
		SourceFormat: "custom", Hosts: []inventory.Host{hJump}, Identities: []inventory.Identity{idOps}, Nodes: []inventory.Node{n1, n2, n3},
	})
	if err != nil {
		t.Fatalf("NewImportBundle(deep): %v", err)
	}
	deepPrev, err := shallowSvc.PlanImport(ctx, ucinv.ImportSourceRequest{Bundle: algebraic.Some(deepBundle)})
	if err != nil || !deepPrev.Report().HasConflicts() {
		t.Fatalf("MaxJumpDepth=1 时 PlanImport 必须拦截 2 跳深度超限: conflicts=%d err=%v", deepPrev.Report().ConflictCount, err)
	}
	if _, err := shallowSvc.ApplyImport(ctx, ucinv.ApplyImportRequest{
		Source: ucinv.ImportSourceRequest{Bundle: algebraic.Some(deepBundle)}, DryRun: true,
	}); !errors.Is(err, ucinv.ErrImportConflict) {
		t.Fatalf("MaxJumpDepth=1 时 DryRun ApplyImport 必须返回 ErrImportConflict，实际=%v", err)
	}
}

func TestDoctorAndCRUD_ReviewRegressions(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)

	// 1. GetHost 传入无效 ID 时必须闭合 OperationStream（确定性 EOF）。
	badStream := mustNewInvStream(t, h.rng)
	if _, _, err := h.svc.GetHost(ctx, zeroTest[inventory.HostID](), ucinv.QueryRequest{OperationStream: badStream}); !errors.Is(err, ucinv.ErrInvalidRequest) || !badStream.IsClosed() {
		t.Fatalf("无效 HostID 早退必须闭合 OperationStream: err=%v closed=%v", err, badStream.IsClosed())
	}

	// 2. ValidateDAG 遇环路时返回 ErrProxyJumpCycle 且保留 DAGReport.Cycles。
	assertValidateDAGPreservesCycles(t, ctx, h)

	// 3. Vault==nil 时 DeleteIdentity(DeleteUnusedSecrets=true) 必须写前失败关闭返回 ErrVaultUnavailable；
	//    Doctor(CheckVaultSecrets=true, CheckPrivateKeys=true) 且缺端口时须发出 Warn 告警。
	assertMissingPortsFailClosedAndWarn(t, ctx, h)

	// 4. buildValidatedGraph 在 VaultControl.Status 报错时必须失败关闭；
	//    post-commit GC 失败必须上报 AuditOutcomeUnknown；DoctorReport 支持 JSON v2 往返且核验全部 KeyPaths。
	assertDoctorMultiKeyVaultStatusAndPostCommitGC(t, ctx, h)
}

func assertValidateDAGPreservesCycles(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	vhA := mustVirtualHost(t, "cyc-a", "198.51.100.210", 22, "ops", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "cyc-b")))
	vhB := mustVirtualHost(t, "cyc-b", "198.51.100.211", 22, "ops", option.UnsetOptionLayer().WithProxyRoute(mustProxyJump(t, "cyc-a")))
	hCyc := newInvHarness(t, nil, vhA, vhB)
	rep, err := hCyc.svc.ValidateDAG(ctx, ucinv.QueryRequest{})
	if !errors.Is(err, inventory.ErrProxyJumpCycle) || len(rep.Cycles) == 0 {
		t.Fatalf("ValidateDAG 遇环路必须保留 Cycles 供诊断: err=%v cycles=%v", err, rep.Cycles)
	}
	_ = h
}

func assertMissingPortsFailClosedAndWarn(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	noVaultSvc, err := ucinv.NewService(ucinv.ServiceConfig{
		Store: h.store, Gate: h.gate, Clock: h.clock, Entropy: h.rng.Fork(), KnownStores: []string{testStoreName},
	})
	if err != nil {
		t.Fatalf("NewService(noVault): %v", err)
	}
	iid, _ := inventory.ParseIdentityID("id-nv")
	if _, err := noVaultSvc.DeleteIdentity(ctx, ucinv.DeleteIdentityRequest{ID: iid, DeleteUnusedSecrets: true}); !errors.Is(err, ucinv.ErrVaultUnavailable) {
		t.Fatalf("Vault==nil 且 DeleteUnusedSecrets=true 必须失败关闭返回 ErrVaultUnavailable，实际=%v", err)
	}
	docRep, err := noVaultSvc.Doctor(ctx, ucinv.DoctorRequest{CheckVaultSecrets: true, CheckPrivateKeys: true})
	if err != nil {
		t.Fatalf("Doctor(noVault/noSigner): %v", err)
	}
	if !hasInvFinding(docRep.Findings, ucinv.DoctorSeverityWarn, "vault_unavailable") ||
		!hasInvFinding(docRep.Findings, ucinv.DoctorSeverityWarn, "key_signer_unavailable") {
		t.Fatalf("缺少 Vault/KeySigner 时 Doctor 必须发出 Warn 告警: %+v", docRep.Findings)
	}
	raw, err := jsonv2.Marshal(docRep, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("jsonv2.Marshal(DoctorReport): %v", err)
	}
	var roundTrip ucinv.DoctorReport
	if err := jsonv2.Unmarshal(raw, &roundTrip); err != nil || len(roundTrip.Findings) != len(docRep.Findings) {
		t.Fatalf("inventory.DoctorReport JSON v2 往返失败: err=%v got=%+v", err, roundTrip)
	}
}

func assertDoctorMultiKeyVaultStatusAndPostCommitGC(t *testing.T, ctx context.Context, h *invTestHarness) {
	t.Helper()
	// 1. VaultControl.Status 报错 -> CreateHost 写前构图必须失败关闭（不静默吞错）。
	h.vault.Faults().InjectOnce("vault.status", io.ErrUnexpectedEOF)
	if _, err := h.svc.CreateHost(ctx, ucinv.HostMutationRequest{Host: mustTestHost(t, "h-vs-fail", "198.51.100.220", 22)}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("VaultControl.Status 失败时写前构图必须失败关闭，实际=%v", err)
	}

	// 2. Doctor 检查多 KeyPaths 与无口令私钥（覆盖全路径）。
	plainSigner := &unencryptedAwareKeySigner{
		base:      h.signer,
		plainFPs:  map[string]inventory.KeyFingerprint{"~/.ssh/plain_k1": mustTestFP(t, 1)},
		inspected: make(map[string]int),
	}
	kp1, _ := inventory.ParseKeyPathSpec("~/.ssh/plain_k1")
	kp2, _ := inventory.ParseKeyPathSpec("~/.ssh/plain_k2_missing")
	aMulti, err := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kp1, kp2), algebraic.None[inventory.KeyPassphraseBinding](), nil)
	if err != nil {
		t.Fatalf("NewAuthPrivateKey(multi): %v", err)
	}
	idMulti := mustTestIdentity(t, "id-multi-kp", "ops", aMulti)
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: idMulti}); err != nil {
		t.Fatalf("CreateIdentity(id-multi-kp): %v", err)
	}
	docSvc, err := ucinv.NewService(ucinv.ServiceConfig{
		Store: h.store, Gate: h.gate, Vault: h.vault, VaultControl: h.vault, KeySigner: plainSigner,
		Clock: h.clock, Entropy: h.rng.Fork(), KnownStores: []string{testStoreName},
	})
	if err != nil {
		t.Fatalf("NewService(plainSigner): %v", err)
	}
	docRep, err := docSvc.Doctor(ctx, ucinv.DoctorRequest{CheckPrivateKeys: true})
	if err != nil || plainSigner.inspected[kp1.String()] != 1 || plainSigner.inspected[kp2.String()] != 1 ||
		!hasInvFinding(docRep.Findings, ucinv.DoctorSeverityError, "private_key_inspect_failed") {
		t.Fatalf("Doctor 必须核验无口令与全部多路径私钥: inspected=%v findings=%+v err=%v", plainSigner.inspected, docRep.Findings, err)
	}

	// 3. DeleteIdentity 提交后 GC 失败 -> 必须上报 AuditOutcomeUnknown。
	rGC := mustTestRef(t, "post-commit-gc-fail")
	putTestSecret(t, h.vault, rGC, "gc-fail-val")
	aPwd, _ := inventory.NewAuthPassword(rGC)
	idGC := mustTestIdentity(t, "id-gc-fail", "ops", aPwd)
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: idGC}); err != nil {
		t.Fatalf("CreateIdentity(id-gc-fail): %v", err)
	}
	h.vault.Faults().InjectOnce("vault.delete", io.ErrUnexpectedEOF)
	if _, err := h.svc.DeleteIdentity(ctx, ucinv.DeleteIdentityRequest{ID: idGC.ID(), DeleteUnusedSecrets: true}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("提交后 GC 失败应返回故障错误，实际=%v", err)
	}
	entries := h.cluster.Entries()
	if last := entries[len(entries)-1]; last.Outcome() != ports.AuditOutcomeUnknown {
		t.Fatalf("配置 CAS 已生效但后置 GC 失败必须上报 AuditOutcomeUnknown，实际=%s", last.Outcome())
	}
}

func TestKeyEnroll_PreGateIsolationAndMultiSecretReplaceGC(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	h := newInvHarness(t, nil)

	// 1. 门控拒绝（RiskDangerous 无审批）时 ReplaceExisting=true 绝不可在 Gate 前调用 store.Load 或 PromptSecret！
	cStore := &countingStore{base: h.store}
	cUI := &countingUI{base: h.ui}
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskDangerous, NoElicitFallback: gate.NoElicitFallbackDeny,
	})
	if err != nil {
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	procID, _ := ports.ParseProcessInstanceID("proc-key-strict")
	sink, err := h.cluster.NewSink(procID)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	strictGate, err := gate.NewGate(gate.GateConfig{
		Profile: gate.PolicyProfileStrictAgent, Policy: pol, AuditSink: sink, Interaction: nil, Clock: h.clock, Entropy: h.rng.Fork(),
	})
	if err != nil {
		t.Fatalf("NewGate(strict): %v", err)
	}
	strictSvc, err := ucinv.NewService(ucinv.ServiceConfig{
		Store: cStore, Gate: strictGate, Vault: h.vault, VaultControl: h.vault, KeySigner: h.signer,
		Interaction: cUI, Clock: h.clock, Entropy: h.rng.Fork(), KnownStores: []string{testStoreName},
	})
	if err != nil {
		t.Fatalf("NewService(strict): %v", err)
	}
	kp, _ := inventory.ParseKeyPathSpec("~/.ssh/strict_ed25519")
	user, _ := option.ParseUsername("deploy")
	iid, _ := inventory.ParseIdentityID("id-strict-key")
	_, err = strictSvc.EnrollEncryptedPrivateKeyIdentity(ctx, ucinv.EnrollEncryptedPrivateKeyRequest{
		IdentityID: iid, User: user, KeyPath: kp, NewRef: mustTestRef(t, "denied-key-ref"),
		ReplaceExisting: true, Risk: algebraic.Some(security.RiskDangerous),
	})
	if err == nil || cStore.loadHits.Load() != 0 || cUI.promptHits.Load() != 0 {
		t.Fatalf("策略拒绝场景绝不可提前 Load 或 PromptSecret: err=%v loads=%d prompts=%d", err, cStore.loadHits.Load(), cUI.promptHits.Load())
	}

	// 2. ReplaceExisting=true 覆盖多凭据 *AuthComposite（密码 + TOTP + 旧私钥口令）后，3 处旧凭据必须全部 GC 零孤儿！
	rOldPwd := mustTestRef(t, "multi-old-pwd")
	rOldKey := mustTestRef(t, "multi-old-key")
	rOldTOTP := mustTestRef(t, "multi-old-totp")
	rOldChal := mustTestRef(t, "multi-old-chal")
	for _, r := range []secret.Ref{rOldPwd, rOldKey, rOldTOTP, rOldChal} {
		putTestSecret(t, h.vault, r, "old-secret-"+r.Item())
	}
	compIdent := mustTestIdentity(t, "id-multi-replace", "deploy", buildFiveLocationCompositeAuth(t, rOldPwd, rOldKey, rOldTOTP, rOldChal))
	if _, err := h.svc.CreateIdentity(ctx, ucinv.IdentityMutationRequest{Identity: compIdent}); err != nil {
		t.Fatalf("CreateIdentity(comp): %v", err)
	}
	newKP, _ := inventory.ParseKeyPathSpec("~/.ssh/new_replace_key")
	newFP := mustTestFP(t, 88)
	h.signer.Register(newKP.String(), "new-replace-pass", newFP)
	newRef := mustTestRef(t, "multi-new-key")
	h.ui.SetReplies("", []byte("new-replace-pass"))
	res, err := h.svc.EnrollEncryptedPrivateKeyIdentity(ctx, ucinv.EnrollEncryptedPrivateKeyRequest{
		IdentityID: compIdent.ID(), User: user, KeyPath: newKP, NewRef: newRef, ReplaceExisting: true,
	})
	if err != nil || !res.IsValid() || !res.Fingerprint().Equal(newFP) {
		t.Fatalf("覆盖多凭据身份登记加密私钥失败: res=%+v err=%v", res, err)
	}
	for _, oldR := range []secret.Ref{rOldPwd, rOldKey, rOldTOTP, rOldChal} {
		if _, exists := h.vault.CiphertextFor(oldR); exists {
			t.Fatalf("覆盖多凭据身份后旧凭据 %s 未被 GC 回收（孤儿泄漏）", oldR)
		}
	}
}

func hasInvFinding(findings []ucinv.DoctorFinding, sev ucinv.DoctorSeverity, code string) bool {
	for _, f := range findings {
		if f.Severity == sev && f.Code == code {
			return true
		}
	}
	return false
}
