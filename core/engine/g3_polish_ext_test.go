package engine_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
)

// TestEngine_G3Polish_SemanticErrorsAndReferenceConflict 验证 #118 M1 / #119 B1-7：
// 公开 engine 语义错误哨兵保链映射与资产/凭据结构化引用冲突只读提取器。
func TestEngine_G3Polish_SemanticErrorsAndReferenceConflict(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSimRig(t, engine.PolicyProfileDirectOperator, security.RiskDangerous, true)
	defer rig.close(t)
	ctx := context.Background()

	secRef := seedReferencedNodeAndAssertConflicts(t, ctx, rig)
	assertVaultAndTransferSemanticErrors(t, ctx, rig, secRef)
}

func seedReferencedNodeAndAssertConflicts(t *testing.T, ctx context.Context, rig *fullSimRig) secret.Ref {
	t.Helper()
	hID, _ := inventory.ParseHostID("h-ref")
	ep, _ := netaddr.ParseEndpoint("10.20.0.1:22")
	hostObj, _ := inventory.NewHost(inventory.HostSpec{ID: hID, Endpoint: ep})
	if _, err := rig.eng.CreateHost(ctx, engine.HostMutationRequest{Host: hostObj}); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	if _, err := rig.eng.CreateHost(ctx, engine.HostMutationRequest{Host: hostObj}); !errors.Is(err, engine.ErrAlreadyExists) {
		t.Fatalf("重复 CreateHost 期望 ErrAlreadyExists，实际=%v", err)
	}
	staleRev, _ := engine.ParseRevision("rev-stale-999")
	if _, err := rig.eng.UpdateHost(ctx, engine.HostMutationRequest{Host: hostObj, ExpectedRevision: algebraic.Some(staleRev)}); !errors.Is(err, engine.ErrRevisionConflict) || !errors.Is(err, ports.ErrRevisionConflict) {
		t.Fatalf("过期 Revision 期望 ErrRevisionConflict + ports.ErrRevisionConflict，实际=%v", err)
	}

	secRef, _ := secret.NewRef("vault", "ref-secret-1")
	_ = secret.WithBytes([]byte("pw-1"), func(box *secret.SecretBox) error { return rig.vault.PutAndVerify(ctx, secRef, box) })
	idID, _ := inventory.ParseIdentityID("id-ref")
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthPassword(secRef)
	identObj, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idID, User: user, Auth: auth})
	if _, err := rig.eng.CreateIdentity(ctx, engine.IdentityMutationRequest{Identity: identObj}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	nID, _ := inventory.ParseNodeID("node-ref")
	nodeObj, _ := inventory.NewNode(inventory.NodeSpec{ID: nID, HostRef: hID, IdentityRef: idID, Origin: inventory.NewOriginManaged()})
	if _, err := rig.eng.CreateNode(ctx, engine.NodeMutationRequest{Node: nodeObj}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	_, delHostErr := rig.eng.DeleteHost(ctx, engine.DeleteAssetRequest{ID: "h-ref"})
	if !errors.Is(delHostErr, engine.ErrStillReferenced) {
		t.Fatalf("删除被引用 Host 期望 ErrStillReferenced，实际=%v", delHostErr)
	}
	if rc, ok := engine.ExtractReferenceConflict(delHostErr); !ok || !rc.IsValid() || rc.AssetKind() != "host" || rc.Subject() != "h-ref" || len(rc.AssetReferences()) == 0 {
		t.Fatalf("ExtractReferenceConflict(Host) 失配: ok=%v rc=%+v", ok, rc)
	}
	delSecErr := rig.eng.DeleteSecret(ctx, engine.DeleteSecretRequest{Ref: secRef})
	if !errors.Is(delSecErr, engine.ErrStillReferenced) {
		t.Fatalf("删除被引用 Secret 期望 ErrStillReferenced，实际=%v", delSecErr)
	}
	if rc, ok := engine.ExtractReferenceConflict(delSecErr); !ok || !rc.IsValid() || rc.AssetKind() != "secret" || len(rc.SecretReferences()) == 0 {
		t.Fatalf("ExtractReferenceConflict(Secret) 失配: ok=%v rc=%+v", ok, rc)
	}
	return secRef
}

func assertVaultAndTransferSemanticErrors(t *testing.T, ctx context.Context, rig *fullSimRig, secRef secret.Ref) {
	t.Helper()
	missID, _ := inventory.ParseNodeID("no-such-node")
	if _, _, err := rig.eng.GetNode(ctx, missID, engine.InventoryQueryRequest{}); !errors.Is(err, engine.ErrNotFound) {
		t.Fatalf("GetNode 缺失期望 ErrNotFound，实际=%v", err)
	}
	missRef, _ := secret.NewRef("vault", "missing-key")
	if err := rig.eng.WithSecret(ctx, engine.WithSecretRequest{Ref: missRef}, func(*secret.SecretBox) error { return nil }); !errors.Is(err, engine.ErrSecretNotFound) || !errors.Is(err, ports.ErrSecretNotFound) {
		t.Fatalf("WithSecret 缺失期望 ErrSecretNotFound + ports.ErrSecretNotFound，实际=%v", err)
	}
	if err := rig.eng.VaultLock(ctx, engine.VaultOpRequest{}); err != nil {
		t.Fatalf("VaultLock: %v", err)
	}
	if err := rig.eng.WithSecret(ctx, engine.WithSecretRequest{Ref: secRef}, func(*secret.SecretBox) error { return nil }); !errors.Is(err, engine.ErrVaultLocked) || !errors.Is(err, ports.ErrVaultLocked) {
		t.Fatalf("锁定 Vault 期望 ErrVaultLocked + ports.ErrVaultLocked，实际=%v", err)
	}
	rc := engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "node-ref"}}
	dirPath, _ := pathalg.ParseRemotePath("/srv")
	if _, err := rig.eng.ReadRemoteFile(ctx, engine.RemoteFileReadRequest{RemoteCall: rc, Path: dirPath}); !errors.Is(err, engine.ErrRemoteIsDir) || !errors.Is(err, ports.ErrRemoteIsDir) {
		t.Fatalf("读取远端目录期望 ErrRemoteIsDir，实际=%v", err)
	}
	fPath, _ := pathalg.ParseRemotePath("/srv/patch.txt")
	if _, err := rig.eng.WriteRemoteFile(ctx, engine.RemoteFileWriteRequest{RemoteCall: rc, Path: fPath, Content: []byte("hello world")}); err != nil {
		t.Fatalf("WriteRemoteFile: %v", err)
	}
	badEdit, _ := engine.NewTextEdit("not-present", "x", false)
	if _, err := rig.eng.PatchRemoteFile(ctx, engine.RemoteFilePatchRequest{RemoteCall: rc, Path: fPath, Edits: []engine.TextEdit{badEdit}}); !errors.Is(err, engine.ErrPatchConflict) {
		t.Fatalf("补丁不匹配期望 ErrPatchConflict，实际=%v", err)
	}
	wrongAnc, _ := engine.NewRemoteFileAnchor(engine.RemoteFileRegular, true, 999, 999)
	if _, err := rig.eng.WriteRemoteFile(ctx, engine.RemoteFileWriteRequest{RemoteCall: rc, Path: fPath, Content: []byte("v2"), ExpectedAnchor: algebraic.Some(wrongAnc)}); !errors.Is(err, engine.ErrRemoteAnchorMismatch) || !errors.Is(err, ports.ErrRemoteAnchorMismatch) {
		t.Fatalf("远端锚点失配期望 ErrRemoteAnchorMismatch，实际=%v", err)
	}
	var badHandle plan.ManagedHandle[plan.KindPTY]
	if _, err := rig.eng.InspectPTY(ctx, badHandle); err == nil || !errors.Is(err, pool.ErrInvalidHandle) {
		t.Fatalf("无效句柄期望 ErrInvalidHandle，实际=%v", err)
	}
}

// TestEngine_G3Polish_OperationStreamDeterministicEOFOnEarlyReturns 验证 #118 M2：
// 全部带 OperationStream 的 Engine 入口在参数校验/未初始化/已关闭/空 Vault/空回调早退路径均确保确定性 EOF。
func TestEngine_G3Polish_OperationStreamDeterministicEOFOnEarlyReturns(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newFullSimRig(t, engine.PolicyProfileDirectOperator, security.RiskDangerous, true)
	defer rig.close(t)
	ctx := context.Background()

	assertClosedEOF := func(name string, s *events.OperationStream) {
		t.Helper()
		if !s.IsClosed() {
			t.Fatalf("%s 早退后未关闭 OperationStream", name)
		}
		for _, iterErr := range s.All(ctx) {
			if iterErr != nil {
				t.Fatalf("%s OperationStream.All 异常: %v", name, iterErr)
			}
		}
	}
	newStream := func() *events.OperationStream {
		s, err := rig.eng.NewOperationStream(ctx, 8)
		if err != nil {
			t.Fatalf("NewOperationStream: %v", err)
		}
		return s
	}

	// 1. 零值 Engine 早退
	var zeroEng engine.Engine
	s0 := newStream()
	_, _ = zeroEng.Exec(ctx, engine.ExecRequest{TargetSpec: "127.0.0.1", Command: "id", OperationStream: s0})
	assertClosedEOF("zeroEng.Exec", s0)

	// 2. DeleteHost / DeleteIdentity / DeleteNode 非法 ID 早退
	s1, s2, s3 := newStream(), newStream(), newStream()
	_, _ = rig.eng.DeleteHost(ctx, engine.DeleteAssetRequest{ID: "bad id!", CallOptions: engine.CallOptions{OperationStream: s1}})
	_, _ = rig.eng.DeleteIdentity(ctx, engine.DeleteAssetRequest{ID: "bad id!", CallOptions: engine.CallOptions{OperationStream: s2}})
	_, _ = rig.eng.DeleteNode(ctx, engine.DeleteAssetRequest{ID: "bad id!", CallOptions: engine.CallOptions{OperationStream: s3}})
	assertClosedEOF("DeleteHost(badID)", s1)
	assertClosedEOF("DeleteIdentity(badID)", s2)
	assertClosedEOF("DeleteNode(badID)", s3)

	// 3. WithPendingEnrollment / WithSecret 空回调早退
	s4, s5 := newStream(), newStream()
	_, _ = rig.eng.WithPendingEnrollment(ctx, engine.PendingEnrollmentRequest{OperationStream: s4}, nil)
	_ = rig.eng.WithSecret(ctx, engine.WithSecretRequest{OperationStream: s5}, nil)
	assertClosedEOF("WithPendingEnrollment(nil fn)", s4)
	assertClosedEOF("WithSecret(nil fn)", s5)

	// 4. ExecPrivileged / WriteRemoteFile / BatchExec / RunPlaybook 早退（含 NodeStreams）
	s6, s7, s8, sNode, s9 := newStream(), newStream(), newStream(), newStream(), newStream()
	nID, _ := inventory.ParseNodeID("bad-n1")
	var zeroTarget engine.ResolvedTarget
	_, _ = rig.eng.ExecPrivileged(ctx, engine.PrivilegeExecRequest{RemoteCall: engine.RemoteCall{CallOptions: engine.CallOptions{OperationStream: s6}}})
	_, _ = rig.eng.WriteRemoteFile(ctx, engine.RemoteFileWriteRequest{RemoteCall: engine.RemoteCall{CallOptions: engine.CallOptions{OperationStream: s7}}})
	_, _ = rig.eng.BatchExec(ctx, engine.BatchExecRequest{CallOptions: engine.CallOptions{OperationStream: s8}, Targets: []engine.ResolvedTarget{zeroTarget}, NodeStreams: map[inventory.NodeID]*events.OperationStream{nID: sNode}})
	_, _ = rig.eng.RunPlaybook(ctx, engine.PlaybookRequest{CallOptions: engine.CallOptions{OperationStream: s9}, Targets: []engine.ResolvedTarget{zeroTarget}})
	assertClosedEOF("ExecPrivileged(badTarget)", s6)
	assertClosedEOF("WriteRemoteFile(badTarget)", s7)
	assertClosedEOF("BatchExec(badTarget)", s8)
	assertClosedEOF("BatchExec.NodeStreams", sNode)
	assertClosedEOF("RunPlaybook(badTarget)", s9)
}

// TestEngine_G3Polish_NoHiddenListNodesAuditOnBatchAndPlaybook 验证 #118 M3 / #119 Nit-1：
// ApprovalThreshold == RiskSafe 且不可交互下，BatchExec / RunPlaybook / MCP xops_exec_batch
// 直接消费 ResolvedTarget 快照的 Tags/DefaultProfile，产生 0 条隐藏 get_snapshot 审计与挑战。
func TestEngine_G3Polish_NoHiddenListNodesAuditOnBatchAndPlaybook(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rig := newFullSimRig(t, engine.PolicyProfileStrictOperator, security.RiskSafe, true)
	defer rig.close(t)

	// 创建带 Tag 与 DefaultProfile 的托管节点（需走先 CreateHost/Identity/Node，simRig 的 interact 允许确认）。
	hID, _ := inventory.ParseHostID("h-tag")
	ep, _ := netaddr.ParseEndpoint("10.30.0.1:22")
	hostObj, _ := inventory.NewHost(inventory.HostSpec{ID: hID, Endpoint: ep})
	if _, err := rig.eng.CreateHost(ctx, engine.HostMutationRequest{Host: hostObj}); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	secRef, _ := secret.NewRef("vault", "tag-pw")
	_ = secret.WithBytes([]byte("pw"), func(box *secret.SecretBox) error { return rig.vault.PutAndVerify(ctx, secRef, box) })
	idID, _ := inventory.ParseIdentityID("id-tag")
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthPassword(secRef)
	identObj, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idID, User: user, Auth: auth})
	if _, err := rig.eng.CreateIdentity(ctx, engine.IdentityMutationRequest{Identity: identObj}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	webTag, _ := inventory.ParseTag("web")
	nID, _ := inventory.ParseNodeID("web-01")
	prof := execution.DefaultServerLaunchProfile()
	nodeObj, _ := inventory.NewNode(inventory.NodeSpec{
		ID: nID, HostRef: hID, IdentityRef: idID, Origin: inventory.NewOriginManaged(),
		Tags: []inventory.Tag{webTag}, Execution: algebraic.Some(prof),
	})
	if _, err := rig.eng.CreateNode(ctx, engine.NodeMutationRequest{Node: nodeObj}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	resolved, err := rig.eng.ResolveTarget(ctx, engine.ResolveTargetRequest{Target: "web-01"})
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if len(resolved.Tags()) != 1 || resolved.Tags()[0] != webTag || resolved.DefaultProfile().IsNone() {
		t.Fatalf("ResolvedTarget 未快照托管 Tags/DefaultProfile: tags=%v prof=%+v", resolved.Tags(), resolved.DefaultProfile())
	}

	auditBefore := len(rig.auditClust.Entries())
	cmd, _ := execution.NewCommandPlan(execution.CommandPlanSpec{Kind: execution.PlanKindCommand, Profile: prof, Command: "echo hi"})
	sel, _ := playbook.NewTargetSelector(playbook.TargetSelectorSpec{Nodes: []inventory.NodeID{nID}, Tags: []inventory.Tag{webTag}})
	var nodeStreamCalled atomic.Int32
	rep, err := rig.eng.BatchExec(ctx, engine.BatchExecRequest{
		Targets: []engine.ResolvedTarget{resolved}, Selector: algebraic.Some(sel), Command: cmd,
		NodeStreamFactory: func(_ inventory.NodeID, _ security.TraceID, _ security.OperationID) (*events.OperationStream, error) {
			nodeStreamCalled.Add(1)
			return rig.eng.NewOperationStream(ctx, 8)
		},
	})
	if err != nil || !rep.IsValid() || rep.SucceededCount() != 1 || nodeStreamCalled.Load() != 1 {
		t.Fatalf("BatchExec 失配: rep=%+v err=%v factoryCalls=%d", rep, err, nodeStreamCalled.Load())
	}
	assertNoGetSnapshotAudit(t, "BatchExec", rig.auditClust.Entries()[auditBefore:])
	assertMCPBatchNoHiddenSnapshotAudit(t, ctx, rig)
}

func assertNoGetSnapshotAudit(t *testing.T, label string, entries []ports.AuditEntry) {
	t.Helper()
	for _, entry := range entries {
		if entry.Binding().Action() == "get_snapshot" {
			t.Fatalf("%s 触发了隐式 get_snapshot 幽灵审计: %+v", label, entry)
		}
	}
}

func assertMCPBatchNoHiddenSnapshotAudit(t *testing.T, ctx context.Context, rig *fullSimRig) {
	t.Helper()
	mcpSrv, err := rig.eng.NewMCPServer(engine.MCPConfig{
		TransferRoot: algebraic.Some(rig.transferRoot), ArtifactRoot: algebraic.Some(rig.artifactRoot),
	})
	if err != nil {
		t.Fatalf("NewMCPServer: %v", err)
	}
	if _, err := mcpSrv.Prepare(ctx); err != nil {
		t.Fatalf("MCPServer.Prepare: %v", err)
	}
	mcpAuditBefore := len(rig.auditClust.Entries())
	_, _, _ = mcpSrv.HandleMessage(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"t","version":"1"}}}`))
	resp, ok, err := mcpSrv.HandleMessage(ctx, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"terminal_exec","arguments":{"action":"batch_exec","targets":["web-01"],"command":"echo mcp"}}}`))
	if err != nil || !ok || strings.Contains(string(resp), `"isError":true`) || strings.Contains(string(resp), `"error"`) {
		t.Fatalf("HandleMessage(terminal_exec batch) 失败: ok=%v err=%v resp=%s", ok, err, string(resp))
	}
	assertNoGetSnapshotAudit(t, "MCP terminal_exec batch", rig.auditClust.Entries()[mcpAuditBefore:])
}

// TestEngine_G3Polish_M4FieldsAndProjectionLifecycle 验证 #118 M4：
// 遗漏请求字段透传、CheckSecretReferences/FindSecretReferences 与 Projection 纳入 Engine.Close 逆序关闭。
func TestEngine_G3Polish_M4FieldsAndProjectionLifecycle(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rig := newFullSimRig(t, engine.PolicyProfileDirectOperator, security.RiskDangerous, true)
	defer rig.close(t)

	// 1. CheckSecretReferences & FindSecretReferences & RotateSecretRequest(VerifyNewRef/ExtraPending)
	ref1, _ := secret.NewRef("vault", "m4-sec-1")
	ref2, _ := secret.NewRef("vault", "m4-sec-2")
	_ = secret.WithBytes([]byte("v1"), func(box *secret.SecretBox) error { return rig.vault.PutAndVerify(ctx, ref1, box) })
	idID, _ := inventory.ParseIdentityID("id-m4")
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthPassword(ref1)
	identObj, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idID, User: user, Auth: auth})
	if _, err := rig.eng.CreateIdentity(ctx, engine.IdentityMutationRequest{Identity: identObj}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	extraPin := []inventory.PendingSecretRef{{OwnerID: "enroll-pending-1", Ref: ref1}}
	invRefs, err := rig.eng.CheckSecretReferences(ctx, engine.SecretRefCheckRequest{Ref: ref1, ExtraPending: extraPin})
	if err != nil || len(invRefs) != 2 {
		t.Fatalf("CheckSecretReferences 失配: refs=%+v err=%v", invRefs, err)
	}
	credRefs, err := rig.eng.FindSecretReferences(ctx, engine.FindSecretReferencesRequest{Ref: ref1, ExtraPending: extraPin})
	if err != nil || len(credRefs) != 2 {
		t.Fatalf("FindSecretReferences 失配: refs=%+v err=%v", credRefs, err)
	}
	var verifiedCalled atomic.Bool
	if err := secret.WithBytes([]byte("v2"), func(box *secret.SecretBox) error {
		_, rErr := rig.eng.RotateSecret(ctx, engine.RotateSecretRequest{
			OldRef: ref1, NewRef: ref2, ExtraPending: extraPin,
			VerifyNewRef: func(_ context.Context, r secret.Ref) error {
				verifiedCalled.Store(r.Equal(ref2))
				return nil
			},
		}, box)
		return rErr
	}); err != nil || !verifiedCalled.Load() {
		t.Fatalf("RotateSecret(VerifyNewRef/ExtraPending) 失败: verified=%v err=%v", verifiedCalled.Load(), err)
	}

	// 2. Projection 纳入 Engine.Close 逆序关闭（无需手动 Close 仍 0 goleak），且关闭后 NewProjection 拒绝。
	proj, err := rig.eng.NewProjection(ctx, engine.ProjectionConfig{})
	if err != nil || proj == nil {
		t.Fatalf("NewProjection: %v", err)
	}
	_ = proj.Snapshot()
	rig.close(t)
	if _, err := rig.eng.NewProjection(ctx, engine.ProjectionConfig{}); !errors.Is(err, engine.ErrEngineClosed) {
		t.Fatalf("关闭后 NewProjection 期望 ErrEngineClosed，实际=%v", err)
	}
}

// muxClientSpy 包装 SimMuxSocket，用于实证 Engine 透明客户端 ControlMaster 复用、计数与 INV-C4 身份校验。
type muxClientSpy struct {
	inner         *sim.SimMuxSocket
	dialer        *fullFacadeDialer
	dialMuxCalls  atomic.Int32
	spoofEndpoint algebraic.Option[netaddr.Endpoint]
	spoofClosed   atomic.Bool
}

func (m *muxClientSpy) Probe(ctx context.Context, p pathalg.LocalSourcePath) (ports.MuxControlResponse, error) {
	return m.inner.Probe(ctx, p)
}
func (m *muxClientSpy) Control(ctx context.Context, r ports.MuxControlRequest) (ports.MuxControlResponse, error) {
	return m.inner.Control(ctx, r)
}
func (m *muxClientSpy) OpenProxy(ctx context.Context, p pathalg.LocalSourcePath) (net.Conn, error) {
	return m.inner.OpenProxy(ctx, p)
}
func (m *muxClientSpy) Serve(ctx context.Context, ln net.Listener, up ports.TransportConn, fwd ports.ForwarderPort) error {
	return m.inner.Serve(ctx, ln, up, fwd)
}

//xops:syncclosure
//xops:borrowed
func (m *muxClientSpy) WithListener(ctx context.Context, p pathalg.LocalSourcePath, fn func(net.Listener) error) error {
	return m.inner.WithListener(ctx, p, func(ln net.Listener) error { return fn(ln) })
}
func (m *muxClientSpy) DialMux(ctx context.Context, p pathalg.LocalSourcePath, dig plan.HopDigest, ep netaddr.Endpoint) (ports.TransportConn, error) {
	m.dialMuxCalls.Add(1)
	if spoof, ok := m.spoofEndpoint.Get(); ok {
		conn, err := m.inner.DialMux(ctx, p, dig, spoof)
		if err != nil {
			return nil, err
		}
		return &spoofCloseTrackerConn{TransportConn: conn, closed: &m.spoofClosed}, nil
	}
	conn, err := m.inner.DialMux(ctx, p, dig, ep)
	if err != nil {
		return nil, err
	}
	return &fullFacadeConn{TransportConn: conn, owner: m.dialer}, nil
}

type spoofCloseTrackerConn struct {
	ports.TransportConn
	closed *atomic.Bool
}

func (c *spoofCloseTrackerConn) Close() error {
	c.closed.Store(true)
	return c.TransportConn.Close()
}

type countingDialer struct {
	inner ports.DialerPort
	calls atomic.Int32
}

func (d *countingDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error) {
	d.calls.Add(1)
	return d.inner.DialHop(ctx, hop, dig, parent)
}

type confirmToggleInteraction struct {
	*sim.SimInteractionPort
	denyConfirm atomic.Bool
}

func (c *confirmToggleInteraction) Confirm(ctx context.Context, req ports.ConfirmRequest) (security.Verdict, error) {
	if c.denyConfirm.Load() {
		return security.VerdictDeny, nil
	}
	return c.SimInteractionPort.Confirm(ctx, req)
}

// TestEngine_G3Polish_TransparentMuxClientDialReuse 验证 #119 M1 / #118 m2：
// Engine 透明客户端 ControlMaster DialMux 复用（Exec/SFTP 实际复用活跃主进程、缺失回退、yes 不附着、autoask 确认与 INV-C4 伪造拒绝）。
func TestEngine_G3Polish_TransparentMuxClientDialReuse(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	clk, rng := sim.NewSimClock(sim.DefaultBaseTime()), sim.NewSeededRand(9901)
	cluster := sim.NewSimAuditCluster()
	sink, _ := cluster.NewSinkFromEntropy(rng.Fork())
	defer func() { _ = sink.Close() }()
	remoteFS := sim.NewSimRemoteFS(clk)
	srvDir, _ := pathalg.ParseRemotePath("/srv")
	_ = remoteFS.MkdirAll(ctx, srvDir, 0o755)
	innerSimDialer := sim.NewSimDialer(clk, rng.Fork())
	ffDialer := &fullFacadeDialer{inner: innerSimDialer, remoteFS: remoteFS}
	baseDial := &countingDialer{inner: ffDialer}
	simMux := sim.NewSimMuxSocket(innerSimDialer)
	muxSpy := &muxClientSpy{inner: simMux, dialer: ffDialer}
	interact := &confirmToggleInteraction{SimInteractionPort: sim.NewSimInteractionPort(true)}
	var zeroID ports.LocalIdentityInfo

	eng, err := engine.New(engine.Config{
		Profile: engine.PolicyProfileDirectOperator, Guardrail: engine.DefaultGuardrailConfig(),
		Clock: clk, Entropy: rng.Fork(), AuditSink: sink, Reconciler: cluster,
		Interaction: interact, ScopedFS: sim.NewSimScopedRootFS(clk), HostTrust: sim.NewSimHostTrust(),
		Env:       sim.NewSimEnvPort(map[string]string{"USER": "ops"}, zeroID),
		MuxSocket: muxSpy, Dialer: baseDial,
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	defer closeEngineChecked(t, eng)

	sockStr := "/tmp/xops-mux-reuse.sock"
	sockPath, _ := pathalg.ParseLocalSourcePath(sockStr)
	cpSpec, _ := option.ParseControlPath(sockStr)
	mkMuxCLI := func(cp option.ControlPathSpec, m option.ControlMasterMode) option.OptionLayer {
		return option.UnsetOptionLayer().WithControlPolicy(option.UnsetControlPolicy().WithPath(cp).WithMaster(m))
	}

	// 1. 活跃 ControlMaster + ControlMaster=auto：Exec 与 WriteRemoteFile/ReadRemoteFile 均走 DialMux（0 底层拨号）。
	simMux.RegisterMaster(sockPath, 4242)
	cliAuto := mkMuxCLI(cpSpec, option.ControlMasterAuto)
	var outBuf bytes.Buffer
	if _, err := eng.Exec(ctx, engine.ExecRequest{TargetSpec: "ops@10.50.0.1:22", CLIOptions: cliAuto, Command: "uname", Stdout: &outBuf}); err != nil {
		t.Fatalf("Exec(mux auto): %v", err)
	}
	fPath, _ := pathalg.ParseRemotePath("/srv/mux.txt")
	if _, err := eng.WriteRemoteFile(ctx, engine.RemoteFileWriteRequest{
		RemoteCall: engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "ops@10.50.0.1:22", CLIOptions: cliAuto}},
		Path:       fPath, Content: []byte("via-mux"),
	}); err != nil {
		t.Fatalf("WriteRemoteFile(mux auto): %v", err)
	}
	if muxSpy.dialMuxCalls.Load() < 1 || baseDial.calls.Load() != 0 {
		t.Fatalf("期望 Exec/SFTP 走 DialMux 且底层拨号=0，实际 muxCalls=%d baseCalls=%d", muxSpy.dialMuxCalls.Load(), baseDial.calls.Load())
	}

	// 2. 未注册的套接字路径：DialMux 返回 ErrMuxUnavailable 时透明回退底层拨号。
	absentCP, _ := option.ParseControlPath("/tmp/xops-mux-absent.sock")
	cliAbsent := mkMuxCLI(absentCP, option.ControlMasterAuto)
	if _, err := eng.Exec(ctx, engine.ExecRequest{TargetSpec: "ops@10.50.0.2:22", CLIOptions: cliAbsent, Command: "uname"}); err != nil {
		t.Fatalf("Exec(mux fallback): %v", err)
	}
	if baseDial.calls.Load() != 1 {
		t.Fatalf("无主进程时应透明回退底层拨号 1 次，实际=%d", baseDial.calls.Load())
	}

	// 3. ControlMaster=yes：不走客户端 DialMux 附着，直接走底层拨号。
	muxBefore := muxSpy.dialMuxCalls.Load()
	cliYes := mkMuxCLI(cpSpec, option.ControlMasterYes)
	if _, err := eng.Exec(ctx, engine.ExecRequest{TargetSpec: "ops@10.50.0.3:22", CLIOptions: cliYes, Command: "uname"}); err != nil {
		t.Fatalf("Exec(mux yes): %v", err)
	}
	if muxSpy.dialMuxCalls.Load() != muxBefore || baseDial.calls.Load() != 2 {
		t.Fatalf("ControlMaster=yes 不应走客户端 DialMux 附着: muxBefore=%d muxAfter=%d base=%d", muxBefore, muxSpy.dialMuxCalls.Load(), baseDial.calls.Load())
	}

	// 4. ControlMaster=autoask 拒绝确认：失败关闭且不回退底层拨号。
	interact.denyConfirm.Store(true)
	cliAutoAsk := mkMuxCLI(cpSpec, option.ControlMasterAutoAsk)
	if _, err := eng.Exec(ctx, engine.ExecRequest{TargetSpec: "ops@10.50.0.4:22", CLIOptions: cliAutoAsk, Command: "uname"}); !errors.Is(err, engine.ErrMuxUnavailable) {
		t.Fatalf("autoask 拒绝期望 ErrMuxUnavailable，实际=%v", err)
	}
	if baseDial.calls.Load() != 2 {
		t.Fatalf("autoask 拒绝后不得回退底层拨号: base=%d", baseDial.calls.Load())
	}

	// 5. INV-C4：DialMux 返回伪造 Endpoint 的连接必须失败关闭并立即关闭该伪造连接。
	fakeEP, _ := netaddr.ParseEndpoint("192.0.2.99:22")
	muxSpy.spoofEndpoint = algebraic.Some(fakeEP)
	if _, err := eng.Exec(ctx, engine.ExecRequest{TargetSpec: "ops@10.50.0.5:22", CLIOptions: cliAuto, Command: "uname"}); !errors.Is(err, engine.ErrMuxUnavailable) || !muxSpy.spoofClosed.Load() {
		t.Fatalf("伪造 Endpoint 必须失败关闭并关闭连接: err=%v closed=%v", err, muxSpy.spoofClosed.Load())
	}
}

// TestEngine_G3Polish_PendingEnrollmentRealProbeAndCommit 验证 #119 M2 / INV-F2：
// 未落盘暂存目标计划解析 + 真实进程内 SSH 服务端公钥指纹零伪造探测提交闭环 + 未知主机键失败关闭回滚。
func TestEngine_G3Polish_PendingEnrollmentRealProbeAndCommit(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()
	rig := newLoopbackRigBase(t, false)
	clientPub, keyPath := writeTestKeyInRoot(t, rig.rootFS, rig.sshDir, "id_ed25519")
	srv := newLoopbackSSHServer(t, clientPub)
	wantFP, err := inventory.ParseKeyFingerprint(ssh.FingerprintSHA256(srv.hostSigner.PublicKey()))
	if err != nil {
		t.Fatalf("ParseKeyFingerprint: %v", err)
	}

	var emptyGraph inventory.Graph
	invStore, _ := sim.NewSimInventoryStore(emptyGraph)
	vault := sim.NewSimVault(rig.rng.Fork())
	eng, err := engine.New(engine.Config{
		Profile: engine.PolicyProfileDirectOperator, Guardrail: engine.DefaultGuardrailConfig(),
		Clock: rig.clk, Entropy: rig.rng.Fork(), AuditSink: rig.auditSink, Reconciler: rig.cluster,
		ScopedFS: rig.rootFS, OperatorReadFS: rig.readFS, Env: rig.env, Terminal: rig.term,
		Vault: vault, VaultControl: vault, InventoryStore: invStore, KnownStores: []string{"vault"},
		DialContext: srv.dialFunc(),
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	defer closeEngineChecked(t, eng)

	hID, _ := inventory.ParseHostID("lb-host-1")
	ep, _ := netaddr.ParseEndpoint("127.0.0.1:22091")
	hostObj, _ := inventory.NewHost(inventory.HostSpec{ID: hID, Endpoint: ep})
	idID, _ := inventory.ParseIdentityID("lb-id-1")
	user, _ := option.ParseUsername("deploy")
	kpSpec, _ := inventory.ParseKeyPathSpec(keyPath)
	auth, _ := inventory.NewAuthPrivateKey(algebraic.NewNonEmpty(kpSpec), algebraic.None[inventory.KeyPassphraseBinding](), nil)
	identObj, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: idID, User: user, Auth: auth})
	nID, _ := inventory.ParseNodeID("lb-node-1")
	nodeObj, _ := inventory.NewNode(inventory.NodeSpec{ID: nID, HostRef: hID, IdentityRef: idID, Origin: inventory.NewOriginManaged()})

	// 1. 失败路径：StrictHostKeyChecking=yes 遇未知主机键 -> ErrHostKeyUnknown，暂存不落盘且钉住凭据自动回收。
	pinRef, _ := secret.NewRef("vault", "pending-pin-1")
	_ = secret.WithBytes([]byte("temp-secret"), func(box *secret.SecretBox) error { return vault.PutAndVerify(ctx, pinRef, box) })
	cliStrict := option.UnsetOptionLayer().WithIdentitiesOnly(true).WithStrictHostKeyChecking(option.StrictHostKeyCheckingYes)
	abortedRes, abortErr := eng.WithPendingEnrollment(ctx, engine.PendingEnrollmentRequest{
		Host: algebraic.Some(hostObj), Identity: algebraic.Some(identObj), Node: nodeObj, PinnedRefs: []secret.Ref{pinRef},
	}, func(lCtx context.Context, lease *engine.PendingEnrollmentLease) error {
		_, pErr := lease.Probe(lCtx, func(pCtx context.Context) (inventory.KeyFingerprint, error) {
			return eng.ProbePendingEnrollmentTarget(pCtx, lease, engine.ProbePendingEnrollmentRequest{CLIOptions: cliStrict})
		})
		return pErr
	})
	if !errors.Is(abortErr, engine.ErrHostKeyUnknown) || !errors.Is(abortErr, ports.ErrHostKeyUnknown) || abortedRes.Phase() != fsm.PendingEnrollPhaseAborted {
		t.Fatalf("未知主机键期望 ErrHostKeyUnknown + Aborted，实际 phase=%v err=%v", abortedRes.Phase(), abortErr)
	}
	if _, _, gErr := eng.GetNode(ctx, nID, engine.InventoryQueryRequest{}); !errors.Is(gErr, engine.ErrNotFound) {
		t.Fatalf("探测失败后未落盘节点不得出现在存储中: err=%v", gErr)
	}

	// 2. 成功路径：StrictHostKeyChecking=accept-new -> 解析未落盘计划 + 真实握手返回服务端 Ed25519 指纹 -> Commit 入库。
	assertPendingEnrollmentProbeAndCommitSuccess(t, ctx, eng, hostObj, identObj, nodeObj, wantFP)
}

func assertPendingEnrollmentProbeAndCommitSuccess(
	t *testing.T, ctx context.Context, eng *engine.Engine,
	hostObj inventory.Host, identObj inventory.Identity, nodeObj inventory.Node, wantFP inventory.KeyFingerprint,
) {
	t.Helper()
	cliAccept := option.UnsetOptionLayer().WithIdentitiesOnly(true).WithStrictHostKeyChecking(option.StrictHostKeyCheckingAcceptNew)
	okRes, okErr := eng.WithPendingEnrollment(ctx, engine.PendingEnrollmentRequest{
		Host: algebraic.Some(hostObj), Identity: algebraic.Some(identObj), Node: nodeObj,
	}, func(lCtx context.Context, lease *engine.PendingEnrollmentLease) error {
		resolved, rErr := eng.ResolvePendingEnrollmentTarget(lCtx, lease, cliAccept)
		if rErr != nil || !resolved.IsValid() || resolved.NodeID() != "lb-node-1" {
			t.Fatalf("ResolvePendingEnrollmentTarget 失配: res=%+v err=%v", resolved, rErr)
		}
		fp, pErr := lease.Probe(lCtx, func(pCtx context.Context) (inventory.KeyFingerprint, error) {
			return eng.ProbePendingEnrollmentTarget(pCtx, lease, engine.ProbePendingEnrollmentRequest{CLIOptions: cliAccept})
		})
		if pErr != nil || !fp.Equal(wantFP) {
			t.Fatalf("真实探测指纹失配: got=%v want=%v err=%v", fp, wantFP, pErr)
		}
		_, cErr := lease.Commit(lCtx)
		return cErr
	})
	if okErr != nil || okRes.Phase() != fsm.PendingEnrollPhaseEnrolled {
		t.Fatalf("首连探测提交闭环失败: phase=%v err=%v", okRes.Phase(), okErr)
	}
	if gotFP, hasFP := okRes.HostKeyFingerprint().Get(); !hasFP || !gotFP.Equal(wantFP) {
		t.Fatalf("PendingEnrollmentResult 指纹与真实服务端不一致: got=%v want=%v", gotFP, wantFP)
	}
	if gotNode, _, gErr := eng.GetNode(ctx, nodeObj.ID(), engine.InventoryQueryRequest{}); gErr != nil || gotNode.ID() != nodeObj.ID() {
		t.Fatalf("Commit 后应成功查询已入库节点: err=%v", gErr)
	}
}

// TestEngine_G3Polish_RecoverAllGatedCanSuspendSharedMCPAndRecursiveSCP 验证：
// #119 Minor-1 (RecoverAllTransfers 门控)、Minor-2 (CanSuspendProcessGroup)、#118 m3 (共享活跃句柄视图) 与 #119 M3 (递归 SCPUpload)。
func TestEngine_G3Polish_RecoverAllGatedCanSuspendSharedMCPAndRecursiveSCP(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx := context.Background()

	// 1. CanSuspendProcessGroup 失败关闭与正常委托
	var zeroEng engine.Engine
	if v, err := zeroEng.CanSuspendProcessGroup(); v != security.VerdictDeny || !errors.Is(err, engine.ErrEngineNotInitialized) {
		t.Fatalf("零值 CanSuspendProcessGroup 必须失败关闭: v=%v err=%v", v, err)
	}
	rig := newFullSimRig(t, engine.PolicyProfileStrictOperator, security.RiskModerate, true)
	defer rig.close(t)
	if v, err := rig.eng.CanSuspendProcessGroup(); v != security.VerdictDeny || !errors.Is(err, engine.ErrUnsupported) {
		t.Fatalf("未注入 TerminalPort 时 CanSuspendProcessGroup 必须失败关闭: v=%v err=%v", v, err)
	}

	// 2. RecoverAllTransfers 门控：PruneSuperseded=false(RiskSafe) 直接放行；PruneSuperseded=true(RiskModerate) 在不可交互 Challenge 下返回 ErrApprovalRequired。
	if _, err := rig.eng.RecoverAllTransfers(ctx, engine.RecoverAllTransfersRequest{PruneSuperseded: false}); err != nil {
		t.Fatalf("RecoverAllTransfers(Prune=false) 失败: %v", err)
	}
	// 创建不可交互严格 Engine 测试 PruneSuperseded=true 审批挑战闭环。
	strictNoInteract := newNoInteractStrictEngine(t, rig)
	defer closeEngineChecked(t, strictNoInteract)
	_, challengeErr := strictNoInteract.RecoverAllTransfers(ctx, engine.RecoverAllTransfersRequest{PruneSuperseded: true})
	if !errors.Is(challengeErr, engine.ErrApprovalRequired) || !errors.Is(challengeErr, gate.ErrApprovalRequired) {
		t.Fatalf("RecoverAllTransfers(Prune=true) 期望 ErrApprovalRequired，实际=%v", challengeErr)
	}
	ch, ok := engine.ExtractApprovalChallenge(challengeErr)
	if !ok || !ch.IsValid() {
		t.Fatalf("ExtractApprovalChallenge 失败: ok=%v", ok)
	}
	sub, err := engine.NewApprovalSubmission(security.VerdictAllow, ch.EnvelopeDigest(), algebraic.Some(ch.Envelope()), "approve prune")
	if err != nil {
		t.Fatalf("NewApprovalSubmission: %v", err)
	}
	if _, err := strictNoInteract.RecoverAllTransfers(ctx, engine.RecoverAllTransfersRequest{
		PruneSuperseded: true, Approval: algebraic.Some(sub),
	}); err != nil {
		t.Fatalf("带有效审批的 RecoverAllTransfers(Prune=true) 失败: %v", err)
	}

	// 3. #118 m3：MCPServer 启动流式传输后，同进程 Engine.InspectTransfer 立即看到 LiveHandle=true。
	assertSharedMCPTransferVisibility(t, ctx, rig)

	// 4. #119 M3：Engine.SCPUpload 经 ScopedRootFS 执行递归目录上传端到端。
	assertEngineRecursiveSCPUpload(t, ctx, rig)
}

func newNoInteractStrictEngine(t *testing.T, rig *fullSimRig) *engine.Engine {
	t.Helper()
	gCfg := engine.DefaultGuardrailConfig()
	gCfg.ApprovalThreshold = security.RiskModerate
	gCfg.NoElicitFallback = engine.NoElicitFallbackChallenge
	var zeroID ports.LocalIdentityInfo
	eng, err := engine.New(engine.Config{
		Profile: engine.PolicyProfileStrictAgent, Guardrail: gCfg,
		Clock: rig.clk, Entropy: rig.rng.Fork(), AuditSink: rig.auditSink, Reconciler: rig.auditClust,
		Interaction: sim.NewSimInteractionPort(false), ScopedFS: rig.scopedFS, HostTrust: sim.NewSimHostTrust(),
		Env: sim.NewSimEnvPort(map[string]string{"USER": "ops"}, zeroID), Terminal: sim.NewSimTerminalPort(true, 80, 24),
		JournalStore: rig.journalStore, Dialer: rig.dialer,
	})
	if err != nil {
		t.Fatalf("engine.New(strict): %v", err)
	}
	if v, err := eng.CanSuspendProcessGroup(); err != nil || !v.Allowed() {
		t.Fatalf("注入 TerminalPort 后 CanSuspendProcessGroup 期望 Allow: v=%v err=%v", v, err)
	}
	return eng
}

func assertSharedMCPTransferVisibility(t *testing.T, ctx context.Context, rig *fullSimRig) {
	t.Helper()
	mcpSrv, err := rig.eng.NewMCPServer(engine.MCPConfig{
		TransferRoot: algebraic.Some(rig.transferRoot), ArtifactRoot: algebraic.Some(rig.artifactRoot),
	})
	if err != nil {
		t.Fatalf("NewMCPServer: %v", err)
	}
	if _, err := mcpSrv.Prepare(ctx); err != nil {
		t.Fatalf("MCPServer.Prepare: %v", err)
	}
	_, _, _ = mcpSrv.HandleMessage(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"t","version":"1"}}}`))
	rawResp, ok, err := mcpSrv.HandleMessage(ctx, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"transfer","arguments":{"action":"start","target":"ops@10.60.0.1:22","direction":"upload","remote_path":"/srv/shared-stream.bin","total_bytes":5}}}`))
	if err != nil || !ok {
		t.Fatalf("MCP transfer(start) 失败: ok=%v err=%v", ok, err)
	}
	var rpcResp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := jsonv2.Unmarshal(rawResp, &rpcResp); err != nil || len(rpcResp.Result.Content) == 0 {
		t.Fatalf("解析 MCP 响应失败: %s err=%v", string(rawResp), err)
	}
	var payload struct {
		TransferID string `json:"transfer_id"`
	}
	if err := jsonv2.Unmarshal([]byte(rpcResp.Result.Content[0].Text), &payload); err != nil || payload.TransferID == "" {
		t.Fatalf("解析 transfer_id 失败: %s err=%v", rpcResp.Result.Content[0].Text, err)
	}
	tid, err := security.ParseOperationID(payload.TransferID)
	if err != nil {
		t.Fatalf("ParseOperationID: %v", err)
	}
	snap, err := rig.eng.InspectTransfer(ctx, engine.InspectTransferRequest{
		RemoteCall: engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "ops@10.60.0.1:22"}},
		TransferID: tid,
	})
	if err != nil || !snap.LiveHandle || snap.StateKind != fsm.TransferKindStreaming {
		t.Fatalf("Engine.InspectTransfer 应观测到同进程 MCP 活跃句柄 LiveHandle=true: snap=%+v err=%v", snap, err)
	}
	// #119 Nit-1：验证 HTTP 流式上传端点对畸形 X-Xops-Start-Offset / X-Xops-Approval 头的错误消息经 SanitizeErrorMessage 清洗。
	assertHTTPTransferHeadersSanitized(t, mcpSrv.Handler(), tid.String())
}

func assertHTTPTransferHeadersSanitized(t *testing.T, h http.Handler, tid string) {
	t.Helper()
	initReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"t","version":"1"}}}`))
	initReq.Header.Set("Content-Type", "application/json")
	initReq.Header.Set("Origin", "http://127.0.0.1")
	initRec := httptest.NewRecorder()
	h.ServeHTTP(initRec, initReq)
	sid := initRec.Header().Get("Mcp-Session-Id")
	if initRec.Code != http.StatusOK || sid == "" {
		t.Fatalf("HTTP initialize 失败: code=%d sid=%q", initRec.Code, sid)
	}
	for _, tc := range []struct{ hdr, val, wantCode string }{
		{"X-Xops-Start-Offset", "bad\x1b[31m-" + strings.Repeat("x", 2048), "invalid_offset"},
		{"X-Xops-Approval", `{"verdict":"bad\u001b[31m-` + strings.Repeat("y", 2048) + `"}`, "invalid_approval"},
	} {
		req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1/transfers/"+tid+"/stream", strings.NewReader("hello"))
		req.Header.Set("Mcp-Session-Id", sid)
		req.Header.Set(tc.hdr, tc.val)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var errBody struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if rec.Code != http.StatusBadRequest || jsonv2.Unmarshal(rec.Body.Bytes(), &errBody) != nil || errBody.Code != tc.wantCode || strings.ContainsRune(errBody.Message, '\x1b') || len(errBody.Message) > 1050 {
			t.Fatalf("%s 畸形头错误清洗失配: status=%d body=%s", tc.hdr, rec.Code, rec.Body.String())
		}
	}
}

func assertEngineRecursiveSCPUpload(t *testing.T, ctx context.Context, rig *fullSimRig) {
	t.Helper()
	mtime := time.Date(2025, time.November, 1, 8, 30, 0, 0, time.UTC)
	if err := rig.scopedFS.WithRoot(rig.transferRoot, func(root ports.RootHandle) error {
		d1, _ := pathalg.ParseLocalRootedDest("bundle/sub")
		f1, _ := pathalg.ParseLocalRootedDest("bundle/sub/hello.txt")
		if err := root.MkdirAll(d1, 0o755); err != nil {
			return err
		}
		if _, err := root.WriteChunk(f1, 0, strings.NewReader("hello-recursive"), 15, 0o640); err != nil {
			return err
		}
		return root.Chtimes(f1, mtime, mtime)
	}); err != nil {
		t.Fatalf("准备本地递归目录失败: %v", err)
	}
	srcRel, _ := pathalg.ParseLocalRootedDest("bundle")
	src, err := engine.NewScopedUploadSource(rig.transferRoot, srcRel)
	if err != nil {
		t.Fatalf("NewScopedUploadSource: %v", err)
	}
	dst, _ := pathalg.ParseRemotePath("/srv")
	upRes, err := rig.eng.SCPUpload(ctx, engine.SCPUploadRequest{
		RemoteCall:    engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "ops@10.60.0.1:22"}},
		Source:        src,
		RemoteDest:    dst,
		Recursive:     true,
		ExpandIntoDir: true,
		PreserveMode:  true,
		PreserveTimes: true,
		SymlinkPolicy: pathalg.SymlinkReject,
	})
	if err != nil || upRes.FilesUploaded != 1 || upRes.DirsCreated != 2 || upRes.RemotePath.String() != "/srv/bundle" {
		t.Fatalf("Engine.SCPUpload(Recursive=true) 结果失配: res=%+v err=%v", upRes, err)
	}
	rp, _ := pathalg.ParseRemotePath("/srv/bundle/sub/hello.txt")
	readRes, err := rig.eng.ReadRemoteFile(ctx, engine.RemoteFileReadRequest{
		RemoteCall: engine.RemoteCall{TargetInput: engine.TargetInput{TargetSpec: "ops@10.60.0.1:22"}},
		Path:       rp,
	})
	if err != nil || string(readRes.Content) != "hello-recursive" {
		t.Fatalf("校验远端递归上传文件失配: content=%q err=%v", string(readRes.Content), err)
	}
}
