package ports_test

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

type singleUnwrapper interface {
	error
	Unwrap() error
}

// TestCompileTimeInterfaceContracts 验证 core/ports 全部导出接口与编解码值对象在外部包视角满足预期契约。
func TestCompileTimeInterfaceContracts(t *testing.T) {
	var (
		rev   ports.Revision
		dur   ports.DurabilityOutcome
		vh    ports.OpenSSHVirtualHost
		lm    ports.LockMode
		lim   ports.ReadLimits
		pk    ports.PublicKeyInfo
		hts   ports.HostTrustStatus
		htc   ports.HostTrustCheck
		pty   ports.PTYRequest
		fdir  ports.ForwardDirection
		fspec ports.ForwardSpec
		mact  ports.MuxControlAction
		mresp ports.MuxControlResponse
		rft   ports.RemoteFileType
		ranc  ports.RemoteFileAnchor
		rstat ports.RemoteFileStat
		rde   ports.RemoteDirEntry
		rwsp  ports.RemoteWriteSpec
		pid   ports.ProcessInstanceID
		aph   ports.AuditPhase
		aout  ports.AuditOutcome
		aent  ports.AuditEntry
		crep  ports.CrashReconcileReport
		pspec ports.ProcessSpec
		tsize ports.TerminalSize
		sreq  ports.SecretPromptRequest
		creq  ports.ConfirmRequest
		treq  ports.TextPromptRequest
		aresp ports.ApprovalDecisionResponse
		ent   ports.Entropy
		apwe  *ports.AuditPostWriteError
	)
	var (
		_ io.Reader                = ent
		_ singleUnwrapper          = apwe
		_ encoding.TextAppender    = rev
		_ encoding.TextMarshaler   = rev
		_ encoding.TextUnmarshaler = &rev
		_ encoding.TextAppender    = lm
		_ encoding.TextMarshaler   = lm
		_ encoding.TextUnmarshaler = &lm
		_ encoding.TextAppender    = hts
		_ encoding.TextMarshaler   = hts
		_ encoding.TextUnmarshaler = &hts
		_ encoding.TextAppender    = fdir
		_ encoding.TextMarshaler   = fdir
		_ encoding.TextUnmarshaler = &fdir
		_ encoding.TextAppender    = mact
		_ encoding.TextMarshaler   = mact
		_ encoding.TextUnmarshaler = &mact
		_ encoding.TextAppender    = rft
		_ encoding.TextMarshaler   = rft
		_ encoding.TextUnmarshaler = &rft
		_ encoding.TextAppender    = pid
		_ encoding.TextMarshaler   = pid
		_ encoding.TextUnmarshaler = &pid
		_ encoding.TextAppender    = aph
		_ encoding.TextMarshaler   = aph
		_ encoding.TextUnmarshaler = &aph
		_ encoding.TextAppender    = aout
		_ encoding.TextMarshaler   = aout
		_ encoding.TextUnmarshaler = &aout
		_ jsonv2.MarshalerTo       = dur
		_ jsonv2.UnmarshalerFrom   = &dur
		_ jsonv2.MarshalerTo       = vh
		_ jsonv2.UnmarshalerFrom   = &vh
		_ jsonv2.MarshalerTo       = lim
		_ jsonv2.UnmarshalerFrom   = &lim
		_ jsonv2.MarshalerTo       = pk
		_ jsonv2.UnmarshalerFrom   = &pk
		_ jsonv2.MarshalerTo       = htc
		_ jsonv2.UnmarshalerFrom   = &htc
		_ jsonv2.MarshalerTo       = pty
		_ jsonv2.UnmarshalerFrom   = &pty
		_ jsonv2.MarshalerTo       = fspec
		_ jsonv2.UnmarshalerFrom   = &fspec
		_ jsonv2.MarshalerTo       = mresp
		_ jsonv2.UnmarshalerFrom   = &mresp
		_ jsonv2.MarshalerTo       = ranc
		_ jsonv2.UnmarshalerFrom   = &ranc
		_ jsonv2.MarshalerTo       = rstat
		_ jsonv2.UnmarshalerFrom   = &rstat
		_ jsonv2.MarshalerTo       = rde
		_ jsonv2.UnmarshalerFrom   = &rde
		_ jsonv2.MarshalerTo       = rwsp
		_ jsonv2.UnmarshalerFrom   = &rwsp
		_ jsonv2.MarshalerTo       = aent
		_ jsonv2.UnmarshalerFrom   = &aent
		_ jsonv2.MarshalerTo       = crep
		_ jsonv2.UnmarshalerFrom   = &crep
		_ jsonv2.MarshalerTo       = pspec
		_ jsonv2.UnmarshalerFrom   = &pspec
		_ jsonv2.MarshalerTo       = tsize
		_ jsonv2.UnmarshalerFrom   = &tsize
		_ jsonv2.MarshalerTo       = sreq
		_ jsonv2.UnmarshalerFrom   = &sreq
		_ jsonv2.MarshalerTo       = creq
		_ jsonv2.UnmarshalerFrom   = &creq
		_ jsonv2.MarshalerTo       = treq
		_ jsonv2.UnmarshalerFrom   = &treq
		_ jsonv2.MarshalerTo       = aresp
		_ jsonv2.UnmarshalerFrom   = &aresp
	)
}

func assertZeroInvalid[T interface{ IsValid() bool }](t *testing.T, name string, zero T) {
	t.Helper()
	if zero.IsValid() {
		t.Errorf("零值 %s.IsValid() 必须返回 false", name)
	}
}

func assertZeroEqFalse[T interface {
	IsValid() bool
	Equal(T) bool
}](t *testing.T, name string, zero T) {
	t.Helper()
	if zero.IsValid() || zero.Equal(zero) {
		t.Errorf("零值 %s 未满足失败关闭与 Equal==false 不变量", name)
	}
}

func TestZeroValuesFailClosed(t *testing.T) {
	var (
		rev   ports.Revision
		snap  ports.InventorySnapshot
		dur   ports.DurabilityOutcome
		vh    ports.OpenSSHVirtualHost
		lm    ports.LockMode
		lim   ports.ReadLimits
		fi    ports.LocalFileInfo
		de    ports.LocalDirEntry
		pk    ports.PublicKeyInfo
		sig   ports.Signature
		hts   ports.HostTrustStatus
		htr   ports.HostTrustRequest
		htc   ports.HostTrustCheck
		pty   ports.PTYRequest
		fdir  ports.ForwardDirection
		fspec ports.ForwardSpec
		mact  ports.MuxControlAction
		mreq  ports.MuxControlRequest
		mresp ports.MuxControlResponse
		rft   ports.RemoteFileType
		ranc  ports.RemoteFileAnchor
		rstat ports.RemoteFileStat
		rde   ports.RemoteDirEntry
		rwsp  ports.RemoteWriteSpec
		pid   ports.ProcessInstanceID
		aph   ports.AuditPhase
		aout  ports.AuditOutcome
		aent  ports.AuditEntry
		crep  ports.CrashReconcileReport
		pspec ports.ProcessSpec
		pres  ports.ProcessResult
		tsize ports.TerminalSize
		sreq  ports.SecretPromptRequest
		creq  ports.ConfirmRequest
		treq  ports.TextPromptRequest
		aresp ports.ApprovalDecisionResponse
	)
	assertZeroEqFalse(t, "Revision", rev)
	assertZeroInvalid(t, "InventorySnapshot", snap)
	assertZeroEqFalse(t, "DurabilityOutcome", dur)
	assertZeroEqFalse(t, "OpenSSHVirtualHost", vh)
	assertZeroInvalid(t, "LockMode", lm)
	assertZeroEqFalse(t, "ReadLimits", lim)
	assertZeroEqFalse(t, "LocalFileInfo", fi)
	assertZeroEqFalse(t, "LocalDirEntry", de)
	assertZeroEqFalse(t, "PublicKeyInfo", pk)
	assertZeroEqFalse(t, "Signature", sig)
	assertZeroInvalid(t, "HostTrustStatus", hts)
	assertZeroInvalid(t, "HostTrustRequest", htr)
	assertZeroEqFalse(t, "HostTrustCheck", htc)
	assertZeroEqFalse(t, "PTYRequest", pty)
	assertZeroInvalid(t, "ForwardDirection", fdir)
	assertZeroEqFalse(t, "ForwardSpec", fspec)
	assertZeroInvalid(t, "MuxControlAction", mact)
	assertZeroInvalid(t, "MuxControlRequest", mreq)
	assertZeroEqFalse(t, "MuxControlResponse", mresp)
	assertZeroInvalid(t, "RemoteFileType", rft)
	assertZeroEqFalse(t, "RemoteFileAnchor", ranc)
	assertZeroEqFalse(t, "RemoteFileStat", rstat)
	assertZeroEqFalse(t, "RemoteDirEntry", rde)
	assertZeroEqFalse(t, "RemoteWriteSpec", rwsp)
	assertZeroEqFalse(t, "ProcessInstanceID", pid)
	assertZeroInvalid(t, "AuditPhase", aph)
	assertZeroInvalid(t, "AuditOutcome", aout)
	assertZeroEqFalse(t, "AuditEntry", aent)
	assertZeroEqFalse(t, "CrashReconcileReport", crep)
	assertZeroEqFalse(t, "ProcessSpec", pspec)
	assertZeroEqFalse(t, "ProcessResult", pres)
	assertZeroEqFalse(t, "TerminalSize", tsize)
	assertZeroEqFalse(t, "SecretPromptRequest", sreq)
	assertZeroEqFalse(t, "ConfirmRequest", creq)
	assertZeroEqFalse(t, "TextPromptRequest", treq)
	assertZeroEqFalse(t, "ApprovalDecisionResponse", aresp)
	if dur.Applied() || dur.Durable() || htc.IsTrusted() || mresp.Alive() ||
		ranc.Matches(ranc) || pres.Succeeded() || creq.Risk() != security.RiskUnknown ||
		aresp.Approved() || aresp.Verdict() != security.VerdictDeny {
		t.Fatal("零值安全谓词必须严格失败关闭")
	}
}

func TestDurabilityAndAnchorInvariants(t *testing.T) {
	rev, err := ports.ParseRevision("rev-001")
	if err != nil {
		t.Fatalf("ParseRevision 失败: %v", err)
	}
	committed, err := ports.NewDurabilityCommitted(rev)
	if err != nil || !committed.Applied() || !committed.Durable() || committed.Status() != fsm.DurabilityCommitted {
		t.Fatalf("Committed 构造异常: (%v, %v)", committed, err)
	}
	appliedOnly, err := ports.NewDurabilityAppliedNotDurable(algebraic.Some(rev), "fsync failed")
	if err != nil || !appliedOnly.Applied() || appliedOnly.Durable() || appliedOnly.Status() != fsm.DurabilityAppliedNotDurable {
		t.Fatalf("AppliedNotDurable 构造异常: (%v, %v)", appliedOnly, err)
	}
	notApplied, err := ports.NewDurabilityNotApplied("cas conflict")
	if err != nil || notApplied.Applied() || notApplied.Durable() || notApplied.Status() != fsm.DurabilityNotApplied {
		t.Fatalf("NotApplied 构造异常: (%v, %v)", notApplied, err)
	}
	unknown, err := ports.NewDurabilityOutcomeUnknown("io timeout")
	if err != nil || unknown.Applied() || unknown.Durable() || unknown.Status() != fsm.DurabilityOutcomeUnknown {
		t.Fatalf("OutcomeUnknown 构造异常: (%v, %v)", unknown, err)
	}

	// 验证 ADR-016 RemoteFileAnchor 匹配规则：含 (dev, ino) 必须精确一致，类型变更必拒。
	a1, err := ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, 10, 200)
	if err != nil {
		t.Fatalf("NewRemoteFileAnchor 失败: %v", err)
	}
	aSame, _ := ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, 10, 200)
	aDiffIno, _ := ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, 10, 201)
	aNoIno, _ := ports.NewRemoteFileAnchor(ports.RemoteFileRegular, false, 0, 0)
	aDir, _ := ports.NewRemoteFileAnchor(ports.RemoteFileDir, true, 10, 200)
	if !a1.Matches(aSame) || a1.Matches(aDiffIno) || a1.Matches(aNoIno) || a1.Matches(aDir) {
		t.Fatal("RemoteFileAnchor.Matches 未严格校验类型与 (dev, ino)")
	}
	if !aNoIno.Matches(a1) || aNoIno.Matches(aDir) {
		t.Fatal("无 (dev, ino) 的类型锚点应仅放行同类型对象")
	}
}

func TestProcessInstanceIDAndAuditPostWriteError(t *testing.T) {
	pid, err := ports.NewProcessInstanceIDFrom(bytes.NewReader([]byte("0123456789abcdef")))
	if err != nil || !pid.IsValid() {
		t.Fatalf("NewProcessInstanceIDFrom 失败: (%v, %v)", pid, err)
	}
	lockName, err := pid.LockFileName()
	if err != nil || !lockName.IsValid() || lockName.String() != pid.String()+".lock" {
		t.Fatalf("LockFileName 异常: (%v, %v)", lockName, err)
	}
	if _, err := ports.NewProcessInstanceIDFrom(nil); !errors.Is(err, ports.ErrInvalidProcessInstanceID) {
		t.Fatalf("nil entropy 应返回 ErrInvalidProcessInstanceID，实际: %v", err)
	}
	if _, err := ports.NewProcessInstanceIDFrom(bytes.NewReader([]byte("short"))); !errors.Is(err, ports.ErrEntropyShortRead) || !errors.Is(err, ports.ErrInvalidProcessInstanceID) {
		t.Fatalf("短读熵源应同时匹配 ErrEntropyShortRead 与 ErrInvalidProcessInstanceID，实际: %v", err)
	}
	if _, err := ports.NewProcessInstanceIDFrom(bytes.NewReader(make([]byte, 16))); !errors.Is(err, ports.ErrInvalidProcessInstanceID) {
		t.Fatalf("全零 16 字节熵源必须拒绝，实际: %v", err)
	}
	if _, err := ports.ParseProcessInstanceID("CON"); !errors.Is(err, ports.ErrInvalidProcessInstanceID) {
		t.Fatalf("Windows 保留设备名 CON 必须拒绝，实际: %v", err)
	}
}

func TestAuditPostWriteErrorContract(t *testing.T) {
	opID, err := security.ParseOperationID("op-audit-postwrite-1")
	if err != nil {
		t.Fatalf("ParseOperationID 失败: %v", err)
	}
	diskFull := errors.New("ENOSPC")
	pwErr, err := ports.NewAuditPostWriteError(opID, diskFull)
	if err != nil || !pwErr.IsValid() || !pwErr.OperationID().Equal(opID) || !errors.Is(pwErr.Unwrap(), diskFull) {
		t.Fatalf("NewAuditPostWriteError 异常: (%v, %v)", pwErr, err)
	}
	if !strings.Contains(pwErr.Error(), opID.String()) || !strings.Contains(pwErr.Error(), "ENOSPC") {
		t.Fatalf("AuditPostWriteError.Error() 缺少 opID 或根因: %s", pwErr.Error())
	}
	if !errors.Is(pwErr, ports.ErrAuditPostWrite) || !errors.Is(pwErr, diskFull) {
		t.Fatalf("AuditPostWriteError 必须同时匹配 ErrAuditPostWrite 与底层根因: %v", pwErr)
	}
	if got, ok := errors.AsType[*ports.AuditPostWriteError](pwErr); !ok || !got.OperationID().Equal(opID) {
		t.Fatalf("errors.AsType[*ports.AuditPostWriteError] 失败")
	}
}

func TestAuditPostWriteErrorInvalidGuards(t *testing.T) {
	// 验证 typed-nil 与未初始化零值 *AuditPostWriteError 全部方法零 panic 且严格失败关闭。
	var typedNil *ports.AuditPostWriteError
	var zeroStruct ports.AuditPostWriteError
	for _, bad := range []*ports.AuditPostWriteError{typedNil, &zeroStruct} {
		if bad.IsValid() || !bad.OperationID().IsZero() || bad.Unwrap() != nil || bad.Error() != ports.ErrAuditPostWrite.Error() {
			t.Fatalf("无效 *AuditPostWriteError 访问器行为异常: valid=%v err=%q unwrap=%v", bad.IsValid(), bad.Error(), bad.Unwrap())
		}
		if bad.Is(ports.ErrAuditPostWrite) || errors.Is(bad, ports.ErrAuditPostWrite) || errors.Is(bad, io.EOF) {
			t.Fatal("无效/typed-nil *AuditPostWriteError 不得匹配任何哨兵错误")
		}
	}
}

func TestAuditEntryInvariantsAndAccessors(t *testing.T) {
	pid, _ := ports.ParseProcessInstanceID("proc-inv-01")
	tid, _ := security.ParseTraceID("trace-inv-01")
	oid, _ := security.ParseOperationID("op-inv-01")
	bind, _ := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute, Tool: "exec", Action: "run", NodeID: "n1",
	})
	ts := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

	// 验证 AuditOutcomeUnknown 仅可配对 AuditPhaseFinalized，且完整校验全部访问器。
	unkEntry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID: pid, TraceID: tid, OperationID: oid,
		Phase: ports.AuditPhaseFinalized, Outcome: ports.AuditOutcomeUnknown,
		Risk: security.RiskDangerous, Decision: security.DecisionKindNeedApproval,
		Binding: bind, Timestamp: ts, Duration: algebraic.Some(algebraic.FromStdDuration(10 * time.Millisecond)),
		ErrorCode: "E_UNKNOWN", Reason: "transport reset mid-flight",
	})
	if err != nil || !unkEntry.IsValid() || unkEntry.Outcome() != ports.AuditOutcomeUnknown ||
		!unkEntry.ProcessID().Equal(pid) || !unkEntry.TraceID().Equal(tid) || !unkEntry.OperationID().Equal(oid) ||
		unkEntry.Phase() != ports.AuditPhaseFinalized || unkEntry.Risk() != security.RiskDangerous ||
		unkEntry.Decision() != security.DecisionKindNeedApproval || !unkEntry.Binding().Equal(bind) ||
		!unkEntry.Timestamp().Equal(ts) || unkEntry.ErrorCode() != "E_UNKNOWN" || unkEntry.Reason() != "transport reset mid-flight" {
		t.Fatalf("AuditOutcomeUnknown 构造或访问器异常: %v", err)
	}
	if dur, ok := unkEntry.Duration().Get(); !ok || dur.Std() != 10*time.Millisecond {
		t.Fatalf("AuditEntry.Duration 异常: (%v, %v)", dur, ok)
	}

	// 验证 Denied 合法配对（Deny / NeedApproval）。
	for _, dec := range []security.DecisionKind{security.DecisionKindDeny, security.DecisionKindNeedApproval} {
		if _, dErr := ports.NewAuditEntry(ports.AuditEntrySpec{
			ProcessID: pid, TraceID: tid, OperationID: oid,
			Phase: ports.AuditPhaseDenied, Outcome: ports.AuditOutcomeDenied,
			Risk: security.RiskModerate, Decision: dec, Binding: bind, Timestamp: ts,
		}); dErr != nil {
			t.Fatalf("AuditPhaseDenied 应接受决策 %s: %v", dec, dErr)
		}
	}

	// 验证矛盾的 (Phase, Decision)、非法 OutcomeUnknown 阶段与负时长均被拒绝。
	badSpecs := []ports.AuditEntrySpec{
		{ProcessID: pid, TraceID: tid, OperationID: oid, Phase: ports.AuditPhaseAuthorized, Outcome: ports.AuditOutcomePending, Risk: security.RiskSafe, Decision: security.DecisionKindDeny, Binding: bind, Timestamp: ts},
		{ProcessID: pid, TraceID: tid, OperationID: oid, Phase: ports.AuditPhaseFinalized, Outcome: ports.AuditOutcomeSucceeded, Risk: security.RiskSafe, Binding: bind, Timestamp: ts}, // 省略 Decision（零值 Deny）
		{ProcessID: pid, TraceID: tid, OperationID: oid, Phase: ports.AuditPhaseDenied, Outcome: ports.AuditOutcomeDenied, Risk: security.RiskSafe, Decision: security.DecisionKindAllow, Binding: bind, Timestamp: ts},
		{ProcessID: pid, TraceID: tid, OperationID: oid, Phase: ports.AuditPhaseAuthorized, Outcome: ports.AuditOutcomeUnknown, Risk: security.RiskSafe, Decision: security.DecisionKindAllow, Binding: bind, Timestamp: ts},
		{ProcessID: pid, TraceID: tid, OperationID: oid, Phase: ports.AuditPhaseFinalized, Outcome: ports.AuditOutcomeSucceeded, Risk: security.RiskSafe, Decision: security.DecisionKindAllow, Binding: bind, Timestamp: ts, Duration: algebraic.Some(algebraic.FromStdDuration(-time.Second))},
	}
	for i, sp := range badSpecs {
		if _, bErr := ports.NewAuditEntry(sp); bErr == nil {
			t.Fatalf("badSpecs[%d] 必须失败关闭", i)
		}
	}

	// 校验 CrashReconcileReport 与交互值对象全部访问器。
	rep, err := ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{
		ScannedLocks: 4, LiveLocksSkipped: 2, DeadLocksClaimed: 1, AbortedOperations: []security.OperationID{oid},
	})
	if err != nil || rep.ScannedLocks() != 4 || rep.LiveLocksSkipped() != 2 || rep.DeadLocksClaimed() != 1 || len(rep.AbortedOperations()) != 1 {
		t.Fatalf("CrashReconcileReport 访问器异常: %v", err)
	}
	sreq, _ := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Title: "T", Prompt: "P", Subject: "S", AllowEmpty: true})
	creq, _ := ports.NewConfirmRequest(ports.ConfirmRequestSpec{Title: "CT", Message: "CM", Subject: "CS", Risk: security.RiskDangerous})
	treq, _ := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{Title: "TT", Prompt: "TP", Subject: "TS", AllowEmpty: true})
	dig := security.DigestBytes([]byte("env"))
	aresp, _ := ports.NewApprovalDecisionResponse(security.VerdictAllow, dig, "ok")
	if sreq.Title() != "T" || sreq.Prompt() != "P" || sreq.Subject() != "S" || !sreq.AllowEmpty() ||
		creq.Title() != "CT" || creq.Message() != "CM" || creq.Subject() != "CS" || creq.Risk() != security.RiskDangerous ||
		treq.Title() != "TT" || treq.Prompt() != "TP" || treq.Subject() != "TS" || !treq.AllowEmpty() ||
		!aresp.Approved() || aresp.Verdict() != security.VerdictAllow || !aresp.EnvelopeDigest().Equal(dig) || aresp.Comment() != "ok" {
		t.Fatal("交互端口值对象访问器返回值不匹配")
	}
}

func TestMiscConstructorsAndValidation(t *testing.T) {
	ep, _ := netaddr.ParseEndpoint("192.0.2.10:22")
	fp := inventory.KeyFingerprintFromSHA256(sha256.Sum256([]byte("pub")))
	pk, err := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm: "ssh-ed25519", Fingerprint: fp, WireBlob: []byte{1, 2, 3}, Comment: "ops",
	})
	if err != nil || !pk.IsValid() {
		t.Fatalf("NewPublicKeyInfo 失败: (%v, %v)", pk, err)
	}
	if _, err := ports.NewHostTrustRequest(ports.HostTrustRequestSpec{
		Endpoint: ep, Presented: pk, Mode: option.StrictHostKeyCheckingYes,
	}); err != nil {
		t.Fatalf("NewHostTrustRequest 失败: %v", err)
	}
	var zeroRev ports.Revision
	if _, err := ports.NewInventorySnapshot(zeroRev, inventory.EmptyGraph()); err == nil {
		t.Fatal("零值 Revision 构造 InventorySnapshot 必须失败关闭")
	}
	if _, err := ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: "a.txt", Size: -1, Mode: 0o600}); err == nil {
		t.Fatal("负文件大小必须失败关闭")
	}
	if _, err := ports.NewLocalDirEntry("CON", fs.ModePerm, 10); err == nil {
		t.Fatal("非法本地目录项名 CON 必须失败关闭")
	}
	if _, err := ports.NewProcessResult(ports.ProcessResultSpec{ExitStatus: execution.NewExitCode(0), Stdout: []byte("ok")}); err != nil {
		t.Fatalf("NewProcessResult 失败: %v", err)
	}
	sock, _ := pathalg.ParseLocalSourcePath("/tmp/xops-mux.sock")
	if _, err := ports.NewMuxControlRequest(ports.MuxActionForward, sock, algebraic.None[ports.ForwardSpec]()); err == nil {
		t.Fatal("forward 动作缺少 ForwardSpec 必须失败关闭")
	}
	if _, err := ports.NewMuxControlRequest(ports.MuxActionCheck, sock, algebraic.None[ports.ForwardSpec]()); err != nil {
		t.Fatalf("NewMuxControlRequest check 失败: %v", err)
	}
	if _, err := ports.NewSignature("ssh-ed25519", []byte{9, 8, 7}); err != nil {
		t.Fatalf("NewSignature 失败: %v", err)
	}
	if _, err := ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: "ok.txt", Size: 12, Mode: 0o600, ModTime: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("NewLocalFileInfo 失败: %v", err)
	}
	var typedNilAuditErr *ports.AuditPostWriteError
	if typedNilAuditErr.IsValid() || typedNilAuditErr.Is(ports.ErrAuditPostWrite) {
		t.Fatal("typed-nil *AuditPostWriteError 必须失败关闭且不匹配 ErrAuditPostWrite")
	}
}
