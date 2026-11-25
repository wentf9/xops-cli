package ports_test

import (
	"crypto/sha256"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

func assertJSONRoundTrip[T interface {
	IsValid() bool
	Equal(T) bool
}](t *testing.T, name string, val T, badPayloads ...string) []byte {
	t.Helper()
	raw1, err := jsonv2.Marshal(val, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("%s Marshal 失败: %v", name, err)
	}
	raw2, err := jsonv2.Marshal(val, jsonv2.Deterministic(true))
	if err != nil || string(raw1) != string(raw2) {
		t.Fatalf("%s Deterministic(true) 编码非确定性: %s vs %s", name, raw1, raw2)
	}
	var got T
	if err := jsonv2.Unmarshal(raw1, &got); err != nil {
		t.Fatalf("%s Unmarshal 失败 (raw=%s): %v", name, raw1, err)
	}
	if !got.IsValid() || !got.Equal(val) {
		t.Fatalf("%s 往返结果不一致: got=%+v want=%+v", name, got, val)
	}
	var zero T
	if _, err := jsonv2.Marshal(zero, jsonv2.Deterministic(true)); err == nil {
		t.Fatalf("%s 零值 Marshal 必须失败关闭", name)
	}
	for _, raw := range append([]string{`null`, `{}`}, badPayloads...) {
		var dst T
		if err := jsonv2.Unmarshal([]byte(raw), &dst); err == nil || dst.IsValid() {
			t.Fatalf("%s 应拒绝非法 JSON %s，实际 err=%v valid=%v", name, raw, err, dst.IsValid())
		}
	}
	return raw1
}

func TestStoreAndLocalFSJSONCodecs(t *testing.T) {
	rev, _ := ports.ParseRevision("rev-42")
	committed, _ := ports.NewDurabilityCommitted(rev)
	rawDur := assertJSONRoundTrip(t, "DurabilityOutcome(committed)", committed,
		`{"status":"committed"}`,
		`{"status":"committed","revision":"rev-42","extra":1}`,
		`{"status":"not_applied","revision":"rev-42"}`,
	)
	if len(rawDur) == 0 {
		t.Fatal("DurabilityOutcome 编码不应为空")
	}
	andOut, _ := ports.NewDurabilityAppliedNotDurable(algebraic.Some(rev), "fsync failed")
	assertJSONRoundTrip(t, "DurabilityOutcome(applied_not_durable)", andOut,
		`{"status":"applied_not_durable"}`,
	)

	ep, _ := netaddr.ParseEndpoint("192.0.2.10:2222")
	user, _ := option.ParseUsername("deploy")
	jumpProxy, err := option.ParseProxyJump("bastion.example.test:2222")
	if err != nil {
		t.Fatalf("ParseProxyJump 失败: %v", err)
	}
	layer, err := option.ParseOptionLayer("ConnectTimeout 15", "StrictHostKeyChecking yes")
	if err != nil {
		t.Fatalf("ParseOptionLayer 失败: %v", err)
	}
	vh, err := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias:      "prod-web",
		SourceFile: "/home/ops/.ssh/config",
		Endpoint:   algebraic.Some(ep),
		User:       algebraic.Some(user),
		Proxy:      jumpProxy,
		Layer:      layer,
	})
	if err != nil {
		t.Fatalf("NewOpenSSHVirtualHost 失败: %v", err)
	}
	assertJSONRoundTrip(t, "OpenSSHVirtualHost(populated)", vh,
		`{"alias":"prod-web","extra":true}`,
	)

	lim, _ := ports.NewReadLimits(4096)
	assertJSONRoundTrip(t, "ReadLimits", lim,
		`{"max_bytes":0}`,
		`{"max_bytes":-5}`,
		`{"max_bytes":4096,"extra":1}`,
	)
}

func TestVaultTransportAndRemoteFSJSONCodecs(t *testing.T) {
	ep, _ := netaddr.ParseEndpoint("192.0.2.10:22")
	fp := inventory.KeyFingerprintFromSHA256(sha256.Sum256([]byte("ed25519-key")))
	pk, _ := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{
		Algorithm: "ssh-ed25519", Fingerprint: fp, WireBlob: []byte{0x01, 0x02, 0x03}, Comment: "ci",
	})
	assertJSONRoundTrip(t, "PublicKeyInfo", pk,
		`{"algorithm":"ssh-ed25519","fingerprint":"`+fp.String()+`","wire_blob_b64":"!!!bad!!!"}`,
		`{"algorithm":"ssh-ed25519","fingerprint":"`+fp.String()+`","wire_blob_b64":"AQID","extra":1}`,
	)

	htc, _ := ports.NewHostTrustCheck(ports.HostTrustCheckSpec{
		Status: ports.HostTrustMismatch, Endpoint: ep, Presented: pk,
		ExpectedFingerprints: []inventory.KeyFingerprint{fp}, Reason: "key changed",
	})
	assertJSONRoundTrip(t, "HostTrustCheck", htc,
		`{"status":"trusted","endpoint":"192.0.2.10:22"}`,
	)

	sz, _ := ports.NewTerminalSize(120, 40)
	assertJSONRoundTrip(t, "TerminalSize", sz, `{"cols":0,"rows":24}`, `{"cols":80,"rows":24,"extra":1}`)

	pty, _ := ports.NewPTYRequest("xterm-256color", sz)
	assertJSONRoundTrip(t, "PTYRequest", pty, `{"term":"xterm"}`, `{"term":"xterm","size":{"cols":80,"rows":24},"extra":1}`)

	fwd, _ := ports.NewForwardSpec(ports.ForwardLocal, "127.0.0.1:8080", "10.0.0.5:80")
	assertJSONRoundTrip(t, "ForwardSpec", fwd,
		`{"direction":"local","bind_addr":"127.0.0.1:8080"}`,
		`{"direction":"dynamic","bind_addr":"127.0.0.1:1080","target_addr":"bad"}`,
	)

	mresp, _ := ports.NewMuxControlResponse(true, 12345, "running")
	assertJSONRoundTrip(t, "MuxControlResponse", mresp,
		`{"alive":false,"master_pid":123}`,
		`{"alive":true,"extra":1}`,
	)

	anc, _ := ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, 7, 99)
	assertJSONRoundTrip(t, "RemoteFileAnchor", anc,
		`{"file_type":"regular","has_dev_ino":false,"ino":1}`,
		`{"file_type":"regular","extra":1}`,
	)

	rp, _ := pathalg.ParseAbsRemotePath("/etc/app.conf")
	ts := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	rstat, _ := ports.NewRemoteFileStat(ports.RemoteFileStatSpec{
		Path: rp, Size: 512, Mode: 0o640, ModTime: ts, Anchor: anc,
	})
	assertJSONRoundTrip(t, "RemoteFileStat", rstat, `{"path":"/etc/app.conf","size":-1,"mode":416,"anchor":{"file_type":"regular"}}`)

	rn, _ := pathalg.ParseRemoteName("app.conf")
	rde, _ := ports.NewRemoteDirEntry(ports.RemoteDirEntrySpec{
		Name: rn, FileType: ports.RemoteFileRegular, Size: 512, Mode: 0o640, ModTime: ts,
	})
	assertJSONRoundTrip(t, "RemoteDirEntry", rde, `{"name":"app.conf","file_type":"regular","size":-1,"mode":416}`)

	rwsp, _ := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{
		Perm: 0o600, ExpectedAnchor: algebraic.Some(anc), AtomicRename: true,
	})
	assertJSONRoundTrip(t, "RemoteWriteSpec", rwsp,
		`{"perm":0}`,
		`{"perm":384,"no_clobber":true,"expected_anchor":{"file_type":"regular"}}`,
	)
}

func TestAuditAndSystemJSONCodecs(t *testing.T) {
	pid, _ := ports.ParseProcessInstanceID("proc-01")
	tid, _ := security.ParseTraceID("trace-01")
	oid, _ := security.ParseOperationID("op-01")
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityExecute,
		Tool:       "terminal_exec",
		Action:     "run",
		NodeID:     "web-01",
	})
	if err != nil {
		t.Fatalf("NewOperationBinding 失败: %v", err)
	}
	entry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID:   pid,
		TraceID:     tid,
		OperationID: oid,
		Phase:       ports.AuditPhaseFinalized,
		Outcome:     ports.AuditOutcomeSucceeded,
		Risk:        security.RiskModerate,
		Decision:    security.DecisionKindAllow,
		Binding:     binding,
		Timestamp:   time.Date(2026, 11, 25, 12, 30, 0, 0, time.UTC),
		Duration:    algebraic.Some(algebraic.FromStdDuration(250 * time.Millisecond)),
		Reason:      "completed cleanly",
	})
	if err != nil {
		t.Fatalf("NewAuditEntry 失败: %v", err)
	}
	rawAudit := assertJSONRoundTrip(t, "AuditEntry", entry,
		`{"process_id":"proc-01","trace_id":"trace-01","operation_id":"op-01","phase":"authorized","outcome":"succeeded"}`,
		`{"process_id":"`+pid.String()+`","trace_id":"`+tid.String()+`","operation_id":"`+oid.String()+`","phase":"finalized","outcome":"succeeded","risk":"moderate","binding":{"capability":"execute","tool":"ssh","action":"exec"},"timestamp":"2026-11-25T10:00:00Z"}`,
		`{"process_id":"`+pid.String()+`","trace_id":"`+tid.String()+`","operation_id":"`+oid.String()+`","phase":"finalized","outcome":"succeeded","risk":"moderate","decision":null,"binding":{"capability":"execute","tool":"ssh","action":"exec"},"timestamp":"2026-11-25T10:00:00Z"}`,
		`{"process_id":"`+pid.String()+`","trace_id":"`+tid.String()+`","operation_id":"`+oid.String()+`","phase":"authorized","outcome":"pending","risk":"safe","decision":"deny","binding":{"capability":"execute","tool":"ssh","action":"exec"},"timestamp":"2026-11-25T10:00:00Z"}`,
		`{"process_id":"`+pid.String()+`","trace_id":"`+tid.String()+`","operation_id":"`+oid.String()+`","phase":"denied","outcome":"denied","risk":"safe","decision":"allow","binding":{"capability":"execute","tool":"ssh","action":"exec"},"timestamp":"2026-11-25T10:00:00Z"}`,
	)
	canon, err := entry.CanonicalJSON()
	if err != nil || string(canon) != string(rawAudit) {
		t.Fatalf("CanonicalJSON 与 Deterministic Marshal 不一致: %v", err)
	}
	unkEntry, err := ports.NewAuditEntry(ports.AuditEntrySpec{
		ProcessID: pid, TraceID: tid, OperationID: oid,
		Phase: ports.AuditPhaseFinalized, Outcome: ports.AuditOutcomeUnknown,
		Risk: security.RiskDangerous, Decision: security.DecisionKindNeedApproval,
		Binding: binding, Timestamp: time.Date(2026, 11, 25, 12, 31, 0, 0, time.UTC),
		Reason: "peer closed mid-write",
	})
	if err != nil {
		t.Fatalf("NewAuditEntry(outcome_unknown) 失败: %v", err)
	}
	assertJSONRoundTrip(t, "AuditEntry(outcome_unknown)", unkEntry)

	rep, _ := ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{
		ScannedLocks: 3, LiveLocksSkipped: 1, DeadLocksClaimed: 2,
		AbortedOperations: []security.OperationID{oid},
	})
	assertJSONRoundTrip(t, "CrashReconcileReport", rep,
		`{"scanned_locks":1,"live_locks_skipped":2,"dead_locks_claimed":0}`,
		`{"scanned_locks":1,"live_locks_skipped":0,"dead_locks_claimed":0,"extra":1}`,
	)

	wd, _ := pathalg.ParseLocalDir("/tmp")
	pspec, err := ports.NewProcessSpec(ports.ProcessSpecInput{
		Command: "/usr/bin/ssh", Args: []string{"-V"}, WorkDir: algebraic.Some(wd),
		Env:     map[string]string{"Z_KEY": "3", "A_KEY": "1", "M_KEY": "2"},
		Timeout: algebraic.Some(algebraic.FromStdDuration(5 * time.Second)),
	})
	if err != nil {
		t.Fatalf("NewProcessSpec 失败: %v", err)
	}
	assertJSONRoundTrip(t, "ProcessSpec", pspec,
		`{"command":"/usr/bin/ssh","max_output_bytes":0}`,
		`{"command":"/usr/bin/ssh","max_output_bytes":1024,"extra":1}`,
	)
	// 验证未显式传 Deterministic(true) 选项调用 jsonv2.Marshal(pspec) 时，多键 Env 仍按字典序稳定编码。
	wantEnvOrder := `"env":{"A_KEY":"1","M_KEY":"2","Z_KEY":"3"}`
	for i := range 20 {
		plainRaw, mErr := jsonv2.Marshal(pspec)
		if mErr != nil || !strings.Contains(string(plainRaw), wantEnvOrder) {
			t.Fatalf("第 %d 次无选项 jsonv2.Marshal(ProcessSpec) 未保持确定性键序: err=%v raw=%s", i, mErr, plainRaw)
		}
	}
	if err := pspec.MarshalJSONTo(nil); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("MarshalJSONTo(nil) 应返回 ErrInvalidArgument，实际: %v", err)
	}

	sreq, _ := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Title: "SSH", Prompt: "Password:", Subject: "web-01"})
	assertJSONRoundTrip(t, "SecretPromptRequest", sreq, `{"prompt":"Password:","extra":1}`)

	creq, _ := ports.NewConfirmRequest(ports.ConfirmRequestSpec{Title: "Confirm", Message: "Trust host?", Subject: "web-01", Risk: security.RiskModerate})
	assertJSONRoundTrip(t, "ConfirmRequest", creq, `{"message":"Trust host?"}`, `{"message":"Trust host?","risk":"safe","extra":1}`)

	treq, _ := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{Title: "OTP", Prompt: "Code:", Subject: "web-01"})
	assertJSONRoundTrip(t, "TextPromptRequest", treq, `{"prompt":"Code:","extra":1}`)

	dig := security.DigestBytes([]byte("envelope"))
	aresp, _ := ports.NewApprovalDecisionResponse(security.VerdictAllow, dig, "approved")
	assertJSONRoundTrip(t, "ApprovalDecisionResponse", aresp,
		`{"verdict":"allow"}`,
		`{"envelope_digest":"`+dig.String()+`"}`,
		`{"verdict":null,"envelope_digest":"`+dig.String()+`"}`,
		`{"verdict":"allow","envelope_digest":"`+dig.String()+`","extra":1}`,
	)
}
