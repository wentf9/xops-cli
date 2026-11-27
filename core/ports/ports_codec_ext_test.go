package ports_test

import (
	"crypto/sha256"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
	assertJSONRoundTrip(t, "ForwardSpec(local/tcp)", fwd,
		`{"direction":"local","bind_addr":"127.0.0.1:8080"}`,
		`{"direction":"local","bind_addr":"127.0.0.1:8080","target_addr":"10.0.0.5:80"}`,
		`{"direction":"dynamic","bind_kind":"tcp","bind_addr":"127.0.0.1:1080","target_addr":"bad"}`,
		`{"direction":"dynamic","bind_kind":"unix","bind_addr":"/tmp/d.sock"}`,
		`{"direction":"tun","bind_addr":"tun0","target_addr":"tun1"}`,
		`{"direction":"local","bind_kind":"tcp","bind_addr":"127.0.0.1:8080","target_kind":"tcp","target_addr":"10.0.0.5:80","tun":{"mode":"ethernet","local_unit":0,"remote_unit":0}}`,
	)
	for _, tc := range []struct {
		name      string
		dir       ports.ForwardDirection
		bk, tk    ports.ForwardEndpointKind
		bind, tgt string
	}{
		{"local/unix-unix", ports.ForwardLocal, ports.ForwardEndpointUnix, ports.ForwardEndpointUnix, "/tmp/local.sock", "/run/remote.sock"},
		{"local/tcp-unix", ports.ForwardLocal, ports.ForwardEndpointTCP, ports.ForwardEndpointUnix, "127.0.0.1:8080", "/run/remote.sock"},
		{"local/unix-tcp", ports.ForwardLocal, ports.ForwardEndpointUnix, ports.ForwardEndpointTCP, "/tmp/local.sock", "10.0.0.5:80"},
		{"remote/unix-unix", ports.ForwardRemote, ports.ForwardEndpointUnix, ports.ForwardEndpointUnix, "/run/remote.sock", "/tmp/local.sock"},
		{"remote/unix-tcp", ports.ForwardRemote, ports.ForwardEndpointUnix, ports.ForwardEndpointTCP, "/run/remote.sock", "127.0.0.1:3000"},
		{"remote/tcp-unix", ports.ForwardRemote, ports.ForwardEndpointTCP, ports.ForwardEndpointUnix, "0.0.0.0:9090", "/tmp/local.sock"},
	} {
		sp, sErr := ports.NewTypedForwardSpec(tc.dir, tc.bk, tc.bind, tc.tk, tc.tgt)
		if sErr != nil || sp.BindKind() != tc.bk || sp.TargetKind() != tc.tk {
			t.Fatalf("NewTypedForwardSpec(%s) 失败: (%v, %v)", tc.name, sp, sErr)
		}
		assertJSONRoundTrip(t, "ForwardSpec("+tc.name+")", sp)
	}
	fwdDyn, err := ports.NewForwardSpec(ports.ForwardDynamic, "127.0.0.1:1080", "")
	if err != nil || fwdDyn.BindKind() != ports.ForwardEndpointTCP || fwdDyn.TargetKind() != ports.ForwardEndpointInvalid {
		t.Fatalf("NewForwardSpec(dynamic) 失败: (%v, %v)", fwdDyn, err)
	}
	assertJSONRoundTrip(t, "ForwardSpec(dynamic)", fwdDyn)
	tunP2P, _ := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, ports.TUNUnitAny)
	fwdTUNP2P, err := ports.NewForwardTUNSpec(tunP2P)
	if err != nil || !fwdTUNP2P.TUN().IsSome() {
		t.Fatalf("NewForwardTUNSpec(p2p) 失败: (%v, %v)", fwdTUNP2P, err)
	}
	assertJSONRoundTrip(t, "ForwardSpec(tun/p2p)", fwdTUNP2P,
		`{"direction":"tun","bind_addr":"forged","tun":{"mode":"point_to_point","local_unit":0,"remote_unit":1}}`,
		`{"direction":"tun","bind_kind":"tcp","tun":{"mode":"point_to_point","local_unit":0,"remote_unit":1}}`,
	)
	tunEth, _ := ports.NewTUNSpec(ports.TUNModeEthernet, 2, 3)
	fwdTUNEth, err := ports.NewForwardTUNSpec(tunEth)
	if err != nil || fwdTUNEth.BindAddr() != "tap2" || fwdTUNEth.TargetAddr() != "tap3" {
		t.Fatalf("NewForwardTUNSpec(ethernet) 失败: (%v, %v)", fwdTUNEth, err)
	}
	assertJSONRoundTrip(t, "ForwardSpec(tun/ethernet)", fwdTUNEth)
	if _, err := ports.NewForwardSpec(ports.ForwardTUN, "tun0", "tun1"); err == nil {
		t.Fatal("NewForwardSpec(ForwardTUN) 必须失败关闭，强制使用 NewForwardTUNSpec")
	}

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

	rrsp, err := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{ExpectedAnchor: algebraic.Some(anc)})
	if err != nil {
		t.Fatalf("NewRemoteRenameSpec(anchor) 失败: %v", err)
	}
	assertJSONRoundTrip(t, "RemoteRenameSpec(anchor)", rrsp,
		`{"no_clobber":true,"expected_anchor":{"file_type":"regular"}}`,
		`{"extra":1}`,
	)
	rrNoClobber, err := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{NoClobber: true})
	if err != nil || !rrNoClobber.NoClobber() {
		t.Fatalf("NewRemoteRenameSpec(no_clobber) 失败: (%v, %v)", rrNoClobber, err)
	}
	assertJSONRoundTrip(t, "RemoteRenameSpec(no_clobber)", rrNoClobber)
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

func TestInteractionPromptJSONCodecs(t *testing.T) {
	sreq, _ := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{Title: "SSH", Prompt: "Password:", Subject: "web-01"})
	sRaw := assertJSONRoundTrip(t, "SecretPromptRequest(plain)", sreq,
		`{"prompt":"Password:","title_message":{}}`,
		`{"prompt":"Password:","body_message":{"id":"BAD"}}`,
	)
	if strings.Contains(string(sRaw), "title_message") || strings.Contains(string(sRaw), "body_message") {
		t.Fatalf("无结构化消息时 SecretPromptRequest 应经 omitzero 省略消息字段: %s", sRaw)
	}
	sTitleMsg := domi18n.NewMessage(domi18n.KeyInteractPrivilegeTitle)
	sBodyMsg := domi18n.NewMessage(domi18n.KeyInteractPrivilegeBody, domi18n.BoundStr("method", "sudo"), domi18n.BoundStr("node", "web-01"))
	sreqMsg, err := ports.NewSecretPromptRequest(ports.SecretPromptRequestSpec{
		Title: sTitleMsg.Canonical(), Prompt: sBodyMsg.Canonical(), Subject: "web-01",
		TitleMessage: algebraic.Some(sTitleMsg), BodyMessage: algebraic.Some(sBodyMsg),
	})
	if err != nil {
		t.Fatalf("NewSecretPromptRequest(with msg) 失败: %v", err)
	}
	assertJSONRoundTrip(t, "SecretPromptRequest(with messages)", sreqMsg)

	creq, _ := ports.NewConfirmRequest(ports.ConfirmRequestSpec{Title: "Confirm", Message: "Trust host?", Subject: "web-01", Risk: security.RiskModerate})
	cRaw := assertJSONRoundTrip(t, "ConfirmRequest(plain)", creq, `{"message":"Trust host?","risk":"safe","body_message":{}}`)
	if strings.Contains(string(cRaw), "title_message") || strings.Contains(string(cRaw), "body_message") {
		t.Fatalf("无结构化消息时 ConfirmRequest 应经 omitzero 省略消息字段: %s", cRaw)
	}
	cTitleMsg := domi18n.NewMessage(domi18n.KeyInteractHostKeyTitle)
	cBodyMsg := domi18n.NewMessage(domi18n.KeyInteractHostKeyBody, domi18n.BoundStr("algorithm", "ssh-ed25519"), domi18n.BoundStr("fingerprint", "SHA256:test"), domi18n.BoundStr("endpoint", "192.0.2.10:22"))
	creqMsg, err := ports.NewConfirmRequest(ports.ConfirmRequestSpec{
		Title: cTitleMsg.Canonical(), Message: cBodyMsg.Canonical(), Subject: "192.0.2.10:22", Risk: security.RiskModerate,
		TitleMessage: algebraic.Some(cTitleMsg), BodyMessage: algebraic.Some(cBodyMsg),
	})
	if err != nil {
		t.Fatalf("NewConfirmRequest(with msg) 失败: %v", err)
	}
	assertJSONRoundTrip(t, "ConfirmRequest(with messages)", creqMsg)

	treq, _ := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{Title: "OTP", Prompt: "Code:", Subject: "web-01"})
	tRaw := assertJSONRoundTrip(t, "TextPromptRequest(plain)", treq, `{"prompt":"Code:","title_message":{"id":"INVALID"}}`)
	if strings.Contains(string(tRaw), "title_message") || strings.Contains(string(tRaw), "body_message") {
		t.Fatalf("无结构化消息时 TextPromptRequest 应经 omitzero 省略消息字段: %s", tRaw)
	}
	tTitleMsg := domi18n.NewMessage(domi18n.KeyInteractSSHChallengeTitle)
	tBodyMsg := domi18n.NewMessage(domi18n.KeyInteractChallengeResponse)
	treqMsg, err := ports.NewTextPromptRequest(ports.TextPromptRequestSpec{
		Title: tTitleMsg.Canonical(), Prompt: tBodyMsg.Canonical(), Subject: "web-01", AllowEmpty: true,
		TitleMessage: algebraic.Some(tTitleMsg), BodyMessage: algebraic.Some(tBodyMsg),
	})
	if err != nil {
		t.Fatalf("NewTextPromptRequest(with msg) 失败: %v", err)
	}
	assertJSONRoundTrip(t, "TextPromptRequest(with messages)", treqMsg)
	assertAdversarialInteractionPromptJSONRejected(t)
}

func assertAdversarialInteractionPromptJSONRejected(t *testing.T) {
	t.Helper()
	longTitleLeaf := strings.Repeat("t", 140)
	longBodyLeaf := strings.Repeat("b", 530)

	// 1. 嵌套空 Fallback 子消息携带超长叶子参数（JSON 反序列化路径必须拒绝并返回 ErrInvalidArgument）。
	nestedTitleOverflow := `{"prompt":"Password:","title_message":{"id":"a.b","params":[{"key":"c","kind":"message","message":{"id":"c.d","params":[{"key":"x","kind":"string","str":"` + longTitleLeaf + `"}]}}]}}`
	nestedBodyOverflow := `{"prompt":"Code:","body_message":{"id":"a.b","params":[{"key":"c","kind":"message","message":{"id":"c.d","params":[{"key":"x","kind":"string","str":"` + longBodyLeaf + `"}]}}]}}`
	// 2. OSC 52 与 Bidi 覆写字符经 JSON 注入 TitleMessage/BodyMessage 模板或参数，必须拒绝。
	oscTitleJSON := `{"prompt":"Password:","title_message":{"id":"a.osc","fallback":"\u001b]52;c;YQ==\u0007ok"}}`
	bidiBodyJSON := `{"message":"Trust?","risk":"moderate","body_message":{"id":"a.bidi","fallback":"hello {x}","params":[{"key":"x","kind":"string","str":"bad\u202evalue"}]}}`

	for name, raw := range map[string]string{
		"secret_nested_title_overflow": nestedTitleOverflow,
		"secret_osc_title":             oscTitleJSON,
	} {
		var dst ports.SecretPromptRequest
		if err := jsonv2.Unmarshal([]byte(raw), &dst); !errors.Is(err, ports.ErrInvalidArgument) || dst.IsValid() {
			t.Fatalf("%s 应返回 ErrInvalidArgument 且保持零值，实际 err=%v valid=%v", name, err, dst.IsValid())
		}
	}
	var dstText ports.TextPromptRequest
	if err := jsonv2.Unmarshal([]byte(nestedBodyOverflow), &dstText); !errors.Is(err, ports.ErrInvalidArgument) || dstText.IsValid() {
		t.Fatalf("text_nested_body_overflow 应返回 ErrInvalidArgument 且保持零值，实际 err=%v valid=%v", err, dstText.IsValid())
	}
	var dstConf ports.ConfirmRequest
	if err := jsonv2.Unmarshal([]byte(bidiBodyJSON), &dstConf); !errors.Is(err, ports.ErrInvalidArgument) || dstConf.IsValid() {
		t.Fatalf("confirm_bidi_body 应返回 ErrInvalidArgument 且保持零值，实际 err=%v valid=%v", err, dstConf.IsValid())
	}
}

// TestDownstreamPortJSONCodecs 验证 Phase 2.5/3/4 新增端口值对象的 json/v2 编解码与不变量。
func TestDownstreamPortJSONCodecs(t *testing.T) {
	vstat, err := ports.NewVaultStatus(ports.VaultStatusSpec{State: ports.VaultStateUnlocked, KnownStores: []string{"file", "keychain", "file"}, Detail: "ready"})
	if err != nil || !vstat.IsUnlocked() || len(vstat.KnownStores()) != 2 {
		t.Fatalf("NewVaultStatus 失败: (%v, %v)", vstat, err)
	}
	assertJSONRoundTrip(t, "VaultStatus", vstat, `{"state":"invalid"}`, `{"state":"locked","extra":1}`)

	sum256 := sha256.Sum256([]byte("sshfp-key"))
	sshfp, err := ports.NewSSHFPRecord(ports.SSHFPRecordSpec{Algorithm: 4, FingerprintType: 2, Digest: sum256[:], Authenticated: true})
	if err != nil || !sshfp.Authenticated() || sshfp.Algorithm() != 4 || sshfp.FingerprintType() != 2 {
		t.Fatalf("NewSSHFPRecord 失败: (%v, %v)", sshfp, err)
	}
	assertJSONRoundTrip(t, "SSHFPRecord", sshfp,
		`{"algorithm":4,"fingerprint_type":2,"digest_b64":"AQID"}`,
		`{"algorithm":4,"fingerprint_type":2,"digest_b64":"!!!","authenticated":true}`,
	)

	lid, err := ports.NewLocalIdentityInfo(ports.LocalIdentityInfoSpec{LocalHost: "devbox.local", LocalUser: "ops", LocalUID: "1000", HomeDir: "/home/ops"})
	if err != nil || !lid.IsValid() {
		t.Fatalf("NewLocalIdentityInfo 失败: (%v, %v)", lid, err)
	}
	tctx := lid.ApplyToTokenContext(option.TokenContext{})
	if tctx.LocalHost != "devbox.local" || tctx.LocalUser != "ops" || tctx.LocalUID != "1000" || tctx.HomeDir != "/home/ops" {
		t.Fatalf("ApplyToTokenContext 未正确写入字段: %+v", tctx)
	}
	assertJSONRoundTrip(t, "LocalIdentityInfo", lid, `{"local_host":"devbox","local_user":"ops"}`, `{"local_host":"devbox","local_user":"ops","home_dir":"/home/ops","extra":1}`)

	tspec, err := ports.NewTUNSpec(ports.TUNModePointToPoint, 0, ports.TUNUnitAny)
	if err != nil || tspec.LocalUnit() != 0 || tspec.RemoteUnit() != ports.TUNUnitAny {
		t.Fatalf("NewTUNSpec 失败: (%v, %v)", tspec, err)
	}
	assertJSONRoundTrip(t, "TUNSpec", tspec, `{"mode":"point_to_point","local_unit":0}`, `{"mode":"point_to_point","local_unit":9999,"remote_unit":0}`)

	cmd, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindCommand,
		Profile: execution.DefaultServerLaunchProfile(),
		Command: "systemctl reload nginx",
	})
	if err != nil {
		t.Fatalf("NewCommandPlan 失败: %v", err)
	}
	u, _ := option.ParseUsername("root")
	preq, err := ports.NewPrivilegeRequest(ports.PrivilegeRequestSpec{
		Method: ports.PrivilegeMethodSudo, Command: cmd, TargetUser: algebraic.Some(u),
		NonInteractive: true, Timeout: algebraic.Some(algebraic.FromStdDuration(10 * time.Second)),
	})
	if err != nil || !preq.NonInteractive() {
		t.Fatalf("NewPrivilegeRequest 失败: (%v, %v)", preq, err)
	}
	assertJSONRoundTrip(t, "PrivilegeRequest", preq, `{"method":"invalid"}`, `{"method":"sudo","extra":1}`)

	sprob, err := ports.NewShellProbeResult(ports.ShellProbeResultSpec{
		Dialect: execution.DialectPOSIX, Interpreter: execution.InterpreterBash,
		OSFamily: "linux", ProbeStage: 1, RawBanner: "GNU bash 5.2",
	})
	if err != nil || !sprob.LaunchProfile().IsValid() || sprob.ProbeStage() != 1 {
		t.Fatalf("NewShellProbeResult 失败: (%v, %v)", sprob, err)
	}
	assertJSONRoundTrip(t, "ShellProbeResult", sprob,
		`{"dialect":"posix","interpreter":"cmd","probe_stage":1}`,
		`{"dialect":"posix","interpreter":"bash","probe_stage":3}`,
	)
}

func TestEmptySliceNilNormalization(t *testing.T) {
	vs, err := ports.NewVaultStatus(ports.VaultStatusSpec{State: ports.VaultStateUnlocked, KnownStores: []string{}})
	if err != nil || vs.KnownStores() != nil {
		t.Fatalf("NewVaultStatus 空切片须归一化为 nil: err=%v got=%#v", err, vs.KnownStores())
	}
	ep, _ := netaddr.ParseEndpoint("192.0.2.10:22")
	fp := inventory.KeyFingerprintFromSHA256(sha256.Sum256([]byte("empty-slice-norm")))
	pk, _ := ports.NewPublicKeyInfo(ports.PublicKeyInfoSpec{Algorithm: "ssh-ed25519", Fingerprint: fp, WireBlob: []byte{1, 2, 3}})
	htc, err := ports.NewHostTrustCheck(ports.HostTrustCheckSpec{
		Status: ports.HostTrustTrusted, Endpoint: ep, Presented: pk, ExpectedFingerprints: []inventory.KeyFingerprint{},
	})
	if err != nil || htc.ExpectedFingerprints() != nil {
		t.Fatalf("NewHostTrustCheck 空切片须归一化为 nil: err=%v got=%#v", err, htc.ExpectedFingerprints())
	}
	ps, err := ports.NewProcessSpec(ports.ProcessSpecInput{Command: "echo", Args: []string{}})
	if err != nil || ps.Args() != nil {
		t.Fatalf("NewProcessSpec 空 Args 须归一化为 nil: err=%v got=%#v", err, ps.Args())
	}
	pr, err := ports.NewProcessResult(ports.ProcessResultSpec{
		ExitStatus: execution.NewExitCode(0), Stdout: []byte{}, Stderr: []byte{},
	})
	if err != nil || pr.Stdout() != nil || pr.Stderr() != nil {
		t.Fatalf("NewProcessResult 空输出须归一化为 nil: err=%v stdout=%#v stderr=%#v", err, pr.Stdout(), pr.Stderr())
	}
}
