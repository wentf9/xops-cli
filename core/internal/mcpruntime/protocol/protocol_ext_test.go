package protocol_test

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

func TestRequestID_CodecAndFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)

	var zeroID protocol.RequestID
	if zeroID.IsValid() {
		t.Fatalf("零值 RequestID 必须无效")
	}
	if _, err := jsonv2.Marshal(zeroID); err == nil {
		t.Fatalf("零值 RequestID 编码必须失败关闭")
	}
	if _, err := protocol.StringRequestID(""); err == nil {
		t.Fatalf("空字符串 RequestID 必须拒绝")
	}

	strID, err := protocol.StringRequestID("req-42")
	if err != nil || !strID.IsValid() || strID.String() != "req-42" {
		t.Fatalf("StringRequestID 异常: id=%v err=%v", strID, err)
	}
	assertRequestIDRoundTrip(t, strID, `"req-42"`)
	assertRequestIDRoundTrip(t, protocol.IntRequestID(99), `99`)

	for _, bad := range []string{`null`, `3.14`, `true`, `""`, `{}`, `[]`} {
		var dst protocol.RequestID
		if err := jsonv2.Unmarshal([]byte(bad), &dst); err == nil {
			t.Fatalf("非法 RequestID %s 必须失败关闭，却解码为 %v", bad, dst)
		}
	}
}

func assertRequestIDRoundTrip(t *testing.T, id protocol.RequestID, wantJSON string) {
	t.Helper()
	raw, err := protocol.MarshalCanonical(id)
	if err != nil || string(raw) != wantJSON {
		t.Fatalf("RequestID 编码失配: raw=%q want=%q err=%v", raw, wantJSON, err)
	}
	var dec protocol.RequestID
	if err := jsonv2.Unmarshal(raw, &dec); err != nil || !dec.Equal(id) {
		t.Fatalf("RequestID 解码失配: dec=%v err=%v", dec, err)
	}
}

func TestJSONRPC_StrictDecodeAndCanonicalMarshal(t *testing.T) {
	defer goleak.VerifyNone(t)

	var req protocol.Request
	if err := protocol.UnmarshalStrict([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","extra":123}`), &req); err == nil {
		t.Fatalf("含未知字段的 JSON-RPC 请求必须被拒绝")
	}
	if _, err := protocol.DecodeRequest([]byte(`{"jsonrpc":"1.0","id":1,"method":"ping"}`)); !errors.Is(err, protocol.ErrInvalidJSONRPC) {
		t.Fatalf("jsonrpc!=2.0 期望 ErrInvalidJSONRPC，实际=%v", err)
	}
	if _, err := protocol.DecodeRequest([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","extra":123}`)); !errors.Is(err, protocol.ErrInvalidJSONRPC) {
		t.Fatalf("未知顶层字段期望 ErrInvalidJSONRPC，实际=%v", err)
	}
	if _, err := protocol.DecodeRequest([]byte(`{not-json`)); !errors.Is(err, protocol.ErrParseJSON) {
		t.Fatalf("损坏 JSON 期望 ErrParseJSON，实际=%v", err)
	}
	// JSON-RPC 2.0 §5：无可用请求 ID 的错误响应必须显式输出 "id":null，且反序列化可准确还原为 None。
	errResp, err := protocol.NewErrorResponse(algebraic.None[protocol.RequestID](), protocol.CodeParseError, "parse error", nil)
	if err != nil {
		t.Fatalf("NewErrorResponse: %v", err)
	}
	errRaw, err := protocol.MarshalCanonical(errResp)
	if err != nil || !strings.Contains(string(errRaw), `"id":null`) {
		t.Fatalf("无 ID 错误响应必须包含 \"id\":null: raw=%s err=%v", errRaw, err)
	}
	var roundTripErr protocol.Response
	if err := jsonv2.Unmarshal(errRaw, &roundTripErr); err != nil || roundTripErr.ID.IsSome() || roundTripErr.Error == nil || roundTripErr.Error.Code != protocol.CodeParseError {
		t.Fatalf("反序列化含 id:null 的错误响应失败: resp=%+v err=%v", roundTripErr, err)
	}
	notif, err := protocol.DecodeRequest([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil || !notif.IsNotification() {
		t.Fatalf("合法通知解码异常: notif=%+v err=%v", notif, err)
	}

	m := map[string]int{"z": 1, "a": 2, "m": 3}
	b1, err := protocol.MarshalCanonical(m)
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	b2, err := protocol.MarshalCanonical(m)
	if err != nil {
		t.Fatalf("MarshalCanonical repeat: %v", err)
	}
	if !bytes.Equal(b1, b2) || string(b1) != `{"a":2,"m":3,"z":1}` {
		t.Fatalf("规范编码非确定性或未排序: b1=%s b2=%s", b1, b2)
	}
}

func TestToolDefinitions_AllSevenDiscriminatedSchemas(t *testing.T) {
	defer goleak.VerifyNone(t)

	defs, err := protocol.ToolDescriptors()
	if err != nil {
		t.Fatalf("ToolDescriptors: %v", err)
	}
	wantNames := []string{
		protocol.ToolNameNodes,
		protocol.ToolNameTerminalExec,
		protocol.ToolNameTerminalSession,
		protocol.ToolNameFile,
		protocol.ToolNameTransfer,
		protocol.ToolNameTunnel,
		protocol.ToolNameGUI,
	}
	if len(defs) != len(wantNames) {
		t.Fatalf("期望精确 7 个判别式工具，实际=%d", len(defs))
	}
	for i, d := range defs {
		assertToolSchemaValid(t, d, wantNames[i])
	}
}

func assertToolSchemaValid(t *testing.T, d protocol.ToolDescriptor, wantName string) {
	t.Helper()
	if d.Name != wantName || strings.TrimSpace(d.Description) == "" {
		t.Fatalf("工具名称或描述异常: got=%q want=%q", d.Name, wantName)
	}
	for _, r := range d.Description + string(d.InputSchema) {
		if unicode.Is(unicode.Han, r) || (r >= 0x3000 && r <= 0x303F) || (r >= 0xFF00 && r <= 0xFFEF) {
			t.Fatalf("MCP 工具 %q 描述或 Schema 必须为纯英文机器契约，禁止出现汉字/全角标点 %q: desc=%q", d.Name, r, d.Description)
		}
	}
	var schemaObj map[string]any
	if err := jsonv2.Unmarshal(d.InputSchema, &schemaObj); err != nil {
		t.Fatalf("工具 %q InputSchema 非合法 JSON: %v", d.Name, err)
	}
	ap, ok := schemaObj["additionalProperties"].(bool)
	if schemaObj["type"] != "object" || !ok || ap {
		t.Fatalf("工具 %q 必须为 object 且关闭 additionalProperties: %+v", d.Name, schemaObj)
	}
	props, _ := schemaObj["properties"].(map[string]any)
	if _, hasAction := props["action"]; !hasAction {
		t.Fatalf("工具 %q 缺少判别式 action 字段", d.Name)
	}
	if _, hasApproval := props["approval"]; !hasApproval {
		t.Fatalf("工具 %q 缺少统一 approval 字段", d.Name)
	}
}

func TestApprovalDecodeAndClassifyError(t *testing.T) {
	defer goleak.VerifyNone(t)
	assertApprovalDecodeCases(t)
	assertClassifyErrorCases(t)
	assertToolResultEncoders(t)
}

func assertApprovalDecodeCases(t *testing.T) {
	t.Helper()
	opID, err := security.ParseOperationID("op-proto-test-1")
	if err != nil {
		t.Fatalf("ParseOperationID: %v", err)
	}
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapMutate](),
		Tool:       "file", Action: "write", NodeID: "web-1",
		Parameters: map[string]string{"path": "/tmp/a.txt"},
	})
	if err != nil {
		t.Fatalf("NewOperationBinding: %v", err)
	}
	dec, err := security.NewDecisionNeedApproval(security.RiskModerate, "need approval")
	if err != nil {
		t.Fatalf("NewDecisionNeedApproval: %v", err)
	}
	var nonce [16]byte
	nonce[0] = 1
	env, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID: opID, Binding: binding, Risk: security.RiskModerate, Decision: dec,
		ScopeSummary: "write /tmp/a.txt", IssuedAt: now, TTL: algebraic.FromStdDuration(5 * time.Minute), Nonce: nonce,
	})
	if err != nil {
		t.Fatalf("NewApprovalEnvelope: %v", err)
	}
	dig, err := env.Digest()
	if err != nil {
		t.Fatalf("env.Digest: %v", err)
	}
	subOpt, err := protocol.DecodeApprovalSubmission(algebraic.Some(protocol.ApprovalSubmissionDTO{
		Verdict: security.VerdictAllow, EnvelopeDigest: dig, Envelope: algebraic.Some(env), Comment: "ok",
	}))
	if err != nil {
		t.Fatalf("DecodeApprovalSubmission valid: %v", err)
	}
	if sub, ok := subOpt.Get(); !ok || !sub.IsValid() {
		t.Fatalf("期望得到有效 gate.ApprovalSubmission")
	}
	if _, err := protocol.DecodeApprovalSubmission(algebraic.Some(protocol.ApprovalSubmissionDTO{
		Verdict: security.VerdictAllow, EnvelopeDigest: security.DigestBytes([]byte("tampered")), Envelope: algebraic.Some(env),
	})); !errors.Is(err, protocol.ErrInvalidApproval) {
		t.Fatalf("篡改摘要必须返回 ErrInvalidApproval，实际=%v", err)
	}
}

func assertClassifyErrorCases(t *testing.T) {
	t.Helper()
	cases := []struct {
		err       error
		wantCode  int
		wantStr   string
		wantHalt  bool
		wantUncrt bool
	}{
		{fmt.Errorf("w: %w", gate.ErrGateHalted), protocol.CodeGateHalted, "gate_halted", true, false},
		{fmt.Errorf("c: %w", uctrans.ErrUncertainCommit), protocol.CodeUncertainOutcome, "transfer_uncertain_commit", false, true},
		{fmt.Errorf("u: %w", protocol.ErrOutcomeUnknown), protocol.CodeUncertainOutcome, "uncertain_outcome", false, true},
		{protocol.ErrParseJSON, protocol.CodeParseError, "parse_error", false, false},
		{gate.ErrAuthorizationDenied, protocol.CodeAuthorizationDenied, "authorization_denied", false, false},
		{uctrans.ErrSymlinkPolicyDenied, protocol.CodeAuthorizationDenied, "symlink_policy_denied", false, false},
		{fmt.Errorf("%w: bad", protocol.ErrInvalidParams), protocol.CodeInvalidParams, "invalid_params", false, false},
		{fsm.ErrInvalidChunkOffset, protocol.CodeInvalidParams, "invalid_chunk_offset", false, false},
		{fsm.ErrTransferSizeExceeded, protocol.CodeInvalidParams, "transfer_size_exceeded", false, false},
		{fsm.ErrIllegalTransition, protocol.CodeInvalidState, "invalid_state", false, false},
		{uctrans.ErrPatchConflict, protocol.CodeInvalidState, "patch_conflict", false, false},
		{uctrans.ErrDigestMismatch, protocol.CodeInvalidState, "digest_mismatch", false, false},
	}
	for _, tc := range cases {
		code, payload := protocol.ClassifyError(tc.err)
		if code != tc.wantCode || payload.Code != tc.wantStr || payload.Halted != tc.wantHalt || payload.Uncertain != tc.wantUncrt || payload.Retryable {
			t.Fatalf("ClassifyError(%v) 失配: code=%d payload=%+v", tc.err, code, payload)
		}
	}
	noisyErr := fmt.Errorf("%w: %s\x00\r\n%s", ports.ErrInvalidArgument, strings.Repeat("A", 1200), "tail")
	_, noisyPayload := protocol.ClassifyError(noisyErr)
	if !strings.HasSuffix(noisyPayload.Message, "...(truncated)") || len(noisyPayload.Message) > 1040 || strings.ContainsAny(noisyPayload.Message, "\x00\r\n") {
		t.Fatalf("错误消息未脱敏截断: len=%d msg=%q", len(noisyPayload.Message), noisyPayload.Message)
	}
}

func assertToolResultEncoders(t *testing.T) {
	t.Helper()
	res, err := protocol.NewToolSuccessResult(map[string]any{"b": 2, "a": 1})
	if err != nil || res.IsError || len(res.Content) != 1 || string(res.StructuredContent) != `{"a":1,"b":2}` {
		t.Fatalf("NewToolSuccessResult 异常: res=%+v err=%v", res, err)
	}
	errRes, _, _ := protocol.NewToolErrorResult(errors.New("boom"))
	if !errRes.IsError || len(errRes.Content) != 1 || !errRes.StructuredContent.IsValid() {
		t.Fatalf("NewToolErrorResult 异常: res=%+v", errRes)
	}
}
