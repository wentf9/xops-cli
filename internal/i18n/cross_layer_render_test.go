package i18n

import (
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

func TestCrossLayerDomainAndGateTemplates_BilingualParity(t *testing.T) {
	enLoc, zhLoc := mustLoadBilingualLocalizers(t)

	assertDomainLayerBilingualErrors(t, enLoc, zhLoc)
	assertGateCustomNodeBilingualTemplates(t, enLoc, zhLoc)
}

func assertDomainLayerBilingualErrors(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()

	_, durErr := algebraic.ParseDuration("not-a-duration")
	_, dialectErr := execution.ParseLaunchDialect("bogus-dialect")
	_, fsmErr := fsm.ParseApprovalPhase("bogus-phase")
	_, hostIDErr := inventory.ParseHostID("bad/host")
	_, hostPortErr := netaddr.ParseHostPort("missing-port-host")
	_, originErr := option.ParseOriginKind("bogus-origin")
	_, remotePathErr := pathalg.ParseRemotePath("rel/bad\x00path")
	_, digestErr := plan.ParsePlanDigest("not-a-digest")
	_, onErrPolicyErr := playbook.ParseOnErrorPolicy("bogus-policy")
	_, secretRefErr := secret.NewRef("", "ssh-key")
	_, riskErr := security.ParseRiskLevel("bogus-risk")

	cases := []crossLayerCase{
		{name: "domain/algebraic", err: durErr, wantZh: []string{"duration 无效", "not-a-duration"}, forbidZh: []string{"algebraic:", "invalid duration: not-a-duration"}},
		{name: "domain/execution", err: dialectErr, wantZh: []string{"launch_dialect 无效", "bogus-dialect"}, forbidZh: []string{"execution:", "invalid launch_dialect"}},
		{name: "domain/fsm", err: fsmErr, wantZh: []string{"无效", "bogus-phase"}, forbidZh: []string{"fsm:", "invalid approval_phase"}},
		{name: "domain/inventory", err: hostIDErr, wantZh: []string{"无效", "bad/host"}, forbidZh: []string{"inventory:", "invalid host_id"}},
		{name: "domain/netaddr", err: hostPortErr, wantZh: []string{"地址 missing-port-host 必须符合"}, forbidZh: []string{"netaddr:", "must be in"}},
		{name: "domain/option", err: originErr, wantZh: []string{"未知的 origin", "bogus-origin"}, forbidZh: []string{"option:", "unknown origin"}},
		{name: "domain/pathalg", err: remotePathErr, wantZh: []string{"控制字符"}, forbidZh: []string{"pathalg:", "control characters"}},
		{name: "domain/plan", err: digestErr, wantZh: []string{"无效", "not-a-digest"}, forbidZh: []string{"plan:", "invalid plan_digest"}},
		{name: "domain/playbook", err: onErrPolicyErr, wantZh: []string{"无效", "bogus-policy"}, forbidZh: []string{"playbook:", "invalid on_error"}},
		{name: "domain/secret", err: secretRefErr, wantZh: []string{"store 无效"}, forbidZh: []string{"secret:", "invalid store"}},
		{name: "domain/security", err: riskErr, wantZh: []string{"无效", "bogus-risk"}, forbidZh: []string{"security:", "invalid risk_level"}},
	}
	for _, tc := range cases {
		assertCrossLayerParity(t, tc, enLoc, zhLoc)
	}
}

func assertGateCustomNodeBilingualTemplates(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()

	gateApprovalSentinel := domi18n.Sentinel(domi18n.KeyGateApprovalRequired)
	engineApprovalSentinel := domi18n.Sentinel(domi18n.KeyEngineApprovalReq)
	gatePanicSentinel := domi18n.Sentinel(domi18n.KeyGateOperationPanicked)
	ucAutoUncertain := domi18n.Sentinel(domi18n.KeyUCAutoUncertainOutcome)
	engineOutcomeUnknown := domi18n.Sentinel(domi18n.KeyEngineOutcomeUnknown)

	// 1. 镜像 *gate.ApprovalChallengeError 及其经 engine.mapEngineError 分组折叠链。
	challengeNode := &customLocalizableError{
		sentinel: gateApprovalSentinel,
		msg: domi18n.NewMessage(
			domi18n.KeyGateApprovalChallenge,
			domi18n.Str("op", "op-challenge-01"),
			domi18n.Bool("escalated", true),
			domi18n.BoundStr("reason", "protected_path"),
		),
	}
	mappedChallenge := domi18n.WrapSentinel(engineApprovalSentinel, challengeNode, gateApprovalSentinel)

	// 2. 镜像 *gate.OutcomeError（OutcomeUnknown + ucauto.ErrUncertainOutcome）经 engine.mapEngineError 折叠链。
	outcomeNode := &customLocalizableError{
		msg:   domi18n.NewMessage(domi18n.KeyGateExecutionOutcome, domi18n.Str("outcome", "unknown")),
		cause: domi18n.WrapSentinel(ucAutoUncertain, errors.New("transport reset")),
	}
	mappedOutcome := domi18n.WrapSentinel(engineOutcomeUnknown, outcomeNode, ucAutoUncertain)

	// 3. 镜像 *gate.OperationPanicError 与无效/typed-nil 失败关闭兜底节点。
	panicNode := &customLocalizableError{
		sentinel: gatePanicSentinel,
		msg:      domi18n.NewMessage(domi18n.KeyGateOpPanickedDetail, domi18n.BoundStr("panic", "nil-deref")),
	}
	invalidOutcomeNode := &customLocalizableError{msg: domi18n.NewMessage(domi18n.KeyGateInvalidOutcome)}
	invalidPanicNode := &customLocalizableError{msg: domi18n.NewMessage(domi18n.KeyGateOperationPanicked)}

	cases := []crossLayerCase{
		{
			name:     "gate/ApprovalChallengeError+engine",
			err:      mappedChallenge,
			wantZh:   []string{"操作需要两阶段人工审批确认", "需要人工审批", "op-challenge-01", "protected_path"},
			forbidZh: []string{"engine:", "gate:", "approval challenge required"},
		},
		{
			name:     "gate/OutcomeError+engine",
			err:      mappedOutcome,
			wantZh:   []string{"副作用终态未知", "执行终态=unknown", "transport reset"},
			forbidZh: []string{"engine:", "gate:", "usecase/automation:", "execution outcome="},
		},
		{
			name:     "gate/OperationPanicError",
			err:      panicNode,
			wantZh:   []string{"授权回调发生 panic", "nil-deref"},
			forbidZh: []string{"gate:", "authorized callback panicked"},
		},
		{
			name:     "gate/OutcomeError-invalid",
			err:      invalidOutcomeNode,
			wantZh:   []string{"无效的执行终态"},
			forbidZh: []string{"gate:", "invalid ExecutionOutcome"},
		},
		{
			name:     "gate/OperationPanicError-invalid",
			err:      invalidPanicNode,
			wantZh:   []string{"授权回调发生 panic"},
			forbidZh: []string{"gate:", "authorized callback panicked"},
		},
	}
	for _, tc := range cases {
		assertCrossLayerParity(t, tc, enLoc, zhLoc)
	}
}

type crossLayerCase struct {
	name     string
	err      error
	wantZh   []string
	forbidZh []string
}

func assertCrossLayerParity(t *testing.T, tc crossLayerCase, enLoc, zhLoc *Localizer) {
	t.Helper()
	if tc.err == nil {
		t.Fatalf("%s: 期望非 nil 错误", tc.name)
	}
	enText := enLoc.RenderError(tc.err)
	if enText != tc.err.Error() {
		t.Fatalf("%s: EN RenderError 与 err.Error() 不等价:\nRenderError: %q\nerr.Error(): %q", tc.name, enText, tc.err.Error())
	}
	if containsForbiddenCJKRune(enText) {
		t.Fatalf("%s: EN 输出不得包含 CJK/全角字符: %q", tc.name, enText)
	}

	zhText := zhLoc.RenderError(tc.err)
	if !containsHanRune(zhText) {
		t.Fatalf("%s: ZH 输出应为自然简体中文（缺少汉字）: %q", tc.name, zhText)
	}
	if hasRawPlaceholderToken(zhText) {
		t.Fatalf("%s: ZH 输出残留未替换占位符: %q", tc.name, zhText)
	}
	for _, want := range tc.wantZh {
		if !strings.Contains(zhText, want) {
			t.Fatalf("%s: ZH 输出缺少 %q: got=%q", tc.name, want, zhText)
		}
	}
	for _, forbid := range tc.forbidZh {
		if strings.Contains(zhText, forbid) {
			t.Fatalf("%s: ZH 输出泄露英文错误模板 %q: got=%q", tc.name, forbid, zhText)
		}
	}
}

func containsForbiddenCJKRune(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) || (r >= 0x3000 && r <= 0x303F) || (r >= 0xFF00 && r <= 0xFFEF) {
			return true
		}
	}
	return false
}

func containsHanRune(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func hasRawPlaceholderToken(s string) bool {
	for i := range len(s) {
		if s[i] != '{' {
			continue
		}
		if end := strings.IndexByte(s[i+1:], '}'); end > 0 && isPlaceholderIdent(s[i+1:i+1+end]) {
			return true
		}
	}
	return false
}

func isPlaceholderIdent(k string) bool {
	for i := range len(k) {
		c := k[i]
		isValid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
		if !isValid {
			return false
		}
	}
	return len(k) > 0
}
