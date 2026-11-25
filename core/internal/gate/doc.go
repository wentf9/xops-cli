// Package gate 实现 XOps v2 独占能力证明 Authorized[C]、包级泛型作用域门控
// WithAuthorized[C]、两阶段审批信封核验、启动期崩溃审计对账入口以及 StrictAgentProfile
// 不可逆 Halted 熔断器（ADR-008 / ADR-009 / ADR-010 / ADR-011 / ADR-016）。
//
// 核心架构与安全不变量：
//   - 编译期物理封锁能力证明（ADR-008 / RFC §3.1）：Authorized[C] 直接定义于本包，
//     全字段私有且同时内置正向有效门控 valid bool 与失效哨兵 revoked *atomic.Bool；
//     Authorizer 接口通过未导出方法物理封闭于本包，全仓除本包外任何模块均无法伪造授权句柄或绕过护栏。
//   - 全作用域借用与零孤儿审计（Plan §4.4 / ADR-011）：WithAuthorized[C] 显式标注
//     //xops:syncclosure 与 //xops:borrowed，严格按
//     Stage(+opID) -> Audit(Authorized) -> run(ctx, auth) -> Audit(Finalized) -> Unstage(-opID)
//     顺序推进；无论正常返回、业务错误、上下文取消、panic 还是 runtime.Goexit，
//     回调退出瞬间即吊销 auth 并以 context.WithoutCancel 闭合终态审计，严禁将 OutcomeUnknown
//     降级为 AuditOutcomeFailed。
//   - 严格六边形解耦与熔断（ADR-008 / ADR-009）：本包严禁导入 core/internal/pool、
//     core/osfs 或 core/internal/sshnet/**；StrictAgentProfile 下捕获 AuditPostWriteError
//     （或任意终态审计落盘失败）立即不可逆进入 Halted 态、吊销全部在途句柄、拒绝一切新请求，
//     并在锁外经 sync.Once 线性化触发出站回调 OnHaltFunc 通知连接池吊销全部 ManagedHandle。
package gate

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	maxReasonBytes          = 512
	maxSummaryBytes         = 512
	maxAuditErrorCodeLen    = 64
	defaultPendingCapacity  = 256
	defaultReplayHistoryCap = 4096
	defaultApprovalTTL      = 5 * time.Minute
	maxApprovalTTL          = 24 * time.Hour
)

// 本包导出的不可变哨兵错误，供用例服务、MCP 运行时、仿真器与测试通过 errors.Is 精确匹配。
var (
	ErrNilContext            = errors.New("gate: context 不能为 nil")
	ErrNilAuthorizer         = errors.New("gate: Authorizer 不能为 nil")
	ErrNilCallback           = errors.New("gate: WithAuthorized 回调函数不能为 nil")
	ErrInvalidConfig         = errors.New("gate: 无效的 GateConfig 配置")
	ErrInvalidPolicy         = errors.New("gate: 无效的 GuardrailPolicy 护栏策略")
	ErrInvalidProfile        = errors.New("gate: 无效的 PolicyProfileKind 策略配置档")
	ErrInvalidFallback       = errors.New("gate: 无效的 NoElicitFallback 不可交互回退策略")
	ErrInvalidRequest        = errors.New("gate: 无效的 GateRequest 授权请求")
	ErrInvalidOutcome        = errors.New("gate: 无效的 ExecutionOutcome 执行结果")
	ErrCapabilityMismatch    = errors.New("gate: 幻影能力类型 C 与 OperationBinding.Capability 不匹配或无效")
	ErrGateNotInitialized    = errors.New("gate: Gate 未经有效初始化")
	ErrGateHalted            = errors.New("gate: Gate 已进入不可逆 Halted 熔断态")
	ErrInvalidPermit         = errors.New("gate: Authorized 能力证明无效或未初始化")
	ErrPermitRevoked         = errors.New("gate: Authorized 能力证明已吊销或超出借用作用域")
	ErrAuthorizationDenied   = errors.New("gate: 安全护栏策略拒绝该操作")
	ErrApprovalRequired      = errors.New("gate: 操作需要用户显式审批挑战")
	ErrApprovalRejected      = errors.New("gate: 用户拒绝了审批挑战")
	ErrApprovalExpired       = errors.New("gate: 审批挑战信封已过期或尚未生效")
	ErrApprovalReplayed      = errors.New("gate: 审批挑战信封或 Nonce 已被消费，禁止重放")
	ErrApprovalMismatch      = errors.New("gate: 审批挑战信封与操作标识、能力或绑定作用域不匹配")
	ErrApprovalInvalidated   = errors.New("gate: 审批挑战令牌已作废")
	ErrPendingLimitExceeded  = errors.New("gate: 活跃待审批挑战数量已达上限")
	ErrScopeEscalated        = errors.New("gate: 规范化阶段检测到安全作用域升级或受保护路径重定向")
	ErrAuditStageFailed      = errors.New("gate: 只追加审计操作登记 StageOperation 失败")
	ErrAuditPreWriteFailed   = errors.New("gate: 前置审计记录落盘失败，拒绝执行副作用")
	ErrAuditUnstageFailed    = errors.New("gate: 终态闭合后注销登记 UnstageOperation 失败")
	ErrReconcilerUnavailable = errors.New("gate: 未配置 AuditReconciler 启动期崩溃对账端口")
	ErrOperationPanicked     = errors.New("gate: 授权回调执行期间发生 panic")
	ErrOperationAborted      = errors.New("gate: 授权回调异常中止（如 runtime.Goexit）")
)

func zeroVal[T any]() (z T) { return z }

func isValidRFC3339Time(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	y := t.UTC().Year()
	return y >= 1 && y <= 9999
}

func optInvalid[T interface{ IsValid() bool }](opt algebraic.Option[T]) bool {
	v, ok := opt.Get()
	return ok && !v.IsValid()
}

func sanitizeReason(raw, fallback string) string {
	cleaned := strings.TrimSpace(security.SanitizePromptText(raw))
	if cleaned == "" {
		return fallback
	}
	return truncateUTF8(cleaned, maxReasonBytes)
}

func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// normalizeAuditErrorCode 将领域执行结果码规范化为满足 ports.NewAuditEntry 约束（可打印非空 ASCII 0x21..0x7E，
// 最长 64 字节）的安全错误码，避免 128 字节合法领域 OutcomeUnknown.Code() 触发审计条目构造失败或误熔断。
func normalizeAuditErrorCode(raw, fallback string) string {
	if raw == "" {
		return fallback
	}
	var buf [maxAuditErrorCodeLen]byte
	n := 0
	for i := 0; i < len(raw) && n < maxAuditErrorCodeLen; i++ {
		if b := raw[i]; b >= 0x21 && b <= 0x7E {
			buf[n] = b
			n++
		}
	}
	if n == 0 {
		return fallback
	}
	return string(buf[:n])
}
