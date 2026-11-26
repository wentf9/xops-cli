package credential

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// DoctorSeverity 表示凭据诊断告警严重级别；零值 DoctorSeverityInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type DoctorSeverity uint8

const (
	DoctorSeverityInvalid DoctorSeverity = iota // 无效级别（零值失败关闭）
	DoctorSeverityInfo                          // 提示信息
	DoctorSeverityWarn                          // 告警（如凭据库锁定）
	DoctorSeverityError                         // 严重错误（如凭据缺失/损坏/未知存储）
)

// IsValid 报告诊断级别是否有效。
func (s DoctorSeverity) IsValid() bool { return s >= DoctorSeverityInfo && s <= DoctorSeverityError }

// IsZero 报告诊断级别是否处于零值无效态。
func (s DoctorSeverity) IsZero() bool { return s == DoctorSeverityInvalid }

// String 返回诊断级别规范名称。
func (s DoctorSeverity) String() string {
	switch s {
	case DoctorSeverityInfo:
		return "info"
	case DoctorSeverityWarn:
		return "warn"
	case DoctorSeverityError:
		return "error"
	default:
		return "invalid"
	}
}

// AppendText 实现 encoding.TextAppender（值接收者），零值失败关闭。
func (s DoctorSeverity) AppendText(b []byte) ([]byte, error) {
	if !s.IsValid() {
		return nil, fmt.Errorf("%w: 无效 DoctorSeverity=%d", ErrInvalidRequest, uint8(s))
	}
	return append(b, s.String()...), nil
}

// ParseDoctorSeverity 严格解析规范小写诊断严重级别（"info"、"warn"、"error"），非法输入失败关闭返回 DoctorSeverityInvalid。
func ParseDoctorSeverity(raw string) (DoctorSeverity, error) {
	switch strings.TrimSpace(raw) {
	case "info":
		return DoctorSeverityInfo, nil
	case "warn":
		return DoctorSeverityWarn, nil
	case "error":
		return DoctorSeverityError, nil
	default:
		return DoctorSeverityInvalid, fmt.Errorf("%w: 无效 DoctorSeverity %q", ErrInvalidRequest, raw)
	}
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (s DoctorSeverity) MarshalText() ([]byte, error) { return s.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；非法文本时失败关闭将接收者归零为 DoctorSeverityInvalid。
func (s *DoctorSeverity) UnmarshalText(text []byte) error {
	if s == nil {
		return fmt.Errorf("%w: DoctorSeverity 接收者不能为 nil", ErrInvalidRequest)
	}
	parsed, err := ParseDoctorSeverity(string(text))
	if err != nil {
		*s = DoctorSeverityInvalid
		return err
	}
	*s = parsed
	return nil
}

// DoctorFinding 描述单条凭据健康诊断发现（仅含脱敏元数据，严禁包含任何明文）。
type DoctorFinding struct {
	Severity DoctorSeverity `json:"severity"`
	Code     string         `json:"code"`
	Subject  string         `json:"subject,omitzero"`
	Message  string         `json:"message"`
}

// DoctorRequest 描述只读凭据系统诊断请求。
type DoctorRequest struct {
	// SkipSecretProbe 为 true 时仅检查 Vault 状态与存储注册表，不对已解锁 Vault 逐条探活。
	SkipSecretProbe bool
	ExtraPending    []inventory.PendingSecretRef
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// DoctorReport 封装凭据系统只读诊断报告（零明文、零副作用）。
type DoctorReport struct {
	Healthy            bool                                `json:"healthy"`
	VaultStatus        algebraic.Option[ports.VaultStatus] `json:"vault_status,omitzero"`
	ReferencedCount    int                                 `json:"referenced_count"`
	DistinctRefCount   int                                 `json:"distinct_ref_count"`
	ActivePendingCount int                                 `json:"active_pending_count"`
	Findings           []DoctorFinding                     `json:"findings,omitzero"`
}

type vaultDoctorState struct {
	knownStores []string
	unlocked    bool
}

// Doctor 经 CapInspect 鉴权执行严格只读凭据系统诊断（不修改存储、不调用 box.Use、不泄露明文）。
func (s *Service) Doctor(ctx context.Context, req DoctorRequest) (DoctorReport, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateBaseCall(ctx, req.Risk); err != nil {
		return DoctorReport{}, err
	}
	gateReq, err := buildInspectGateRequest("vault_doctor", "", nil, req.Risk.OrElse(security.RiskSafe), "credential doctor", req.Approval, req.OperationStream)
	if err != nil {
		return DoctorReport{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var rep DoctorReport
	err = gate.WithAuthorized[security.CapInspect](ctx, s.gate, gateReq, func(authCtx context.Context, _ gate.Authorized[security.CapInspect]) error {
		var runErr error
		rep, runErr = s.runDoctor(authCtx, req)
		return runErr
	})
	return rep, err
}

// VaultSecretCheckSpec 定义共享只读 Vault 状态、存储注册表与凭据探活检查的入参规格（供 credential 与 inventory 复用）。
type VaultSecretCheckSpec struct {
	Vault            ports.SecretVault
	VaultControl     ports.VaultControlPort
	AllRefs          []inventory.SecretReference
	GraphKnownStores []string
	ExtraKnownStores []string
	ProbeSecrets     bool
}

// VaultSecretCheckResult 封装共享只读 Vault 与凭据诊断结果（零明文、零副作用）。
type VaultSecretCheckResult struct {
	VaultStatus algebraic.Option[ports.VaultStatus]
	Findings    []DoctorFinding
}

// InspectVaultAndSecrets 执行只读 Vault 生命周期检查、权威存储注册表核验与可选 SecretVault.WithSecret 零明文探活。
// 权威 KnownStores 基线优先取实时 VaultStatus 与 ExtraKnownStores；绝不将陈旧 GraphKnownStores 并入实时基线，
// 仅在不存在实时存储源时才回退使用 GraphKnownStores，确保已下线存储的 unknown_secret_store 告警可达。
func InspectVaultAndSecrets(ctx context.Context, spec VaultSecretCheckSpec) VaultSecretCheckResult {
	var res VaultSecretCheckResult
	vState := checkVaultControlStatus(ctx, spec.VaultControl, spec.Vault != nil, &res)
	authoritativeStores := MergeSortedUniqueStrings(spec.ExtraKnownStores, vState.knownStores)
	if len(authoritativeStores) == 0 {
		authoritativeStores = MergeSortedUniqueStrings(spec.GraphKnownStores, nil)
	}
	checkUnknownSecretStores(spec.AllRefs, authoritativeStores, &res)
	if !spec.ProbeSecrets {
		return res
	}
	if spec.Vault == nil {
		appendVaultFinding(&res, DoctorSeverityWarn, "vault_unavailable", "", "未配置 SecretVault，无法执行凭据只读探活")
		return res
	}
	if vState.unlocked {
		probeDistinctSecrets(ctx, spec.Vault, collectDistinctRefs(spec.AllRefs), &res)
	}
	return res
}

func (s *Service) runDoctor(ctx context.Context, req DoctorRequest) (DoctorReport, error) {
	rep := DoctorReport{Healthy: true}
	pending, err := s.collectPendingRefs(req.ExtraPending)
	if err != nil {
		return DoctorReport{}, err
	}
	rep.ActivePendingCount = len(pending)
	allRefs, graphStores := s.doctorLoadGraphRefs(ctx, pending, &rep)
	rep.ReferencedCount = len(allRefs)
	rep.DistinctRefCount = len(collectDistinctRefs(allRefs))

	checkRes := InspectVaultAndSecrets(ctx, VaultSecretCheckSpec{
		Vault:            s.vault,
		VaultControl:     s.vaultControl,
		AllRefs:          allRefs,
		GraphKnownStores: graphStores,
		ProbeSecrets:     !req.SkipSecretProbe,
	})
	rep.VaultStatus = checkRes.VaultStatus
	for _, f := range checkRes.Findings {
		rep.Findings = append(rep.Findings, f)
		if f.Severity == DoctorSeverityError {
			rep.Healthy = false
		}
	}
	return rep, nil
}

func checkVaultControlStatus(ctx context.Context, ctrl ports.VaultControlPort, hasVault bool, res *VaultSecretCheckResult) vaultDoctorState {
	if ctrl == nil {
		return vaultDoctorState{unlocked: hasVault}
	}
	st, err := ctrl.Status(ctx)
	if err != nil {
		appendVaultFinding(res, DoctorSeverityError, "vault_status_failed", "", "查询凭据库状态失败: "+err.Error())
		return vaultDoctorState{}
	}
	res.VaultStatus = algebraic.Some(st)
	switch st.State() {
	case ports.VaultStateUnlocked:
		return vaultDoctorState{knownStores: st.KnownStores(), unlocked: true}
	case ports.VaultStateLocked:
		appendVaultFinding(res, DoctorSeverityWarn, "vault_locked", "", "凭据库处于锁定状态，跳过凭据条目只读探活")
		return vaultDoctorState{knownStores: st.KnownStores()}
	case ports.VaultStateUninitialized:
		appendVaultFinding(res, DoctorSeverityWarn, "vault_uninitialized", "", "凭据库尚未初始化")
		return vaultDoctorState{knownStores: st.KnownStores()}
	default:
		appendVaultFinding(res, DoctorSeverityError, "vault_state_invalid", "", "凭据库返回无效状态")
		return vaultDoctorState{}
	}
}

func (s *Service) doctorLoadGraphRefs(
	ctx context.Context,
	pending []inventory.PendingSecretRef,
	rep *DoctorReport,
) ([]inventory.SecretReference, []string) {
	if s.store == nil {
		return pendingToSecretRefs(pending), nil
	}
	snap, err := s.store.Load(ctx)
	if err != nil {
		addDoctorFinding(rep, DoctorSeverityError, "store_load_failed", "", "加载资产图失败: "+err.Error())
		// 存储加载失败时仍保留活跃 Pending 凭据引用参与后续存储白名单与只读探活诊断。
		return pendingToSecretRefs(pending), nil
	}
	return snap.Graph().AllSecretReferences(pending...), snap.Graph().KnownStores()
}

func pendingToSecretRefs(pending []inventory.PendingSecretRef) []inventory.SecretReference {
	if len(pending) == 0 {
		return nil
	}
	out := make([]inventory.SecretReference, 0, len(pending))
	for _, p := range pending {
		out = append(out, inventory.SecretReference{Location: inventory.SecretLocPending, OwnerID: p.OwnerID, Ref: p.Ref})
	}
	return out
}

func checkUnknownSecretStores(allRefs []inventory.SecretReference, knownStores []string, res *VaultSecretCheckResult) {
	if len(knownStores) == 0 {
		return
	}
	for _, sr := range allRefs {
		if !slices.Contains(knownStores, sr.Ref.Store()) {
			appendVaultFinding(res, DoctorSeverityError, "unknown_secret_store", sr.Ref.String(),
				fmt.Sprintf("%s (%s) 引用了未注册凭据存储 %q", sr.OwnerID, sr.Location, sr.Ref.Store()))
		}
	}
}

func probeDistinctSecrets(ctx context.Context, vault ports.SecretVault, distinct []secret.Ref, res *VaultSecretCheckResult) {
	for _, ref := range distinct {
		err := vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			if !box.IsValid() {
				return ports.ErrCorruptData
			}
			return nil
		})
		switch {
		case err == nil:
		case errors.Is(err, ports.ErrSecretNotFound):
			appendVaultFinding(res, DoctorSeverityError, "secret_not_found", ref.String(), "凭据库中缺少被引用的凭据条目")
		case errors.Is(err, ports.ErrVaultLocked):
			appendVaultFinding(res, DoctorSeverityWarn, "vault_locked", ref.String(), "凭据库已锁定，无法探活条目")
		default:
			appendVaultFinding(res, DoctorSeverityError, "secret_probe_failed", ref.String(), "凭据只读探活失败: "+err.Error())
		}
	}
}

func appendVaultFinding(res *VaultSecretCheckResult, sev DoctorSeverity, code, subject, msg string) {
	res.Findings = append(res.Findings, DoctorFinding{
		Severity: sev,
		Code:     code,
		Subject:  subject,
		Message:  security.SanitizePromptText(msg),
	})
}

func addDoctorFinding(rep *DoctorReport, sev DoctorSeverity, code, subject, msg string) {
	rep.Findings = append(rep.Findings, DoctorFinding{
		Severity: sev,
		Code:     code,
		Subject:  subject,
		Message:  security.SanitizePromptText(msg),
	})
	if sev == DoctorSeverityError {
		rep.Healthy = false
	}
}

func collectDistinctRefs(all []inventory.SecretReference) []secret.Ref {
	if len(all) == 0 {
		return nil
	}
	out := make([]secret.Ref, 0, len(all))
	for _, sr := range all {
		out = append(out, sr.Ref)
	}
	slices.SortFunc(out, secret.Ref.Compare)
	return slices.CompactFunc(out, secret.Ref.Equal)
}

// MergeSortedUniqueStrings 合并两个字符串切片并按字典序排序去重（供 credential 与 inventory 共享权威存储表归一化）。
func MergeSortedUniqueStrings(a, b []string) []string {
	out := slices.Concat(a, b)
	if len(out) == 0 {
		return nil
	}
	slices.SortFunc(out, cmp.Compare[string])
	return slices.Compact(out)
}
