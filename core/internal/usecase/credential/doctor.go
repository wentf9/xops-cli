package credential

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

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

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (s DoctorSeverity) MarshalText() ([]byte, error) { return s.AppendText(nil) }

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

func (s *Service) runDoctor(ctx context.Context, req DoctorRequest) (DoctorReport, error) {
	rep := DoctorReport{Healthy: true}
	vState := s.doctorCheckVaultStatus(ctx, &rep)
	pending, err := s.collectPendingRefs(req.ExtraPending)
	if err != nil {
		return DoctorReport{}, err
	}
	rep.ActivePendingCount = len(pending)
	allRefs, graphStores := s.doctorLoadGraphRefs(ctx, pending, &rep)
	knownStores := mergeSortedUniqueStrings(vState.knownStores, graphStores)
	rep.ReferencedCount = len(allRefs)

	distinct := collectDistinctRefs(allRefs)
	rep.DistinctRefCount = len(distinct)
	doctorCheckUnknownStores(allRefs, knownStores, &rep)
	if !req.SkipSecretProbe && vState.unlocked {
		s.doctorProbeSecrets(ctx, distinct, &rep)
	}
	return rep, nil
}

func (s *Service) doctorCheckVaultStatus(ctx context.Context, rep *DoctorReport) vaultDoctorState {
	if s.vaultControl == nil {
		return vaultDoctorState{unlocked: true}
	}
	st, err := s.vaultControl.Status(ctx)
	if err != nil {
		addDoctorFinding(rep, DoctorSeverityError, "vault_status_failed", "", "查询凭据库状态失败: "+err.Error())
		return vaultDoctorState{}
	}
	rep.VaultStatus = algebraic.Some(st)
	switch st.State() {
	case ports.VaultStateUnlocked:
		return vaultDoctorState{knownStores: st.KnownStores(), unlocked: true}
	case ports.VaultStateLocked:
		addDoctorFinding(rep, DoctorSeverityWarn, "vault_locked", "", "凭据库处于锁定状态，跳过凭据条目只读探活")
		return vaultDoctorState{knownStores: st.KnownStores()}
	case ports.VaultStateUninitialized:
		addDoctorFinding(rep, DoctorSeverityWarn, "vault_uninitialized", "", "凭据库尚未初始化")
		return vaultDoctorState{knownStores: st.KnownStores()}
	default:
		addDoctorFinding(rep, DoctorSeverityError, "vault_state_invalid", "", "凭据库返回无效状态")
		return vaultDoctorState{}
	}
}

func (s *Service) doctorLoadGraphRefs(
	ctx context.Context,
	pending []inventory.PendingSecretRef,
	rep *DoctorReport,
) ([]inventory.SecretReference, []string) {
	if s.store == nil {
		out := make([]inventory.SecretReference, 0, len(pending))
		for _, p := range pending {
			out = append(out, inventory.SecretReference{Location: inventory.SecretLocPending, OwnerID: p.OwnerID, Ref: p.Ref})
		}
		return out, nil
	}
	snap, err := s.store.Load(ctx)
	if err != nil {
		addDoctorFinding(rep, DoctorSeverityError, "store_load_failed", "", "加载资产图失败: "+err.Error())
		return nil, nil
	}
	return snap.Graph().AllSecretReferences(pending...), snap.Graph().KnownStores()
}

func doctorCheckUnknownStores(allRefs []inventory.SecretReference, knownStores []string, rep *DoctorReport) {
	if len(knownStores) == 0 {
		return
	}
	for _, sr := range allRefs {
		if !slices.Contains(knownStores, sr.Ref.Store()) {
			addDoctorFinding(rep, DoctorSeverityError, "unknown_secret_store", sr.Ref.String(),
				fmt.Sprintf("%s (%s) 引用了未注册凭据存储 %q", sr.OwnerID, sr.Location, sr.Ref.Store()))
		}
	}
}

func (s *Service) doctorProbeSecrets(ctx context.Context, distinct []secret.Ref, rep *DoctorReport) {
	for _, ref := range distinct {
		err := s.vault.WithSecret(ctx, ref, func(box *secret.SecretBox) error {
			if !box.IsValid() {
				return ports.ErrCorruptData
			}
			return nil
		})
		switch {
		case err == nil:
		case errors.Is(err, ports.ErrSecretNotFound):
			addDoctorFinding(rep, DoctorSeverityError, "secret_not_found", ref.String(), "凭据库中缺少被引用的凭据条目")
		case errors.Is(err, ports.ErrVaultLocked):
			addDoctorFinding(rep, DoctorSeverityWarn, "vault_locked", ref.String(), "凭据库已锁定，无法探活条目")
		default:
			addDoctorFinding(rep, DoctorSeverityError, "secret_probe_failed", ref.String(), "凭据只读探活失败: "+err.Error())
		}
	}
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

func mergeSortedUniqueStrings(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	if len(out) == 0 {
		return nil
	}
	slices.SortFunc(out, cmp.Compare[string])
	return slices.Compact(out)
}
