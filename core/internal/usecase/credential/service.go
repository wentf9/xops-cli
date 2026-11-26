package credential

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// ServiceConfig 定义凭据用例服务 Service 的显式出站依赖配置。
type ServiceConfig struct {
	// Gate 是必填的能力门控授权器（ADR-008：严禁 nil 逃生口）。
	Gate gate.Authorizer
	// Vault 是必填的全作用域凭据存储端口。
	Vault ports.SecretVault
	// VaultControl 可选注入凭据库初始化/解锁/锁定/状态控制端口。
	VaultControl ports.VaultControlPort
	// Store 可选注入资产配置存储端口（执行 VaultSagaFSM、5 位置引用检查与安全删除时必填）。
	Store ports.InventoryStore
	// Interaction 可选注入交互式输入端口（执行 *Interactive 方法时必填）。
	Interaction ports.InteractionPort
	// Clock 是必填的时钟端口（用于事件时间戳与操作耗时统计）。
	Clock ports.Clock
	// Entropy 是必填的显式熵源端口（用于生成 SagaID 与新凭据随机条目名）。
	Entropy ports.Entropy
	// PendingRefs 可选注入运行期活跃 Pending 暂存凭据引用源（与 SecretLocPending 联动防 GC 误删）。
	PendingRefs PendingSecretRefProvider
}

// Service 是 XOps v2 凭据库生命周期、作用域借用与 VaultSagaFSM 编排用例服务；
// 零值恒未初始化并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Service struct {
	gate         gate.Authorizer
	vault        ports.SecretVault
	vaultControl ports.VaultControlPort
	store        ports.InventoryStore
	interaction  ports.InteractionPort
	clock        ports.Clock
	entropy      ports.Entropy
	pendingRefs  PendingSecretRefProvider
	valid        bool
}

// NewService 校验必填出站依赖（Gate、Vault、Clock、Entropy）并构造凭据用例服务 Service。
func NewService(cfg ServiceConfig) (*Service, error) {
	switch {
	case cfg.Gate == nil:
		return nil, fmt.Errorf("%w: Gate 授权器不能为 nil", ErrInvalidConfig)
	case cfg.Vault == nil:
		return nil, fmt.Errorf("%w: Vault 凭据端口不能为 nil", ErrInvalidConfig)
	case cfg.Clock == nil:
		return nil, fmt.Errorf("%w: Clock 时钟端口不能为 nil", ErrInvalidConfig)
	case cfg.Entropy == nil:
		return nil, fmt.Errorf("%w: Entropy 熵源端口不能为 nil", ErrInvalidConfig)
	}
	return &Service{
		gate:         cfg.Gate,
		vault:        cfg.Vault,
		vaultControl: cfg.VaultControl,
		store:        cfg.Store,
		interaction:  cfg.Interaction,
		clock:        cfg.Clock,
		entropy:      cfg.Entropy,
		pendingRefs:  cfg.PendingRefs,
		valid:        true,
	}, nil
}

// StatusRequest 描述查询凭据库状态的只读授权请求。
type StatusRequest struct {
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// VaultControlRequest 描述凭据库初始化、解锁或锁定操作的授权请求（绝不含明文）。
type VaultControlRequest struct {
	ScopeSummary    string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// InteractiveVaultControlRequest 描述经 InteractionPort.PromptSecret 采集主口令的凭据库控制请求。
type InteractiveVaultControlRequest struct {
	// Prompt 是首次主口令输入提示规格。
	Prompt ports.SecretPromptRequest
	// ConfirmPrompt 可选二次确认提示规格（仅 InitInteractive 使用，非零值时执行常量时间 Equal 核验）。
	ConfirmPrompt   algebraic.Option[ports.SecretPromptRequest]
	ScopeSummary    string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// WithSecretRequest 描述单次全作用域借用 *secret.SecretBox 的授权请求。
type WithSecretRequest struct {
	// Ref 是目标凭据的非敏感逻辑引用（<store>/<item>）。
	Ref             secret.Ref
	NodeID          string
	ScopeSummary    string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// Status 经 CapInspect 鉴权查询凭据库当前生命周期状态（Uninitialized / Locked / Unlocked）。
func (s *Service) Status(ctx context.Context, req StatusRequest) (ports.VaultStatus, error) {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateControlCall(ctx, req.Risk); err != nil {
		return zeroVal[ports.VaultStatus](), err
	}
	gateReq, err := buildInspectGateRequest("vault_status", "", nil, req.Risk.OrElse(security.RiskSafe), "inspect vault status", req.Approval, req.OperationStream)
	if err != nil {
		return zeroVal[ports.VaultStatus](), fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var out ports.VaultStatus
	err = gate.WithAuthorized[security.CapInspect](ctx, s.gate, gateReq, func(authCtx context.Context, _ gate.Authorized[security.CapInspect]) error {
		st, stErr := s.vaultControl.Status(authCtx)
		if stErr != nil {
			return stErr
		}
		out = st
		return nil
	})
	if err != nil {
		return zeroVal[ports.VaultStatus](), err
	}
	return out, nil
}

// Init 经 CapMutate 鉴权并使用借用主口令 SecretBox 初始化凭据库（零逃逸、零明文消费）。
func (s *Service) Init(
	ctx context.Context,
	req VaultControlRequest,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateControlCall(ctx, req.Risk); err != nil {
		return err
	}
	if !pass.IsValid() {
		return ErrInvalidSecretBox
	}
	return s.runVaultControlMutation(ctx, "vault_init", req, func(authCtx context.Context) error {
		return s.vaultControl.Init(authCtx, pass)
	})
}

// InitFromBytes 通过 secret.WithBytes 深拷贝并立即清零 raw 后初始化凭据库（无论成败均清零 raw）。
func (s *Service) InitFromBytes(ctx context.Context, req VaultControlRequest, raw []byte) error {
	return secret.WithBytes(raw, func(box *secret.SecretBox) error {
		return s.Init(ctx, req, box)
	})
}

// InitInteractive 通过 InteractionPort.PromptSecret 采集主口令（可选二次常量时间 Equal 确认）并初始化凭据库。
func (s *Service) InitInteractive(ctx context.Context, req InteractiveVaultControlRequest) error {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateInteractiveControlCall(ctx, req); err != nil {
		return err
	}
	ctrlReq := VaultControlRequest{
		ScopeSummary:    req.ScopeSummary,
		Risk:            req.Risk,
		Approval:        req.Approval,
		OperationStream: req.OperationStream,
	}
	return s.runVaultControlMutation(ctx, "vault_init", ctrlReq, func(authCtx context.Context) error {
		return s.interaction.PromptSecret(authCtx, req.Prompt, func(first *secret.SecretBox) error {
			if confirmReq, hasConfirm := req.ConfirmPrompt.Get(); hasConfirm {
				return s.confirmAndInitVault(authCtx, confirmReq, first)
			}
			return s.vaultControl.Init(authCtx, first)
		})
	})
}

func (s *Service) confirmAndInitVault(
	ctx context.Context,
	confirmReq ports.SecretPromptRequest,
	//xops:borrowed
	first *secret.SecretBox,
) error {
	return s.interaction.PromptSecret(ctx, confirmReq, func(second *secret.SecretBox) error {
		if !first.Equal(second) {
			return ErrPassphraseConfirmMismatch
		}
		return s.vaultControl.Init(ctx, first)
	})
}

// Unlock 经 CapMutate 鉴权并使用借用主口令 SecretBox 解锁凭据库（零逃逸、零明文消费）。
func (s *Service) Unlock(
	ctx context.Context,
	req VaultControlRequest,
	//xops:borrowed
	pass *secret.SecretBox,
) error {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateControlCall(ctx, req.Risk); err != nil {
		return err
	}
	if !pass.IsValid() {
		return ErrInvalidSecretBox
	}
	return s.runVaultControlMutation(ctx, "vault_unlock", req, func(authCtx context.Context) error {
		return s.vaultControl.Unlock(authCtx, pass)
	})
}

// UnlockFromBytes 通过 secret.WithBytes 深拷贝并立即清零 raw 后解锁凭据库。
func (s *Service) UnlockFromBytes(ctx context.Context, req VaultControlRequest, raw []byte) error {
	return secret.WithBytes(raw, func(box *secret.SecretBox) error {
		return s.Unlock(ctx, req, box)
	})
}

// UnlockInteractive 通过 InteractionPort.PromptSecret 采集主口令并解锁凭据库。
func (s *Service) UnlockInteractive(ctx context.Context, req InteractiveVaultControlRequest) error {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateInteractiveControlCall(ctx, req); err != nil {
		return err
	}
	ctrlReq := VaultControlRequest{
		ScopeSummary:    req.ScopeSummary,
		Risk:            req.Risk,
		Approval:        req.Approval,
		OperationStream: req.OperationStream,
	}
	return s.runVaultControlMutation(ctx, "vault_unlock", ctrlReq, func(authCtx context.Context) error {
		return s.interaction.PromptSecret(authCtx, req.Prompt, func(pass *secret.SecretBox) error {
			return s.vaultControl.Unlock(authCtx, pass)
		})
	})
}

// Lock 经 CapMutate 鉴权锁定凭据库。
func (s *Service) Lock(ctx context.Context, req VaultControlRequest) error {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateControlCall(ctx, req.Risk); err != nil {
		return err
	}
	return s.runVaultControlMutation(ctx, "vault_lock", req, func(authCtx context.Context) error {
		return s.vaultControl.Lock(authCtx)
	})
}

// WithSecret 经 CapInspect 鉴权并在同步闭包内借出 *secret.SecretBox；
// 回调返回后由底层 SecretVault 无条件清零，严禁将 box 逃逸出闭包。
//
//xops:syncclosure
//xops:borrowed
func (s *Service) WithSecret(ctx context.Context, req WithSecretRequest, fn func(box *secret.SecretBox) error) error {
	if req.OperationStream != nil {
		defer req.OperationStream.Close()
	}
	if err := s.validateBaseCall(ctx, req.Risk); err != nil {
		return err
	}
	if fn == nil {
		return ErrNilCallback
	}
	if !req.Ref.IsValid() {
		return fmt.Errorf("%w: Ref 无效", ErrInvalidRequest)
	}
	summary := pickIf(req.ScopeSummary != "", req.ScopeSummary, "with secret "+req.Ref.String())
	gateReq, err := buildInspectGateRequest(
		"vault_with_secret",
		req.NodeID,
		map[string]string{"secret_ref": req.Ref.String()},
		req.Risk.OrElse(security.RiskModerate),
		summary,
		req.Approval,
		req.OperationStream,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return gate.WithAuthorized[security.CapInspect](ctx, s.gate, gateReq, func(authCtx context.Context, _ gate.Authorized[security.CapInspect]) error {
		return s.vault.WithSecret(authCtx, req.Ref, func(box *secret.SecretBox) error {
			return fn(box)
		})
	})
}

// WithPromptedSecret 通过 InteractionPort.PromptSecret 以全作用域闭包借出用户交互输入的 *secret.SecretBox；
// 退出后无条件清零，零命令式 *SecretBox 返回。
//
//xops:syncclosure
//xops:borrowed
func (s *Service) WithPromptedSecret(ctx context.Context, prompt ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	if err := s.validateInteractionCall(ctx, prompt); err != nil {
		return err
	}
	if fn == nil {
		return ErrNilCallback
	}
	return s.interaction.PromptSecret(ctx, prompt, func(box *secret.SecretBox) error {
		return fn(box)
	})
}

func (s *Service) allocateRandomRef(storeID string) (secret.Ref, error) {
	var raw [randomSecretItemBytes]byte
	if _, err := io.ReadFull(s.entropy, raw[:]); err != nil {
		return zeroVal[secret.Ref](), fmt.Errorf("%w: 生成随机凭据条目失败: %w", ports.ErrEntropyShortRead, err)
	}
	return secret.NewRef(storeID, "sec-"+hex.EncodeToString(raw[:]))
}

func (s *Service) collectPendingRefs(extra []inventory.PendingSecretRef) ([]inventory.PendingSecretRef, error) {
	var live []inventory.PendingSecretRef
	if s.pendingRefs != nil {
		live = s.pendingRefs.ActivePendingSecretRefs()
	}
	out := make([]inventory.PendingSecretRef, 0, len(live)+len(extra))
	for _, group := range [2][]inventory.PendingSecretRef{live, extra} {
		for _, p := range group {
			if !p.Ref.IsValid() {
				return nil, fmt.Errorf("%w: 存在无效 PendingSecretRef", ErrInvalidRequest)
			}
			out = append(out, p)
		}
	}
	return out, nil
}
