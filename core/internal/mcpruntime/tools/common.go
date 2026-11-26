package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

func zeroVal[T any]() (z T) { return z }

// decodeToolArgs 严格解码工具 JSON 参数，拒绝空输入与未知字段。
func decodeToolArgs[T any](raw jsontext.Value) (T, error) {
	var out T
	if err := protocol.UnmarshalStrict([]byte(raw), &out); err != nil {
		return zeroVal[T](), err
	}
	return out, nil
}

// resolveTarget 经 InventoryService 解析目标串并编译不可变 Merkle 多跳连接计划。
func (r *Registry) resolveTarget(ctx context.Context, target string, cliOpts option.OptionLayer) (ucinv.ResolvedTarget, error) {
	if r.inventory == nil {
		return zeroVal[ucinv.ResolvedTarget](), fmt.Errorf("%w: InventoryService 未配置", ErrServiceUnavailable)
	}
	if strings.TrimSpace(target) == "" {
		return zeroVal[ucinv.ResolvedTarget](), fmt.Errorf("%w: target 不能为空", protocol.ErrInvalidParams)
	}
	return r.inventory.ResolveTarget(ctx, ucinv.ResolveTargetRequest{
		Target:     target,
		CLIOptions: cliOpts,
	})
}

func (r *Registry) buildTransferCallBase(
	ctx context.Context,
	target string,
	riskRaw algebraic.Option[security.RiskLevel],
	approvalDTO algebraic.Option[protocol.ApprovalSubmissionDTO],
) (uctrans.CallBase, error) {
	resolved, err := r.resolveTarget(ctx, target, option.UnsetOptionLayer())
	if err != nil {
		return uctrans.CallBase{}, err
	}
	approval, err := protocol.DecodeApprovalSubmission(approvalDTO)
	if err != nil {
		return uctrans.CallBase{}, err
	}
	return uctrans.CallBase{
		Plan:     resolved.Plan(),
		NodeID:   resolved.NodeID(),
		Risk:     riskRaw,
		Approval: approval,
	}, nil
}

func parseOptionalRevision(raw string) (algebraic.Option[ports.Revision], error) {
	if strings.TrimSpace(raw) == "" {
		return algebraic.None[ports.Revision](), nil
	}
	rev, err := ports.ParseRevision(raw)
	if err != nil {
		return algebraic.None[ports.Revision](), fmt.Errorf("%w: expected_revision 非法: %w", protocol.ErrInvalidParams, err)
	}
	return algebraic.Some(rev), nil
}

func parseOptionalPerm(opt algebraic.Option[uint32]) (algebraic.Option[fs.FileMode], error) {
	v, ok := opt.Get()
	if !ok {
		return algebraic.None[fs.FileMode](), nil
	}
	if v == 0 || v > 0o777 {
		return algebraic.None[fs.FileMode](), fmt.Errorf("%w: perm=%#o 超出 0001..0777", protocol.ErrInvalidParams, v)
	}
	return algebraic.Some(fs.FileMode(v)), nil
}

func decodeBase64Strict(raw string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: Base64 解码失败: %w", protocol.ErrInvalidParams, err)
	}
	return b, nil
}

func decodeTextOrBase64(text algebraic.Option[string], b64 algebraic.Option[string]) ([]byte, error) {
	tVal, hasT := text.Get()
	bVal, hasB := b64.Get()
	if hasT == hasB {
		return nil, fmt.Errorf("%w: 文本字段与 base64 字段必须二选一", protocol.ErrInvalidParams)
	}
	if hasB {
		return decodeBase64Strict(bVal)
	}
	return []byte(tVal), nil
}

func parseRemotePathParam(name, raw string) (pathalg.RemotePath, error) {
	p, err := pathalg.ParseRemotePath(raw)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), fmt.Errorf("%w: %s 非法: %w", protocol.ErrInvalidParams, name, err)
	}
	return p, nil
}

func parseOptionalDigest(raw string) (algebraic.Option[security.Digest], error) {
	if strings.TrimSpace(raw) == "" {
		return algebraic.None[security.Digest](), nil
	}
	d, err := security.ParseDigest(raw)
	if err != nil {
		return algebraic.None[security.Digest](), fmt.Errorf("%w: expected_digest 非法: %w", protocol.ErrInvalidParams, err)
	}
	return algebraic.Some(d), nil
}

// ClearTrackedHandles 在 Gate 进入 Halted 熔断态或运行时停机时清空全部缓存句柄索引。
func (r *Registry) ClearTrackedHandles() {
	if r == nil || !r.valid {
		return
	}
	r.mu.Lock()
	clear(r.ptyHandles)
	clear(r.tunnelHandles)
	clear(r.guiHandles)
	clear(r.muxHandles)
	clear(r.transfers)
	r.mu.Unlock()
}

// LookupTransfer 供 HTTP 10 GiB 流式传输端点按 transfer_id 查询已登记的活跃流式传输绑定。
func (r *Registry) LookupTransfer(id security.OperationID) (TransferBinding, bool) {
	if r == nil || !r.valid || !id.IsValid() || r.gate.IsHalted() {
		return TransferBinding{}, false
	}
	r.mu.Lock()
	b, ok := r.transfers[id.String()]
	r.mu.Unlock()
	return b, ok && b.IsValid()
}

// DropTransfer 移除已提交或中止的流式传输绑定。
func (r *Registry) DropTransfer(id security.OperationID) {
	if r == nil || !r.valid || !id.IsValid() {
		return
	}
	r.mu.Lock()
	delete(r.transfers, id.String())
	r.mu.Unlock()
}

// TransferService 返回受沙箱隔离（0 OperatorReadFS）的传输用例服务引用，供 HTTP 流端点驱动分片读写。
func (r *Registry) TransferService() *uctrans.Service {
	if r == nil || !r.valid {
		return nil
	}
	return r.transfer
}

// ScopedFS 返回基于 os.Root 的沙箱本地文件系统端口（绝无 OperatorReadFS），供 HTTP 下载流端点读取已提交产物。
func (r *Registry) ScopedFS() ports.ScopedRootFS {
	if r == nil || !r.valid {
		return nil
	}
	return r.scopedFS
}

func storeHandleMap[K plan.HandleKind](m map[string]plan.ManagedHandle[K], maxCap int, h plan.ManagedHandle[K]) string {
	tok := h.String()
	if len(m) >= maxCap {
		// 仅驱逐索引缓存（连接池自身槽位由 Pool.MaxHandles 严格限流），避免索引 map 无界增长。
		for k := range m {
			delete(m, k)
			break
		}
	}
	m[tok] = h
	return tok
}

func resolveHandleArg[K plan.HandleKind](
	mu *sync.Mutex,
	m map[string]plan.ManagedHandle[K],
	explicit algebraic.Option[plan.ManagedHandle[K]],
	token string,
) (plan.ManagedHandle[K], error) {
	if h, ok := explicit.Get(); ok {
		if !h.IsValid() {
			return zeroVal[plan.ManagedHandle[K]](), fmt.Errorf("%w: handle 无效", protocol.ErrInvalidParams)
		}
		return h, nil
	}
	tok := strings.TrimSpace(token)
	if tok == "" {
		return zeroVal[plan.ManagedHandle[K]](), fmt.Errorf("%w: 必须提供 handle 或 handle_token", protocol.ErrInvalidParams)
	}
	mu.Lock()
	h, ok := m[tok]
	mu.Unlock()
	if !ok || !h.IsValid() {
		return zeroVal[plan.ManagedHandle[K]](), fmt.Errorf("%w: %s", ErrHandleNotFound, tok)
	}
	return h, nil
}

// outcomeJSON 是 execution.ExecutionOutcome 封闭和类型的确定性 JSON 适配器。
type outcomeJSON struct {
	outcome execution.ExecutionOutcome
}

func (o outcomeJSON) IsZero() bool { return o.outcome == nil || !o.outcome.IsValid() }

func (o outcomeJSON) MarshalJSONTo(enc *jsontext.Encoder) error {
	return execution.MarshalOutcomeTo(enc, o.outcome)
}

// boundedBuffer 实现带字节上限与截断标记的纯内存输出采集器，阻断远端海量输出撑爆 MCP 内存。
type boundedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	if limit <= 0 || limit > maxExecOutBytesCap {
		limit = defaultMaxExecOutBytes
	}
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	rem := b.limit - b.buf.Len()
	if rem <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > rem {
		_, _ = b.buf.Write(p[:rem])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *boundedBuffer) String() string  { return b.buf.String() }
func (b *boundedBuffer) Truncated() bool { return b.truncated }

// validateApprovalAndRisk 统一解码可选风险等级与两步审批回执，供各工具处理器复用。
func validateApprovalAndRisk(
	risk algebraic.Option[security.RiskLevel],
	approval algebraic.Option[protocol.ApprovalSubmissionDTO],
) (algebraic.Option[security.RiskLevel], algebraic.Option[gate.ApprovalSubmission], error) {
	if rv, ok := risk.Get(); ok && !rv.IsValid() {
		return algebraic.None[security.RiskLevel](), algebraic.None[gate.ApprovalSubmission](), fmt.Errorf("%w: risk 非法", protocol.ErrInvalidParams)
	}
	sub, err := protocol.DecodeApprovalSubmission(approval)
	if err != nil {
		return algebraic.None[security.RiskLevel](), algebraic.None[gate.ApprovalSubmission](), err
	}
	return risk, sub, nil
}
