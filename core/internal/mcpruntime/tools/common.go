package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
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
		return zeroVal[ucinv.ResolvedTarget](), domi18n.EF(ErrServiceUnavailable, domi18n.KeyCommonMissingDep, domi18n.Str("component", "InventoryService"))
	}
	if strings.TrimSpace(target) == "" {
		return zeroVal[ucinv.ResolvedTarget](), domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "target"))
	}
	return r.inventory.ResolveTarget(ctx, ucinv.ResolveTargetRequest{
		Target:     target,
		CLIOptions: cliOpts,
	})
}

func (r *Registry) buildTransferCallBase(ctx context.Context, target string, riskRaw algebraic.Option[security.RiskLevel], approvalDTO algebraic.Option[protocol.ApprovalSubmissionDTO]) (uctrans.CallBase, error) {
	resolved, err := r.resolveTarget(ctx, target, option.UnsetOptionLayer())
	if err != nil {
		return uctrans.CallBase{}, err
	}
	approval, err := protocol.DecodeApprovalSubmission(approvalDTO)
	if err != nil {
		return uctrans.CallBase{}, err
	}
	return uctrans.CallBase{Plan: resolved.Plan(), NodeID: resolved.NodeID(), Risk: riskRaw, Approval: approval}, nil
}

func parseOptionalRevision(raw string) (algebraic.Option[ports.Revision], error) {
	if strings.TrimSpace(raw) == "" {
		return algebraic.None[ports.Revision](), nil
	}
	rev, err := ports.ParseRevision(raw)
	if err != nil {
		return algebraic.None[ports.Revision](), domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "expected_revision"))
	}
	return algebraic.Some(rev), nil
}

func parseOptionalPerm(opt algebraic.Option[uint32]) (algebraic.Option[fs.FileMode], error) {
	v, ok := opt.Get()
	if !ok {
		return algebraic.None[fs.FileMode](), nil
	}
	if v == 0 || v > 0o777 {
		return algebraic.None[fs.FileMode](), domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonPermInvalid, domi18n.Str("perm", strconv.FormatUint(uint64(v), 8)))
	}
	return algebraic.Some(fs.FileMode(v)), nil
}

func decodeBase64Strict(raw string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil {
		return nil, domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonBase64DecodeFailed)
	}
	return b, nil
}

func decodeTextOrBase64(text algebraic.Option[string], b64 algebraic.Option[string]) ([]byte, error) {
	tVal, hasT := text.Get()
	bVal, hasB := b64.Get()
	if hasT == hasB {
		return nil, domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonOneOfRequired, domi18n.Str("options", "text, base64"))
	}
	if hasB {
		return decodeBase64Strict(bVal)
	}
	return []byte(tVal), nil
}

func parseRemotePathParam(name, raw string) (pathalg.RemotePath, error) {
	p, err := pathalg.ParseRemotePath(raw)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.BoundStr("field", name))
	}
	return p, nil
}

func parseOptionalDigest(raw string) (algebraic.Option[security.Digest], error) {
	if strings.TrimSpace(raw) == "" {
		return algebraic.None[security.Digest](), nil
	}
	d, err := security.ParseDigest(raw)
	if err != nil {
		return algebraic.None[security.Digest](), domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "expected_digest"))
	}
	return algebraic.Some(d), nil
}

// CloseEphemeralHandles 在独立关闭 MCP Server 时尽力释放追踪中的非持久化活跃句柄（PTY/Forward/GUI/Mux），
// 同时仅摘除本地 transfers 路由索引而不中止带 Journal 的可恢复 10 GiB 传输，保证断点续传与崩溃恢复语义不受破坏。
func (r *Registry) CloseEphemeralHandles(ctx context.Context) {
	if r == nil || !r.valid {
		return
	}
	r.mu.Lock()
	ptys := snapshotMapValues(r.ptyHandles)
	tunnels := snapshotMapValues(r.tunnelHandles)
	guis := snapshotMapValues(r.guiHandles)
	muxes := snapshotMapValues(r.muxHandles)
	clear(r.ptyHandles)
	clear(r.tunnelHandles)
	clear(r.guiHandles)
	clear(r.muxHandles)
	clear(r.transfers)
	r.mu.Unlock()
	if ctx == nil || r.gate.IsHalted() {
		return
	}
	r.releaseSessionEphemeral(ctx, ptys, tunnels, muxes)
	if r.observability != nil {
		for _, h := range guis {
			_ = r.observability.CloseGUISession(ctx, h)
		}
	}
}

func (r *Registry) releaseSessionEphemeral(ctx context.Context, ptys []plan.ManagedHandle[plan.KindPTY], tunnels []plan.ManagedHandle[plan.KindTunnel], muxes []plan.ManagedHandle[plan.KindMux]) {
	if r.session == nil {
		return
	}
	for _, h := range ptys {
		_ = r.session.ClosePTY(ctx, h)
	}
	for _, h := range tunnels {
		_ = r.session.StopForward(ctx, h)
	}
	for _, h := range muxes {
		_ = r.session.StopControlMaster(ctx, h)
	}
}

func snapshotMapValues[V any](m map[string]V) []V {
	out := make([]V, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
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

// LookupTransfer / DropTransfer / TransferService / ScopedFS 供 HTTP 10 GiB 流式传输端点安全消费。
func (r *Registry) LookupTransfer(id security.OperationID) (TransferBinding, bool) {
	if r == nil || !r.valid || !id.IsValid() || r.gate.IsHalted() {
		return TransferBinding{}, false
	}
	r.mu.Lock()
	b, ok := r.transfers[id.String()]
	r.mu.Unlock()
	return b, ok && b.IsValid()
}
func (r *Registry) DropTransfer(id security.OperationID) {
	if r == nil || !r.valid || !id.IsValid() {
		return
	}
	r.mu.Lock()
	delete(r.transfers, id.String())
	r.mu.Unlock()
}
func (r *Registry) TransferService() *uctrans.Service {
	if r == nil || !r.valid {
		return nil
	}
	return r.transfer
}
func (r *Registry) ScopedFS() ports.ScopedRootFS {
	if r == nil || !r.valid {
		return nil
	}
	return r.scopedFS
}

func storeHandleMap[K plan.HandleKind](m map[string]plan.ManagedHandle[K], maxCap int, h plan.ManagedHandle[K]) string {
	tok := h.String()
	if len(m) >= maxCap {
		for k := range m {
			delete(m, k)
			break
		}
	}
	m[tok] = h
	return tok
}

func resolveHandleArg[K plan.HandleKind](mu *sync.Mutex, m map[string]plan.ManagedHandle[K], explicit algebraic.Option[plan.ManagedHandle[K]], token string) (plan.ManagedHandle[K], error) {
	if h, ok := explicit.Get(); ok {
		if !h.IsValid() {
			return zeroVal[plan.ManagedHandle[K]](), domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "handle"))
		}
		return h, nil
	}
	tok := strings.TrimSpace(token)
	if tok == "" {
		return zeroVal[plan.ManagedHandle[K]](), domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonOneOfRequired, domi18n.Str("options", "handle, handle_token"))
	}
	mu.Lock()
	h, ok := m[tok]
	mu.Unlock()
	if !ok || !h.IsValid() {
		return zeroVal[plan.ManagedHandle[K]](), domi18n.EF(ErrHandleNotFound, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "handle_token"), domi18n.BoundStr("value", tok))
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

func clampOutputLimit(raw uint64) int {
	if raw == 0 {
		return defaultMaxExecOutBytes
	}
	if raw > uint64(maxExecOutBytesCap) {
		return maxExecOutBytesCap
	}
	return int(raw)
}

func newBoundedBuffer(limit int) *boundedBuffer {
	if limit <= 0 {
		limit = defaultMaxExecOutBytes
	} else if limit > maxExecOutBytesCap {
		limit = maxExecOutBytesCap
	}
	return &boundedBuffer{limit: limit}
}

func optionalStringReader(s string) io.Reader {
	if s == "" {
		return nil
	}
	return strings.NewReader(s)
}

func parseOptionalOpID(raw string) (algebraic.Option[security.OperationID], error) {
	if strings.TrimSpace(raw) == "" {
		return algebraic.None[security.OperationID](), nil
	}
	id, err := security.ParseOperationID(raw)
	if err != nil {
		return algebraic.None[security.OperationID](), domi18n.WrapS(protocol.ErrInvalidParams, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "transfer_id"))
	}
	return algebraic.Some(id), nil
}

// SynthesizeTargetNodeID 为批量/Playbook 目标构造确定性合法的 inventory.NodeID（供 tools 与 core/engine 复用）：
// 托管目标直接解析真实 NodeID；IPv6 或非默认端口 AdHoc 目标按末跳规范化端点合成无冲突合法标识。
func SynthesizeTargetNodeID(rawID string, kind option.OriginKind, connPlan plan.SealedConnectionPlan) (inventory.NodeID, error) {
	if kind == option.OriginManaged {
		return inventory.ParseNodeID(rawID)
	}
	hops := connPlan.Hops().Slice()
	if len(hops) == 0 {
		return inventory.ParseNodeID(rawID)
	}
	ep := hops[len(hops)-1].Endpoint()
	if kind == option.OriginOpenSSHVirtual || ep.Port() == 22 {
		if nid, err := inventory.ParseNodeID(rawID); err == nil {
			return nid, nil
		}
	}
	sanitized := sanitizeEndpointHostForID(ep.Host().String())
	if len(sanitized) > 64 {
		dig := strings.TrimPrefix(security.DigestBytes([]byte(ep.String())).String(), "sha256:")
		sanitized = sanitized[:51] + "-" + dig[:12]
	}
	return inventory.ParseNodeID("adhoc-" + sanitized + "-" + strconv.Itoa(int(ep.Port())))
}

func sanitizeEndpointHostForID(host string) string {
	var b strings.Builder
	b.Grow(len(host))
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "host"
	}
	return b.String()
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
		return algebraic.None[security.RiskLevel](), algebraic.None[gate.ApprovalSubmission](), domi18n.EF(protocol.ErrInvalidParams, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "risk"))
	}
	sub, err := protocol.DecodeApprovalSubmission(approval)
	if err != nil {
		return algebraic.None[security.RiskLevel](), algebraic.None[gate.ApprovalSubmission](), err
	}
	return risk, sub, nil
}
