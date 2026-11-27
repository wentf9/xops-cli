package automation

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	batchPlansDigestDomainTag = "xops.automation.batch_plans.v1"
	varsDigestDomainTag       = "xops.automation.vars.v1"
)

// Service 是 XOps v2 自动化批量执行与 Playbook vNext 执行用例服务；零值恒未初始化并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Service struct {
	gate               gate.Authorizer
	pool               *pool.Pool
	clock              ports.Clock
	entropy            ports.Entropy
	env                ports.EnvPort
	scopedFS           ports.ScopedRootFS
	operatorReadFS     ports.OperatorReadFS
	inventory          *ucinv.Service
	bus                *events.SystemBus
	defaultConcurrency int
	maxScriptBytes     int64
	maxTemplateBytes   int64
	maxCopyBytes       int64
	valid              bool
}

// NewService 严格校验必填出站依赖与容量上下界，构造不可绕过能力门控的 automation.Service。
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Gate == nil || cfg.Pool == nil || cfg.Pool.IsClosed() || cfg.Clock == nil || cfg.Entropy == nil {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonMissingDep, domi18n.Str("component", "Gate/Pool/Clock/Entropy"))
	}
	if cfg.SystemBus != nil && cfg.SystemBus.IsClosed() {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonComponentClosed, domi18n.Str("component", "SystemBus"))
	}
	conc := pickIf(cfg.DefaultConcurrency == 0, defaultConcurrency, cfg.DefaultConcurrency)
	maxScript := pickIf(cfg.MaxScriptBytes == 0, defaultMaxScriptBytes, cfg.MaxScriptBytes)
	maxTmpl := pickIf(cfg.MaxTemplateBytes == 0, defaultMaxTemplateSize, cfg.MaxTemplateBytes)
	maxCopy := pickIf(cfg.MaxCopyBytes == 0, defaultMaxCopyBytes, cfg.MaxCopyBytes)
	if conc < 1 || conc > maxConcurrency ||
		maxScript <= 0 || maxScript > maxAllowedScriptBytes ||
		maxTmpl <= 0 || maxTmpl > maxAllowedTemplateSize ||
		maxCopy <= 0 || maxCopy > maxAllowedCopyBytes {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "concurrency/size_limits"))
	}
	return &Service{
		gate: cfg.Gate, pool: cfg.Pool, clock: cfg.Clock, entropy: cfg.Entropy,
		env: cfg.Env, scopedFS: cfg.ScopedFS, operatorReadFS: cfg.OperatorReadFS,
		inventory: cfg.Inventory, bus: cfg.SystemBus,
		defaultConcurrency: conc, maxScriptBytes: maxScript,
		maxTemplateBytes: maxTmpl, maxCopyBytes: maxCopy, valid: true,
	}, nil
}

func zeroVal[T any]() (z T) { return z }

func pickIf[T any](cond bool, yes, no T) T {
	if cond {
		return yes
	}
	return no
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) enforceStrictPaths() bool {
	return s.gate.Profile() != gate.PolicyProfileDirectOperator
}

func (s *Service) checkReady(ctx context.Context) error {
	if s == nil || !s.valid {
		return ErrServiceNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if s.gate.IsHalted() {
		return gate.ErrGateHalted
	}
	return ctx.Err()
}

func (s *Service) resolveConcurrency(requested int) (int, error) {
	c := pickIf(requested == 0, s.defaultConcurrency, requested)
	if c < 1 || c > maxConcurrency {
		return 0, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldRange, domi18n.Str("field", "concurrency"), domi18n.Int("value", requested), domi18n.Int("min", 1), domi18n.Int("max", maxConcurrency))
	}
	return c, nil
}

func canonicalizeTags(raw []inventory.Tag) ([]inventory.Tag, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	for i, tag := range raw {
		if !tag.IsValid() {
			return nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "tags"), domi18n.Int("index", i))
		}
	}
	out := slices.Clone(raw)
	slices.SortFunc(out, inventory.Tag.Compare)
	return slices.CompactFunc(out, inventory.Tag.Equal), nil
}

func canonicalizeNodeIDs(raw []inventory.NodeID) ([]inventory.NodeID, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	for i, id := range raw {
		if !id.IsValid() {
			return nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "exclude_nodes"), domi18n.Int("index", i))
		}
	}
	out := slices.Clone(raw)
	slices.SortFunc(out, inventory.NodeID.Compare)
	return slices.CompactFunc(out, inventory.NodeID.Equal), nil
}

// resolveTargets 统一解析、去重、筛选并按 NodeID 确定性排序目标节点集合，
// 保证门控绑定中的 NodeIDs 与连接计划集合摘要完全由显式输入确定（零随机/map 迭代漂移）。
func (s *Service) resolveTargets(ctx context.Context, explicit []TargetNode, selector algebraic.Option[playbook.TargetSelector], cliOpts option.OptionLayer, excludeNodes []inventory.NodeID, excludeTags []inventory.Tag) ([]TargetNode, error) {
	if err := cliOpts.Validate(); err != nil {
		return nil, domi18n.WrapS(ErrInvalidRequest, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "CLIOptions"))
	}
	exNodes, err := canonicalizeNodeIDs(excludeNodes)
	if err != nil {
		return nil, err
	}
	exTags, err := canonicalizeTags(excludeTags)
	if err != nil {
		return nil, err
	}
	sel, hasSel := selector.Get()
	if hasSel && !sel.IsValid() {
		return nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "TargetSelector"))
	}
	candidates, err := s.gatherCandidateTargets(ctx, explicit, sel, hasSel, cliOpts, exNodes, exTags)
	if err != nil {
		return nil, err
	}
	return filterAndSortTargets(candidates, sel, hasSel, exNodes, exTags)
}

func (s *Service) gatherCandidateTargets(ctx context.Context, explicit []TargetNode, sel playbook.TargetSelector, hasSel bool, cliOpts option.OptionLayer, exNodes []inventory.NodeID, exTags []inventory.Tag) ([]TargetNode, error) {
	if len(explicit) > 0 {
		for i, t := range explicit {
			if !t.IsValid() {
				return nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "targets"), domi18n.Int("index", i))
			}
		}
		return explicit, nil
	}
	if !hasSel {
		return nil, ErrNoTargets
	}
	return s.resolveTargetsFromInventory(ctx, sel, cliOpts, exNodes, exTags)
}

func (s *Service) resolveTargetsFromInventory(ctx context.Context, sel playbook.TargetSelector, cliOpts option.OptionLayer, exNodes []inventory.NodeID, exTags []inventory.Tag) ([]TargetNode, error) {
	if s.inventory == nil {
		return nil, ErrInventoryUnavailable
	}
	nodes, _, err := s.inventory.ListNodes(ctx, ucinv.QueryRequest{})
	if err != nil {
		return nil, err
	}
	matched := make([]TargetNode, 0, len(nodes))
	foundIDs := make(map[inventory.NodeID]bool, len(nodes))
	for _, n := range nodes {
		if !sel.Matches(n.ID(), n.Tags()) || isNodeExcluded(n.ID(), n.Tags(), exNodes, exTags) {
			continue
		}
		tn, err := s.resolveSingleTargetNode(ctx, n.ID(), n.Tags(), n.Execution(), cliOpts)
		if err != nil {
			return nil, err
		}
		foundIDs[n.ID()] = true
		matched = append(matched, tn)
	}
	return s.appendVirtualSelectorNodes(ctx, sel, foundIDs, exNodes, exTags, cliOpts, matched)
}

// appendVirtualSelectorNodes 对显式节点名选择器（无 all/tags 筛选）中未命中托管表的条目回退 ResolveTarget，兼容 ~/.ssh/config 虚拟节点（ADR-004）。
func (s *Service) appendVirtualSelectorNodes(ctx context.Context, sel playbook.TargetSelector, foundIDs map[inventory.NodeID]bool, exNodes []inventory.NodeID, exTags []inventory.Tag, cliOpts option.OptionLayer, matched []TargetNode) ([]TargetNode, error) {
	if sel.All() || len(sel.Tags()) > 0 {
		return matched, nil
	}
	for _, id := range sel.Nodes() {
		if foundIDs[id] || isNodeExcluded(id, nil, exNodes, exTags) {
			continue
		}
		tn, err := s.resolveSingleTargetNode(ctx, id, nil, algebraic.None[execution.LaunchProfile](), cliOpts)
		if err != nil {
			return nil, err
		}
		matched = append(matched, tn)
	}
	return matched, nil
}

func (s *Service) resolveSingleTargetNode(ctx context.Context, id inventory.NodeID, tags []inventory.Tag, execProf algebraic.Option[execution.LaunchProfile], cliOpts option.OptionLayer) (TargetNode, error) {
	resolved, err := s.inventory.ResolveTarget(ctx, ucinv.ResolveTargetRequest{Target: id.String(), CLIOptions: cliOpts})
	if err != nil {
		return TargetNode{}, domi18n.Wrap(err, domi18n.KeyCommonOpTargetFailed, domi18n.Str("op", "resolve target"), domi18n.BoundStr("target", id.String()))
	}
	return NewTargetNode(TargetNodeSpec{NodeID: id, Plan: resolved.Plan(), Tags: tags, DefaultProfile: execProf})
}

func formatLaunchProfile(p execution.LaunchProfile) string {
	d := "unset"
	if v, ok := p.DialectOption().Get(); ok {
		d = v.String()
	}
	return d + "/" + p.Interpreter().String() + "/" + p.LoginMode().String()
}

func (s *Service) canonicalizeNodeRemotePaths(ctx context.Context, connPlan plan.SealedConnectionPlan, paths []pathalg.RemotePath, out map[string]struct{}) error {
	if len(paths) == 0 {
		return nil
	}
	return s.pool.WithLease(ctx, connPlan, func(leaseCtx context.Context, lease *pool.Lease) error {
		rfs, err := lease.OpenRemoteFS(leaseCtx)
		if err != nil {
			return err
		}
		defer func() { _ = rfs.Close() }()
		for _, p := range paths {
			canon, err := resolveCanonicalRemotePath(leaseCtx, rfs, p)
			if err != nil {
				return err
			}
			out[canon.String()] = struct{}{}
		}
		return nil
	})
}

func filterAndSortTargets(candidates []TargetNode, sel playbook.TargetSelector, hasSel bool, exNodes []inventory.NodeID, exTags []inventory.Tag) ([]TargetNode, error) {
	seen := make(map[inventory.NodeID]bool, len(candidates))
	out := make([]TargetNode, 0, len(candidates))
	for _, t := range candidates {
		if seen[t.nodeID] {
			return nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", "target node"), domi18n.BoundStr("value", t.nodeID.String()))
		}
		seen[t.nodeID] = true
		if (hasSel && !sel.Matches(t.nodeID, t.tags)) || isNodeExcluded(t.nodeID, t.tags, exNodes, exTags) {
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, ErrNoTargets
	}
	slices.SortFunc(out, func(a, b TargetNode) int { return a.nodeID.Compare(b.nodeID) })
	return out, nil
}

func isNodeExcluded(id inventory.NodeID, tags []inventory.Tag, exNodes []inventory.NodeID, exTags []inventory.Tag) bool {
	if _, found := slices.BinarySearchFunc(exNodes, id, inventory.NodeID.Compare); found {
		return true
	}
	for _, tag := range tags {
		if _, found := slices.BinarySearchFunc(exTags, tag, inventory.Tag.Compare); found {
			return true
		}
	}
	return false
}

// digestTargetPlans 对已按 NodeID 排序的目标集合计算确定性 Merkle 摘要，
// 使两步审批信封锚定精确的目标主机列表与每跳连接计划（零门控前抽熵漂移）。
func digestTargetPlans(targets []TargetNode) security.Digest {
	h := sha256.New()
	writeLenPrefixed(h, batchPlansDigestDomainTag)
	writeUint64BE(h, uint64(len(targets)))
	for _, t := range targets {
		writeLenPrefixed(h, t.nodeID.String())
		writeLenPrefixed(h, t.plan.PlanDigest().String())
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return security.DigestFromSHA256(sum)
}

func digestStringMap(domainTag string, m map[string]string) security.Digest {
	h := sha256.New()
	writeLenPrefixed(h, domainTag)
	keys := slices.Sorted(maps.Keys(m))
	writeUint64BE(h, uint64(len(keys)))
	for _, k := range keys {
		writeLenPrefixed(h, k)
		writeLenPrefixed(h, m[k])
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return security.DigestFromSHA256(sum)
}

func writeLenPrefixed(w io.Writer, s string) {
	writeUint64BE(w, uint64(len(s)))
	_, _ = io.WriteString(w, s)
}

func writeUint64BE(w io.Writer, v uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	_, _ = w.Write(buf[:])
}

func extractNodeIDStrings(targets []TargetNode) []string {
	out := make([]string, len(targets))
	for i, t := range targets {
		out[i] = t.nodeID.String()
	}
	return out
}

func (s *Service) filterSendEnv(targetHop plan.HopSpec) map[string]string {
	if filter := targetHop.Transport().SendEnv(); !filter.IsUnset() && s.env != nil {
		return filter.Filter(s.env.Environ())
	}
	return nil
}

// resolveCanonicalRemotePath 在有界跳数预算（pathalg.MaxSymlinkHops）内解析远端真实 POSIX 路径，
// 全程仅使用 pathalg，严格禁止 path/filepath。
func resolveCanonicalRemotePath(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	cur, err := anchorRemotePath(ctx, rfs, p)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	var suffix []pathalg.RemoteName
	for hops := 0; len(suffix) < maxRemoteCanonicalHops; {
		if realCur, rErr := rfs.RealPath(ctx, cur); rErr == nil {
			return rejoinRemoteSuffix(realCur, suffix)
		} else if !errors.Is(rErr, ports.ErrNotFound) {
			return zeroVal[pathalg.RemotePath](), rErr
		}
		if nextCur, jumped, jErr := expandDanglingSymlinkStep(ctx, rfs, cur, suffix, &hops); jErr != nil {
			return zeroVal[pathalg.RemotePath](), jErr
		} else if jumped {
			cur, suffix = nextCur, suffix[:0]
			continue
		}
		base, ok := cur.Base()
		if !ok || cur.IsRoot() || cur.Dir().Equal(cur) {
			return rejoinRemoteSuffix(cur, suffix)
		}
		suffix, cur = append(suffix, base), cur.Dir()
	}
	return zeroVal[pathalg.RemotePath](), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "remote path canonicalization hops"), domi18n.Int("count", len(suffix)), domi18n.Int("limit", maxRemoteCanonicalHops))
}

func anchorRemotePath(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	if p.IsAbs() {
		return p, nil
	}
	dot, _ := pathalg.ParseRemotePath(".")
	cwd, err := rfs.RealPath(ctx, dot)
	if err != nil || !cwd.IsAbs() {
		return zeroVal[pathalg.RemotePath](), firstErr(err, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", cwd.String()), domi18n.Str("reason", "remote working directory must be absolute")))
	}
	return cwd.Resolve(p)
}

func expandDanglingSymlinkStep(ctx context.Context, rfs ports.RemoteFSPort, cur pathalg.RemotePath, suffix []pathalg.RemoteName, hops *int) (pathalg.RemotePath, bool, error) {
	lst, err := rfs.Lstat(ctx, cur)
	if errors.Is(err, ports.ErrNotFound) || (err == nil && !lst.IsSymlink()) {
		return zeroVal[pathalg.RemotePath](), false, nil
	}
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	if *hops >= pathalg.MaxSymlinkHops {
		return zeroVal[pathalg.RemotePath](), false, domi18n.EF(ErrSymlinkPolicyDenied, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "remote symlink hops"), domi18n.Int("count", *hops), domi18n.Int("limit", pathalg.MaxSymlinkHops))
	}
	*hops++
	raw, err := rfs.ReadLink(ctx, cur)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	targetP, err := pathalg.ParseRemotePath(raw)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	nextBase, err := resolveSymlinkBase(ctx, rfs, cur, targetP)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	nextFull, err := rejoinRemoteSuffix(nextBase, suffix)
	return nextFull, err == nil, err
}

func resolveSymlinkBase(ctx context.Context, rfs ports.RemoteFSPort, cur, targetP pathalg.RemotePath) (pathalg.RemotePath, error) {
	if targetP.IsAbs() {
		return targetP, nil
	}
	realParent, err := rfs.RealPath(ctx, cur.Dir())
	if err != nil || !realParent.IsAbs() {
		return zeroVal[pathalg.RemotePath](), firstErr(err, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", realParent.String()), domi18n.Str("reason", "remote symlink parent directory must be absolute")))
	}
	return realParent.Resolve(targetP)
}

func rejoinRemoteSuffix(base pathalg.RemotePath, revSuffix []pathalg.RemoteName) (pathalg.RemotePath, error) {
	if len(revSuffix) == 0 {
		return base, nil
	}
	ordered := slices.Clone(revSuffix)
	slices.Reverse(ordered)
	return base.Join(ordered...)
}

func verifyRemotePathAuthorized(ctx context.Context, enforce bool, rfs ports.RemoteFSPort, binding security.OperationBinding, target pathalg.RemotePath) error {
	if !enforce {
		return nil
	}
	canon, err := resolveCanonicalRemotePath(ctx, rfs, target)
	if err != nil {
		return err
	}
	cs := canon.String()
	ok := slices.Contains(binding.CanonicalPaths(), cs) ||
		slices.ContainsFunc(binding.RecursivePaths(), func(root string) bool {
			return root == "/" || cs == root || strings.HasPrefix(cs, root+"/")
		})
	if !ok {
		return domi18n.EF(gate.ErrScopeEscalated, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", target.String()), domi18n.BoundStr("reason", "canonicalized to unauthorized target "+canon.String()))
	}
	return nil
}
