package sim

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
	"slices"
	"strings"
)

// SimInventoryStore 实现 ports.InventoryStore，支持 CAS 并发冲突与不确定落盘结果注入。
//
//xops:opaque
//xops:failclosed
type SimInventoryStore struct {
	simBase
	ver            uint64
	rev            ports.Revision
	graph          inventory.Graph
	nextDurability algebraic.Option[ports.DurabilityOutcome]
}

// NewSimInventoryStore 以初始资产图（无效时自动构造空有效图）创建存储仿真器。
func NewSimInventoryStore(initial inventory.Graph) (*SimInventoryStore, error) {
	var err error
	if !initial.IsValid() {
		initial, err = inventory.NewGraph(inventory.GraphSpec{})
	}
	rev, rErr := ports.ParseRevision("rev-0")
	if err = firstErr(err, rErr); err != nil {
		return nil, err
	}
	return &SimInventoryStore{simBase: newSimBase(nil), rev: rev, graph: initial}, nil
}

// InjectNextDurability 注入下一次 CommitCAS 的持久化结果（如 Applied&&!Durable 或 Unknown）。
func (s *SimInventoryStore) InjectNextDurability(out ports.DurabilityOutcome) {
	if out.IsValid() {
		s.withLock(func() { s.nextDurability = algebraic.Some(out) })
	}
}
func (s *SimInventoryStore) Load(ctx context.Context) (out ports.InventorySnapshot, err error) {
	if err = s.check(ctx, "store.load"); err != nil {
		return out, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return ports.NewInventorySnapshot(s.rev, s.graph)
}
func (s *SimInventoryStore) CommitCAS(ctx context.Context, expected ports.Revision, next inventory.Graph) (out ports.DurabilityOutcome, err error) {
	if err = s.check(ctx, "store.commit", expected.IsValid(), next.IsValid()); err != nil {
		return out, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.rev.Equal(expected) {
		return out, ports.ErrRevisionConflict
	}
	if inj, ok := s.nextDurability.Get(); ok {
		s.nextDurability = algebraic.None[ports.DurabilityOutcome]()
		if inj.Applied() {
			_, err = s.advanceLocked(next, inj.Revision())
		}
		return inj, err
	}
	rev, err := s.advanceLocked(next, algebraic.None[ports.Revision]())
	if err != nil {
		return out, err
	}
	return ports.NewDurabilityCommitted(rev)
}
func (s *SimInventoryStore) advanceLocked(next inventory.Graph, optRev algebraic.Option[ports.Revision]) (rev ports.Revision, err error) {
	s.ver++
	if r, has := optRev.Get(); has {
		rev = r
	} else if rev, err = ports.ParseRevision(fmt.Sprintf("rev-%d", s.ver)); err != nil {
		return rev, err
	}
	s.rev, s.graph = rev, next
	return rev, nil
}

// SimJournalStore 实现 ports.JournalStore 的纯内存确定性双代传输 WAL 仿真器（支持按代隔离与单侧损坏注入）。
//
//xops:opaque
//xops:failclosed
type SimJournalStore struct {
	simBase
	jm *memtree.JournalMap
}

// NewSimJournalStore 创建空白双代传输 Journal 仿真器。
func NewSimJournalStore() *SimJournalStore {
	return &SimJournalStore{simBase: newSimBase(nil), jm: memtree.NewJournalMap()}
}

// CorruptGeneration 将指定 (transferID, generation) 标记为损坏态以供双代损坏隔离崩溃恢复测试。
func (s *SimJournalStore) CorruptGeneration(id security.OperationID, generation uint64, cause error) {
	s.withLock(func() { s.jm.CorruptGenerationLocked(id, generation, cause) })
}
func (s *SimJournalStore) Append(ctx context.Context, rec fsm.TransferJournalRecord) error {
	if err := s.check(ctx, "journal.append", rec.IsValid()); err != nil {
		return err
	}
	s.withLock(func() { s.jm.AppendLocked(rec) })
	return nil
}
func (s *SimJournalStore) Load(ctx context.Context, id security.OperationID) (out []fsm.TransferJournalRecord, err error) {
	if err = s.check(ctx, "journal.load", id.IsValid()); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jm.LoadLocked(id)
}
func (s *SimJournalStore) LoadGenerations(ctx context.Context, id security.OperationID) ([]ports.JournalGenerationSnapshot, error) {
	if err := s.check(ctx, "journal.load_gens", id.IsValid()); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jm.LoadGenerationsLocked(id)
}
func (s *SimJournalStore) PruneGeneration(ctx context.Context, id security.OperationID, generation uint64) error {
	if err := s.check(ctx, "journal.prune", id.IsValid(), generation > 0); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jm.PruneGenerationLocked(id, generation)
}
func (s *SimJournalStore) ListActive(ctx context.Context) ([]security.OperationID, error) {
	if err := s.check(ctx, "journal.list"); err != nil {
		return nil, err
	}
	return withLockRet(&s.simBase, nil, func() []security.OperationID { return s.jm.ListActiveLocked() }), nil
}
func (s *SimJournalStore) Delete(ctx context.Context, id security.OperationID) error {
	if err := s.check(ctx, "journal.delete", id.IsValid()); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jm.DeleteLocked(id)
}

// SimFormatImporter 实现 ports.FormatImporter，将 CSV 行（alias,addr,port,user）解析为 ImportBundle。
//
//xops:opaque
//xops:failclosed
type SimFormatImporter struct {
	simBase
	format string
}

// NewSimFormatImporter 创建格式导入仿真器（空格式名默认 "csv"）。
func NewSimFormatImporter(format string) *SimFormatImporter {
	return &SimFormatImporter{simBase: newSimBase(nil), format: cmp.Or(strings.ToLower(strings.TrimSpace(format)), "csv")}
}
func (i *SimFormatImporter) Format() string { return i.format }
func (i *SimFormatImporter) Import(ctx context.Context, _ string, r io.Reader) (out inventory.ImportBundle, err error) {
	if err = i.check(ctx, "importer.import", r != nil); err != nil {
		return out, err
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return out, err
	}
	return memtree.ParseCSVImportBundle(i.format, raw)
}

// SimOpenSSHConfigSource 实现 ports.OpenSSHConfigSource 的虚拟主机与 Tier-4 选项折叠仿真器。
//
//xops:opaque
//xops:failclosed
type SimOpenSSHConfigSource struct {
	simBase
	hosts []ports.OpenSSHVirtualHost
}

// NewSimOpenSSHConfigSource 创建预置虚拟主机的 OpenSSHConfigSource 仿真器。
func NewSimOpenSSHConfigSource(hosts ...ports.OpenSSHVirtualHost) *SimOpenSSHConfigSource {
	return &SimOpenSSHConfigSource{simBase: newSimBase(nil), hosts: slices.DeleteFunc(slices.Clone(hosts), func(h ports.OpenSSHVirtualHost) bool { return !h.IsValid() })}
}
func (s *SimOpenSSHConfigSource) ListVirtualHosts(ctx context.Context) ([]ports.OpenSSHVirtualHost, error) {
	if err := s.check(ctx, "openssh.list"); err != nil {
		return nil, err
	}
	return withLockRet(&s.simBase, nil, func() []ports.OpenSSHVirtualHost { return slices.Clone(s.hosts) }), nil
}
func (s *SimOpenSSHConfigSource) ResolveTier4(ctx context.Context, target option.OriginalHostSpec, endpoint algebraic.Option[netaddr.Endpoint]) (out option.OptionLayer, err error) {
	ep, hasReqEP := endpoint.Get()
	if err = s.check(ctx, "openssh.resolve", target.IsValid(), !hasReqEP || ep.IsValid()); err != nil {
		return out, err
	}
	return withLockRet(&s.simBase, option.UnsetOptionLayer(), func() option.OptionLayer {
		return memtree.ResolveSimTier4(s.hosts, target, endpoint)
	}), nil
}

// SimKeySigner 实现 ports.KeySignerPort 的确定性签名与指纹查询仿真器。
//
//xops:opaque
//xops:failclosed
type SimKeySigner struct {
	simBase
	keys   []ports.PublicKeyInfo
	byPath map[string]inventory.KeyFingerprint
}

// NewSimKeySigner 创建预置公钥的密钥签名仿真器。
func NewSimKeySigner(keys ...ports.PublicKeyInfo) *SimKeySigner {
	s := &SimKeySigner{simBase: newSimBase(nil), byPath: make(map[string]inventory.KeyFingerprint)}
	for _, k := range keys {
		s.AddKey(k, "")
	}
	return s
}

// AddKey 注册公钥及其可选私钥路径映射（未注册路径查询时返回 ErrNotFound）。
func (s *SimKeySigner) AddKey(pub ports.PublicKeyInfo, keyPath string) {
	if pub.IsValid() {
		s.withLock(func() {
			s.keys = append(s.keys, pub)
			if keyPath != "" {
				s.byPath[keyPath] = pub.Fingerprint()
			}
		})
	}
}
func (s *SimKeySigner) ListPublicKeys(ctx context.Context, auth inventory.AuthMethod) ([]ports.PublicKeyInfo, error) {
	if err := s.check(ctx, "signer.list", auth != nil && auth.IsValid()); err != nil {
		return nil, err
	}
	return withLockRet(&s.simBase, nil, func() []ports.PublicKeyInfo { return slices.Clone(s.keys) }), nil
}
func (s *SimKeySigner) Sign(ctx context.Context, key inventory.KeyFingerprint, algorithm string, data []byte) (out ports.Signature, err error) {
	if err = s.check(ctx, "signer.sign", key.IsValid(), algorithm != ""); err != nil {
		return out, err
	}
	if !withLockRet(&s.simBase, false, func() bool {
		return slices.ContainsFunc(s.keys, func(k ports.PublicKeyInfo) bool { return k.Fingerprint().Equal(key) })
	}) {
		return out, ports.ErrSignerUnavailable
	}
	return memtree.SignSimKey("", key, algorithm, data)
}
func (s *SimKeySigner) InspectPrivateKeyFingerprint(ctx context.Context, keyPath inventory.KeyPathSpec, _ algebraic.Option[secret.Ref]) (out inventory.KeyFingerprint, err error) {
	if err = s.check(ctx, "signer.inspect", keyPath.IsValid()); err != nil {
		return out, err
	}
	if fp := withLockRet(&s.simBase, out, func() inventory.KeyFingerprint { return s.byPath[keyPath.String()] }); fp.IsValid() {
		return fp, nil
	}
	return out, ports.ErrNotFound
}

// SimHostTrust 实现按 Endpoint (Host, Port) 严格隔离的主机密钥信任库仿真器（INV-E2）。
//
//xops:opaque
//xops:failclosed
type SimHostTrust struct {
	simBase
	trusted map[string][]ports.PublicKeyInfo
	revoked map[inventory.KeyFingerprint]bool
}

// NewSimHostTrust 创建空白主机密钥信任库仿真器。
func NewSimHostTrust() *SimHostTrust {
	return &SimHostTrust{simBase: newSimBase(nil), trusted: make(map[string][]ports.PublicKeyInfo), revoked: make(map[inventory.KeyFingerprint]bool)}
}

// RevokeKey 吊销指定主机公钥指纹，后续核验将返回 HostTrustRevoked。
func (t *SimHostTrust) RevokeKey(fp inventory.KeyFingerprint) {
	if fp.IsValid() {
		t.withLock(func() { t.revoked[fp] = true })
	}
}
func (t *SimHostTrust) PreferredAlgorithms(ctx context.Context, ep netaddr.Endpoint, _ option.KnownHostsList) ([]string, error) {
	if err := t.check(ctx, "trust.algos", ep.IsValid()); err != nil {
		return nil, err
	}
	return withLockRet(&t.simBase, nil, func() []string { return memtree.PreferredAlgosFromKeys(t.trusted[ep.String()]) }), nil
}
func (t *SimHostTrust) VerifyHostKey(ctx context.Context, req ports.HostTrustRequest) (out ports.HostTrustCheck, err error) {
	if err = t.check(ctx, "trust.verify", req.IsValid()); err != nil {
		return out, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return memtree.BuildHostTrustCheck(req, t.trusted[req.Endpoint().String()], t.revoked[req.Presented().Fingerprint()])
}
func (t *SimHostTrust) RecordHostKey(ctx context.Context, ep netaddr.Endpoint, key ports.PublicKeyInfo, _ option.KnownHostsList) error {
	if err := t.check(ctx, "trust.record", ep.IsValid(), key.IsValid()); err != nil {
		return err
	}
	t.withLock(func() {
		if k := ep.String(); !slices.ContainsFunc(t.trusted[k], func(ex ports.PublicKeyInfo) bool { return ex.Fingerprint().Equal(key.Fingerprint()) }) {
			t.trusted[k] = append(t.trusted[k], key)
		}
	})
	return nil
}

// SimInteractionPort 实现 ports.InteractionPort 的可编程确认、审批、文本与机密输入仿真器。
//
//xops:opaque
//xops:failclosed
type SimInteractionPort struct {
	simBase
	interactive, tamperDigest       bool
	confirmVerdict, approvalVerdict security.Verdict
	approvalErr                     error
	textReply                       string
	secretReply                     []byte
}

// NewSimInteractionPort 创建确定性交互端口仿真器。
func NewSimInteractionPort(interactive bool) *SimInteractionPort {
	return &SimInteractionPort{
		simBase: newSimBase(nil), interactive: interactive,
		confirmVerdict: security.VerdictAllow, approvalVerdict: security.VerdictAllow, textReply: "sim-text",
	}
}

// SetInteractive / SetApprovalPolicy / SetReplies 配置交互可用性、审批策略（含摘要篡改）与预设回答。
func (i *SimInteractionPort) SetInteractive(en bool) { i.withLock(func() { i.interactive = en }) }
func (i *SimInteractionPort) SetApprovalPolicy(v security.Verdict, err error, tamper bool) {
	i.withLock(func() { i.approvalVerdict, i.approvalErr, i.tamperDigest = v.Normalize(), err, tamper })
}
func (i *SimInteractionPort) SetReplies(text string, secretBytes []byte) {
	i.withLock(func() { i.textReply, i.secretReply = text, bytes.Clone(secretBytes) })
}
func (i *SimInteractionPort) CanInteract() bool {
	return withLockRet(&i.simBase, false, func() bool { return i.interactive })
}
func (i *SimInteractionPort) checkUI(ctx context.Context, hasFn bool, op string, valid bool) error {
	if err := i.checkFn(ctx, hasFn, op, valid); err != nil {
		return err
	}
	if !i.CanInteract() {
		return ports.ErrInteractionUnavailable
	}
	return nil
}
func (i *SimInteractionPort) Confirm(ctx context.Context, req ports.ConfirmRequest) (security.Verdict, error) {
	if err := i.checkUI(ctx, true, "ui.confirm", req.IsValid()); err != nil {
		return security.VerdictDeny, err
	}
	return withLockRet(&i.simBase, security.VerdictDeny, func() security.Verdict { return i.confirmVerdict.Normalize() }), nil
}
func (i *SimInteractionPort) PromptApproval(ctx context.Context, env security.ApprovalEnvelope) (out ports.ApprovalDecisionResponse, err error) {
	if err = i.checkUI(ctx, true, "ui.approval", env.IsValid()); err != nil {
		return out, err
	}
	i.mu.Lock()
	v, aErr, tamper := i.approvalVerdict, i.approvalErr, i.tamperDigest
	i.mu.Unlock()
	dig, dErr := env.Digest()
	if err = firstErr(aErr, dErr); err != nil {
		return out, err
	}
	if tamper {
		raw, _ := dig.Bytes()
		raw[0] ^= 0xff
		dig = security.DigestFromSHA256(raw)
	}
	return ports.NewApprovalDecisionResponse(v.Normalize(), dig, "sim approval")
}
func (i *SimInteractionPort) PromptText(ctx context.Context, req ports.TextPromptRequest) (string, error) {
	if err := i.checkUI(ctx, true, "ui.text", req.IsValid()); err != nil {
		return "", err
	}
	reply := withLockRet(&i.simBase, "", func() string { return i.textReply })
	if reply == "" && !req.AllowEmpty() {
		return "", ports.ErrInteractionCanceled
	}
	return reply, nil
}

// PromptSecret 经 secret.WithBytes 借出受管 *secret.SecretBox，回调退出前无条件清零。
//
//xops:syncclosure
//xops:borrowed
func (i *SimInteractionPort) PromptSecret(ctx context.Context, req ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	if err := i.checkUI(ctx, fn != nil, "ui.secret", req.IsValid()); err != nil {
		return err
	}
	raw := withLockRet(&i.simBase, nil, func() []byte { return bytes.Clone(i.secretReply) })
	if len(raw) == 0 && !req.AllowEmpty() {
		return ports.ErrInteractionCanceled
	}
	return secret.WithBytes(raw, func(box *secret.SecretBox) error { return fn(box) })
}
