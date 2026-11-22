package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

const (
	OpenSSHNodePrefix = "openssh:"
	maxIncludeDepth   = 16
)

// OpenSSHParser 提供针对 ~/.ssh/config 的解析和模型映射功能
type OpenSSHParser struct {
	cfg *sshConfigDoc
	err error
}

// NewBrokenOpenSSHParser returns an OpenSSHParser that records a load or parse
// failure so callers falling back to OpenSSH fail closed rather than silently degrading.
func NewBrokenOpenSSHParser(err error) *OpenSSHParser {
	return &OpenSSHParser{err: err}
}

// Err returns the load or parse error recorded on p, if any.
func (p *OpenSSHParser) Err() error {
	if p == nil {
		return nil
	}
	return p.err
}

// NewOpenSSHParser 尝试从标准路径加载用户的 ~/.ssh/config 配置文件。
// 如果文件不存在，返回空的 OpenSSHParser 和 nil 错误；其他错误返回具体包装错误。
func NewOpenSSHParser() (*OpenSSHParser, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get user home directory failed: %w", err)
	}
	userConfigPath := filepath.Join(homeDir, ".ssh", "config")
	return NewOpenSSHParserFromPath(userConfigPath)
}

func loadOpenSSHParserFromPath(path string, requireExist bool) (parser *OpenSSHParser, isDevNull bool, retErr error) {
	// Treat platform null-device sentinels ("/dev/null" on all OSes, plus "NUL"
	// and "\\.\NUL" case-insensitively on Windows) uniformly as empty no-op configs.
	if isOpenSSHNullDevicePath(path) {
		return &OpenSSHParser{cfg: nil}, true, nil
	}
	// OpenSSH follows symlinks for root config files (~/.ssh/config and -F)
	// and accepts os.DevNull as an empty config; fsx.OpenRegular opens
	// handle-first without Stat-then-Open and rejects FIFOs/devices/oversize.
	rf, err := fsx.OpenRegular(path, fsx.Limits{MaxBytes: maxOpenSSHConfigFileBytes}, fsx.AllowDevNull(), fsx.FollowSymlinks())
	if err != nil {
		if !requireExist && errors.Is(err, os.ErrNotExist) {
			return &OpenSSHParser{cfg: nil}, false, nil
		}
		if errors.Is(err, fsx.ErrTooLarge) {
			return nil, false, fmt.Errorf("decode ssh config %q failed: ssh config %q size limit (%d bytes) exceeded: %w", path, path, maxOpenSSHConfigFileBytes, err)
		}
		if errors.Is(err, fsx.ErrNonRegular) {
			// Post-rejection diagnostic only (handle open already failed closed).
			if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
				return nil, false, fmt.Errorf("open ssh config %q failed: path is a directory: %w", path, err)
			}
			return nil, false, fmt.Errorf("open ssh config %q failed: not a regular file: %w", path, err)
		}
		return nil, false, fmt.Errorf("open ssh config %q failed: %w", path, err)
	}
	defer func() {
		if closeErr := rf.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("close ssh config %q failed: %w", path, closeErr))
		}
	}()

	if rf.IsDevNull() {
		return &OpenSSHParser{cfg: nil}, true, nil
	}

	cfg, decodeErr := decodeOpenSSHConfig(rf, path)
	if decodeErr != nil {
		return nil, false, fmt.Errorf("decode ssh config %q failed: %w", path, decodeErr)
	}
	return &OpenSSHParser{cfg: cfg}, false, nil
}

// NewOpenSSHParserFromPath 从指定路径加载 SSH 配置文件。如果文件不存在，返回空的 OpenSSHParser 和 nil 错误。
func NewOpenSSHParserFromPath(path string) (*OpenSSHParser, error) {
	parser, _, err := loadOpenSSHParserFromPath(path, false)
	return parser, err
}

// NewOpenSSHParserFromReader 从任意 io.Reader 加载 SSH 配置
func NewOpenSSHParserFromReader(r io.Reader) (*OpenSSHParser, error) {
	if r == nil {
		return &OpenSSHParser{cfg: nil}, nil
	}
	cfg, err := decodeOpenSSHReader(r)
	if err != nil {
		return nil, fmt.Errorf("decode ssh config failed: %w", err)
	}
	return &OpenSSHParser{cfg: cfg}, nil
}

// WithOpenSSHConfigOverride returns a read-only ConfigProvider whose OpenSSH
// configuration is overridden by configPath:
//   - "" returns base unchanged;
//   - "none" (case-insensitive) attaches an empty OpenSSHParser so ~/.ssh/config is skipped;
//   - Any other path loads that file via loadOpenSSHParserFromPath and returns an
//     explicit error if the file does not exist or cannot be read.
func WithOpenSSHConfigOverride(base ConfigProvider, configPath string) (ConfigProvider, error) {
	if configPath == "" {
		return base, nil
	}
	isNone := strings.EqualFold(strings.TrimSpace(configPath), "none")
	var (
		parser    *OpenSSHParser
		isDevNull bool
		err       error
	)
	if isNone {
		parser = &OpenSSHParser{cfg: nil}
	} else {
		parser, isDevNull, err = loadOpenSSHParserFromPath(configPath, true)
		if err != nil {
			return nil, err
		}
	}
	var (
		snap    *Configuration
		origins map[string]OpenSSHOrigin
	)
	if base != nil {
		if src, ok := base.(interface {
			snapshotWithOrigins() (*Configuration, map[string]OpenSSHOrigin)
		}); ok {
			snap, origins = src.snapshotWithOrigins()
		} else {
			snap = base.Snapshot()
		}
	}
	repo, err := NewRepositoryWithOpenSSHParser(snap, readOnlyRejectStore{}, parser)
	if err != nil {
		return nil, fmt.Errorf("create ephemeral ssh config override provider: %w", err)
	}
	if !isNone && !isDevNull {
		copyOverrideOpenSSHOrigins(repo.provider, base, parser, snap, origins, configPath)
	}
	return &openSSHOverrideProvider{ConfigProvider: repo, repo: repo}, nil
}

func copyOverrideOpenSSHOrigins(
	dst *Provider,
	base ConfigProvider,
	parser *OpenSSHParser,
	snap *Configuration,
	origins map[string]OpenSSHOrigin,
	configPath string,
) {
	if dst == nil || snap == nil || snap.Nodes == nil {
		return
	}
	sameDefault := sameDefaultOpenSSHConfigPath(configPath)
	copyOriginIfAllowed := func(nodeID string, origin OpenSSHOrigin) {
		if origin.IsZero() {
			return
		}
		if !sameDefault && !originCompatibleWithOverrideParser(parser, snap, nodeID, origin) {
			return
		}
		dst.setSavedNodeOpenSSHMetadataIfPresent(nodeID, origin.Alias, origin.CanonicalHost)
	}
	if origins != nil {
		for nodeID, origin := range origins {
			if _, exists := snap.Nodes.Get(nodeID); exists {
				copyOriginIfAllowed(nodeID, origin)
			}
		}
		return
	}
	if base == nil {
		return
	}
	for _, nodeID := range snap.Nodes.Keys() {
		baseNode, ok := base.GetNode(nodeID)
		if !ok {
			continue
		}
		copyOriginIfAllowed(nodeID, OpenSSHOrigin{
			Alias:         baseNode.OpenSSHAlias,
			CanonicalHost: baseNode.CanonicalHost,
		})
	}
}

func sameDefaultOpenSSHConfigPath(configPath string) bool {
	homeDir, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(homeDir) == "" {
		return false
	}
	defaultPath := filepath.Join(homeDir, ".ssh", "config")
	absConfig, errA := filepath.Abs(configPath)
	absDefault, errB := filepath.Abs(defaultPath)
	if errA != nil || errB != nil {
		return false
	}
	if absConfig == absDefault {
		return true
	}
	infoA, errA := os.Stat(absConfig)
	infoB, errB := os.Stat(absDefault)
	return errA == nil && errB == nil && os.SameFile(infoA, infoB)
}

func originCompatibleWithOverrideParser(parser *OpenSSHParser, snap *Configuration, nodeID string, origin OpenSSHOrigin) bool {
	if parser == nil || parser.cfg == nil || origin.IsZero() {
		return false
	}
	alias := strings.TrimSpace(origin.Alias)
	if alias == "" || !parser.HasHost(alias) {
		return false
	}
	if snap == nil || snap.Nodes == nil {
		return false
	}
	node, ok := snap.Nodes.Get(nodeID)
	if !ok {
		return false
	}
	host, hasHost := snap.Hosts.Get(node.HostRef)
	if resolvedHost, explicit, err := parser.ResolveExplicitHostName(alias); err != nil {
		return false
	} else if explicit && hasHost {
		nodeEp, nErr := ssh.NewEndpoint(host.Address, int(host.Port))
		resolvedPort := 22
		if rawPort := strings.TrimSpace(parser.getVal(alias, "Port", "22")); rawPort != "" {
			if p, pErr := strconv.ParseUint(rawPort, 10, 16); pErr == nil && p > 0 {
				resolvedPort = int(p)
			} else {
				return false
			}
		}
		resolvedEp, rErr := ssh.NewEndpoint(resolvedHost, resolvedPort)
		if nErr != nil || rErr != nil || !resolvedEp.Equal(nodeEp) {
			return false
		}
	}
	return true
}

type readOnlyRejectStore struct{}

func (readOnlyRejectStore) Load() (*Configuration, error) {
	return nil, errors.New("read-only OpenSSH override store does not support Load")
}

func (readOnlyRejectStore) Save(*Configuration) error {
	return errors.New("read-only OpenSSH override store does not support Save")
}

const maxOverrideConfirmedSnapshots = 64

type openSSHOverrideProvider struct {
	ConfigProvider
	repo *Repository

	confirmedMu    sync.RWMutex
	confirmed      map[string]ConnectionSnapshot
	confirmedOrder []string
}

func cloneConnectionSnapshot(snap ConnectionSnapshot) ConnectionSnapshot {
	out := ConnectionSnapshot{
		Node:       cloneNode(snap.Node),
		Host:       cloneHost(snap.Host),
		Identity:   cloneIdentity(snap.Identity),
		Provenance: snap.Provenance,
	}
	if snap.UpdateRef != nil {
		refCopy := *snap.UpdateRef
		out.UpdateRef = &refCopy
	}
	return out
}

func (p *openSSHOverrideProvider) recordConfirmedSnapshot(nodeID string, snap ConnectionSnapshot) {
	p.confirmedMu.Lock()
	defer p.confirmedMu.Unlock()
	if p.confirmed == nil {
		p.confirmed = make(map[string]ConnectionSnapshot)
	}
	if _, exists := p.confirmed[nodeID]; !exists {
		for len(p.confirmedOrder) >= maxOverrideConfirmedSnapshots {
			oldest := p.confirmedOrder[0]
			p.confirmedOrder = p.confirmedOrder[1:]
			delete(p.confirmed, oldest)
		}
		p.confirmedOrder = append(p.confirmedOrder, nodeID)
	}
	p.confirmed[nodeID] = cloneConnectionSnapshot(snap)
}

func (p *openSSHOverrideProvider) forgetConfirmedSnapshot(nodeID string) {
	p.confirmedMu.Lock()
	defer p.confirmedMu.Unlock()
	if _, exists := p.confirmed[nodeID]; !exists {
		return
	}
	delete(p.confirmed, nodeID)
	for i, id := range p.confirmedOrder {
		if id == nodeID {
			p.confirmedOrder = append(p.confirmedOrder[:i], p.confirmedOrder[i+1:]...)
			break
		}
	}
}

func (p *openSSHOverrideProvider) loadConfirmedSnapshot(nodeID string) (ConnectionSnapshot, bool) {
	p.confirmedMu.RLock()
	defer p.confirmedMu.RUnlock()
	snap, ok := p.confirmed[nodeID]
	if !ok {
		return ConnectionSnapshot{}, false
	}
	return cloneConnectionSnapshot(snap), true
}

type overridePendingLease struct {
	provider  *openSSHOverrideProvider
	nodeID    string
	entry     *pendingConnection
	mu        sync.Mutex
	confirmed bool
	closed    bool
}

var (
	_ PendingLease          = (*overridePendingLease)(nil)
	_ PendingExecutionLease = (*overridePendingLease)(nil)
)

func (l *overridePendingLease) NodeID() string {
	if l == nil {
		return ""
	}
	return l.nodeID
}

func (l *overridePendingLease) Confirm(context.Context) error {
	return l.confirm()
}

func (l *overridePendingLease) ConfirmWithExecution(context.Context, *ssh.ExecutionConfig) error {
	return l.confirm()
}

func (l *overridePendingLease) confirm() error {
	if l == nil || l.provider == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return fmt.Errorf("pending lease for %q is closed", l.nodeID)
	}
	if l.confirmed {
		l.mu.Unlock()
		return nil
	}
	l.confirmed = true
	entry := l.entry
	nodeID := l.nodeID
	l.mu.Unlock()
	l.provider.confirmEphemeralNode(nodeID, entry)
	return nil
}

// WithPendingNode prepares an ephemeral pending node under the read-only -F
// override provider. Ephemeral pending nodes are never persisted to disk and
// are always discarded on return, error, cancellation, or panic.
func (p *openSSHOverrideProvider) WithPendingNode(ctx context.Context, req EnsureNodeOptions, fn func(PendingLease) error) error {
	if p == nil || p.repo == nil || ctx == nil || fn == nil {
		return fmt.Errorf("prepare override connection requires provider, context, and callback")
	}
	// Read-only -F overrides never mutate saved nodes on disk.
	req.ExistingUpdate.Enabled = false
	res, entry, err := p.repo.prepareNodeContext(ctx, req)
	if err != nil {
		return err
	}
	if res.Created && res.NodeID != "" {
		p.forgetConfirmedSnapshot(res.NodeID)
	}
	lease := &overridePendingLease{
		provider: p,
		nodeID:   res.NodeID,
		entry:    entry,
	}
	defer func() {
		lease.mu.Lock()
		wasConfirmed := lease.confirmed
		lease.closed = true
		lease.mu.Unlock()
		if !wasConfirmed && entry != nil {
			p.repo.discardPendingEntry(res.NodeID, entry)
		}
	}()
	return fn(lease)
}

func (p *openSSHOverrideProvider) IsPendingNode(nodeID string) bool {
	if p == nil || p.repo == nil {
		return false
	}
	return p.repo.IsPendingNode(nodeID)
}

func (p *openSSHOverrideProvider) Resolve(nodeID string) (models.Node, models.Host, models.Identity, error) {
	node, host, ident, err := p.repo.Resolve(nodeID)
	if err == nil {
		return node, host, ident, nil
	}
	if errors.Is(err, ErrNodeNotFound) {
		if snap, ok := p.loadConfirmedSnapshot(nodeID); ok {
			return snap.Node, snap.Host, snap.Identity, nil
		}
	}
	return models.Node{}, models.Host{}, models.Identity{}, err
}

func (p *openSSHOverrideProvider) ResolveConnection(nodeID string) (ConnectionSnapshot, error) {
	snap, err := p.repo.ResolveConnection(nodeID)
	if err == nil {
		return snap, nil
	}
	if errors.Is(err, ErrNodeNotFound) {
		if confirmed, ok := p.loadConfirmedSnapshot(nodeID); ok {
			return confirmed, nil
		}
	}
	return ConnectionSnapshot{}, err
}

func (p *openSSHOverrideProvider) ResolveConnectionWithOrigin(nodeID, originalHost string) (ConnectionSnapshot, error) {
	snap, err := p.repo.ResolveConnectionWithOrigin(nodeID, originalHost)
	if err == nil {
		return snap, nil
	}
	if errors.Is(err, ErrNodeNotFound) {
		if confirmed, ok := p.loadConfirmedSnapshot(nodeID); ok {
			return confirmed, nil
		}
	}
	return ConnectionSnapshot{}, err
}

func (p *openSSHOverrideProvider) GetOpenSSHParser() *OpenSSHParser {
	return p.repo.GetOpenSSHParser()
}

func (p *openSSHOverrideProvider) snapshotWithOrigins() (*Configuration, map[string]OpenSSHOrigin) {
	if p == nil || p.repo == nil {
		return cloneConfiguration(nil), nil
	}
	return p.repo.snapshotWithOrigins()
}

func (p *openSSHOverrideProvider) NodeOpenSSHOrigin(nodeID string) OpenSSHOrigin {
	if origin := p.repo.NodeOpenSSHOrigin(nodeID); !origin.IsZero() {
		return origin
	}
	if snap, ok := p.loadConfirmedSnapshot(nodeID); ok {
		return normalizeOpenSSHOrigin(OpenSSHOrigin{
			Alias:         snap.Node.OpenSSHAlias,
			CanonicalHost: snap.Node.CanonicalHost,
		})
	}
	return OpenSSHOrigin{}
}

func (p *openSSHOverrideProvider) SetNodeOpenSSHOrigin(nodeID string, origin OpenSSHOrigin) {
	p.repo.SetNodeOpenSSHOrigin(nodeID, origin)
}

func (p *openSSHOverrideProvider) ClearNodeOpenSSHOrigin(nodeID string) {
	p.repo.ClearNodeOpenSSHOrigin(nodeID)
}

func (p *openSSHOverrideProvider) SetNodeOpenSSHAlias(nodeID, alias string) {
	p.repo.SetNodeOpenSSHAlias(nodeID, alias)
}

func (p *openSSHOverrideProvider) NodeOpenSSHAlias(nodeID string) string {
	return p.NodeOpenSSHOrigin(nodeID).Alias
}

func (p *openSSHOverrideProvider) SetNodeCanonicalHost(nodeID, canonicalHost string) {
	p.repo.SetNodeCanonicalHost(nodeID, canonicalHost)
}

func (p *openSSHOverrideProvider) NodeCanonicalHost(nodeID string) string {
	return p.NodeOpenSSHOrigin(nodeID).CanonicalHost
}

func (p *openSSHOverrideProvider) confirmEphemeralNode(nodeID string, entry *pendingConnection) {
	if p == nil || p.repo == nil || nodeID == "" {
		return
	}
	if !IsOpenSSHNodeID(nodeID) {
		if snap, ok := p.repo.pendingConnectionSnapshot(nodeID); ok {
			p.recordConfirmedSnapshot(nodeID, snap)
		}
	}
	p.repo.discardPendingEntry(nodeID, entry)
}

func (p *openSSHOverrideProvider) PendingNodeExecution(string) (*ssh.ExecutionConfig, bool) {
	return nil, false
}

func (*openSSHOverrideProvider) UpdateAuthAtVersionContext(_ context.Context, _, authVersion, _, _, _ string) (string, error) {
	return authVersion, nil
}

func (*openSSHOverrideProvider) UpdateSudoAtVersionContext(_ context.Context, _, sudoVersion string, _ models.SudoMode, _ string) (string, error) {
	return sudoVersion, nil
}

// OpenSSHOriginalHost extracts the effective original host (%n) for an
// "openssh:" virtual node ID (case-insensitive prefix) by stripping the prefix
// and decomposing composite user@host[:port] specs into their host token.
// Empty, whitespace-padded, control-containing, or double-prefixed selectors
// (e.g. "openssh: web", "openssh:OPENSSH:web") are rejected.
func OpenSSHOriginalHost(nodeID string) (string, bool) {
	rest, ok := cutOpenSSHPrefix(nodeID)
	if !ok {
		return "", false
	}
	if rest == "" || hasControlOrLineSepChar(rest) || hasAnyWhitespace(rest) || hasOpenSSHPrefix(rest) {
		return "", false
	}
	if parsedHost, _, _, err := parseOpenSSHHostSpec(rest); err == nil && parsedHost != "" {
		return parsedHost, true
	}
	return rest, true
}

// UnwrapOpenSSHSelector extracts the host/alias token from an optional
// case-insensitive "openssh:" virtual selector (including disambiguated
// "openssh:user@alias:port"), returns "" for empty, whitespace-padded, or
// double-prefixed "openssh:" selectors, and returns the trimmed input unchanged
// otherwise.
func UnwrapOpenSSHSelector(selector string) string {
	if hasOpenSSHPrefix(selector) {
		if orig, ok := OpenSSHOriginalHost(selector); ok {
			return orig
		}
		return ""
	}
	trimmed := strings.TrimSpace(selector)
	if hasOpenSSHPrefix(trimmed) {
		return ""
	}
	return trimmed
}

func stripOpenSSHSelectorForLookup(alias string) (string, bool) {
	if hasOpenSSHPrefix(alias) {
		rest, _ := cutOpenSSHPrefix(alias)
		if rest == "" || hasControlOrLineSepChar(rest) || hasAnyWhitespace(rest) || hasOpenSSHPrefix(rest) {
			return "", false
		}
		return rest, true
	}
	trimmed := strings.TrimSpace(alias)
	if trimmed == "" || hasOpenSSHPrefix(trimmed) {
		return "", false
	}
	return trimmed, true
}

func hasAnyWhitespace(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// parseExplicitOpenSSHSelector validates and parses an explicit "openssh:"
// selector body fail-closed without trimming leading/trailing whitespace
// padding (rejecting "openssh: web", "openssh:\u00a0web", "openssh:web ",
// control characters, and duplicate "openssh:" prefixes).
func parseExplicitOpenSSHSelector(raw string) (spec, lookupHost, inlineUser string, inlinePort uint16, err error) {
	after, ok := TrimOpenSSHNodePrefix(raw)
	if !ok {
		return "", "", "", 0, fmt.Errorf("parse openssh host %q failed: invalid openssh selector", raw)
	}
	if after == "" || hasControlOrLineSepChar(after) || hasAnyWhitespace(after) || hasOpenSSHPrefix(after) {
		return "", "", "", 0, fmt.Errorf("parse openssh host %q failed: invalid openssh selector", raw)
	}
	lookupHost, inlineUser, inlinePort, err = parseOpenSSHHostSpec(after)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("parse openssh host %q failed: %w", after, err)
	}
	return after, lookupHost, inlineUser, inlinePort, nil
}

// Find 尝试在 ssh_config 中寻找匹配的主机名
// 如果用户输入了未知主机，我们一律返回带前缀的虚拟 NodeID，
// 在连接时利用 ssh_config 的默认回退属性来尝试连接，
// 这样使得 xops 表现得和原生 ssh 命令的体验完全一致。
func (p *OpenSSHParser) Find(alias string) (string, bool) {
	if !IsPlainOpenSSHHostSelector(alias) {
		return "", false
	}
	return OpenSSHNodePrefix + StripHostBrackets(alias), true
}

// HasHost 检查 alias 是否在 ssh_config（含 Include 子配置）中显式定义了具体的 Host 模式（排除仅通配符匹配与否定排除）。
func (p *OpenSSHParser) HasHost(alias string) bool {
	if p == nil || p.cfg == nil || alias == "" {
		return false
	}
	cleanAlias, ok := stripOpenSSHSelectorForLookup(alias)
	if !ok {
		return false
	}
	lookupAlias, _, _, err := parseOpenSSHHostSpec(cleanAlias)
	if err != nil {
		lookupAlias = cleanAlias
	}
	if lookupAlias == "" {
		return false
	}
	found := false
	walkMatchingSSHConfigBlocks(p.cfg, lookupAlias, func(block *sshConfigBlock) bool {
		if block.matchesConcretePattern(lookupAlias) {
			found = true
			return false
		}
		return true
	})
	return found
}

func hasControlOrLineSepChar(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func unwrapExpandedHostName(rawHostName, expanded string) string {
	clean := StripHostBrackets(expanded)
	rawTrimmed := strings.TrimSpace(rawHostName)
	if len(rawTrimmed) >= 2 && rawTrimmed[0] == '[' && rawTrimmed[len(rawTrimmed)-1] == ']' &&
		strings.Contains(rawTrimmed, "%") &&
		len(clean) >= 2 && clean[0] == '[' && clean[len(clean)-1] == ']' {
		inner := strings.TrimSpace(clean[1 : len(clean)-1])
		if inner != "" {
			if ip, err := netip.ParseAddr(inner); err != nil || ip.Is6() {
				return inner
			}
		}
	}
	return clean
}

func hasInternalWhitespace(raw string) bool {
	for _, r := range strings.TrimSpace(raw) {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// ResolveExplicitHostName returns the expanded HostName configured for alias
// when an explicit HostName directive matches alias, with explicit=false if
// no HostName directive is configured.
func (p *OpenSSHParser) ResolveExplicitHostName(alias string) (hostName string, explicit bool, err error) {
	if p == nil || p.cfg == nil {
		return "", false, nil
	}
	if p.err != nil {
		return "", false, p.err
	}
	cleanAlias, ok := stripOpenSSHSelectorForLookup(alias)
	if !ok {
		return "", false, nil
	}
	lookupAlias, _, _, parseErr := parseOpenSSHHostSpec(cleanAlias)
	if parseErr != nil || lookupAlias == "" {
		lookupAlias = cleanAlias
	}
	if firstSSHConfigKeyValue(p.cfg, lookupAlias, "HostName") == "" {
		return "", false, nil
	}
	resolved, resolveErr := resolveOpenSSHHostName(p.cfg, lookupAlias)
	if resolveErr != nil {
		return "", true, resolveErr
	}
	return resolved, true, nil
}

// ResolveExplicitPort returns the explicit Port configured for alias when a
// Port directive matches alias, with explicit=false if no Port directive is configured.
func (p *OpenSSHParser) ResolveExplicitPort(alias string) (port uint16, explicit bool, err error) {
	if p == nil || p.cfg == nil {
		return 0, false, nil
	}
	if p.err != nil {
		return 0, false, p.err
	}
	cleanAlias, ok := stripOpenSSHSelectorForLookup(alias)
	if !ok {
		return 0, false, nil
	}
	lookupAlias, _, _, parseErr := parseOpenSSHHostSpec(cleanAlias)
	if parseErr != nil || lookupAlias == "" {
		lookupAlias = cleanAlias
	}
	rawPort := strings.TrimSpace(firstSSHConfigKeyValue(p.cfg, lookupAlias, "Port"))
	if rawPort == "" {
		return 0, false, nil
	}
	parsedPort, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || parsedPort == 0 {
		return 0, true, fmt.Errorf("invalid port %q for %q in ssh config", rawPort, alias)
	}
	return uint16(parsedPort), true, nil
}

func resolveOpenSSHHostName(doc *sshConfigDoc, alias string) (string, error) {
	rawHostName := firstSSHConfigKeyValue(doc, alias, "HostName")
	if rawHostName == "" {
		if hasControlOrLineSepChar(alias) {
			return "", fmt.Errorf("HostName %q contains invalid control characters", alias)
		}
		unwrapped := StripHostBrackets(alias)
		if unwrapped == "" {
			return "", errors.New("HostName cannot be empty")
		}
		return unwrapped, nil
	}
	expanded, err := ssh.ExpandHostName(rawHostName, alias)
	if err != nil {
		return "", err
	}
	return unwrapExpandedHostName(rawHostName, expanded), nil
}

// FindConcreteHostsByAddress returns concrete Host pattern names in ssh_config
// whose resolved (HostName, Port) endpoint matches ep via strict ssh.Endpoint.Equal.
func (p *OpenSSHParser) FindConcreteHostsByAddress(ep ssh.Endpoint) []string {
	if p == nil || p.cfg == nil || !ep.IsValid() {
		return nil
	}
	var matches []string
	walkConcreteSSHHostNames(p.cfg, func(name string) bool {
		candEp, ok := p.resolveConcreteEndpoint(name)
		if !ok || !candEp.Equal(ep) {
			return true
		}
		matches = append(matches, name)
		return true
	})
	return matches
}

// FindConcreteHostsByHost returns concrete Host pattern names in ssh_config
// whose resolved HostName matches ep's canonical host ignoring port.
//
// SECURITY: Port-agnostic helper; NOT for Tier-4 security scoping. Use
// FindConcreteHostsByAddress for all security scoping and option inheritance.
func (p *OpenSSHParser) FindConcreteHostsByHost(ep ssh.Endpoint) []string {
	if p == nil || p.cfg == nil || !ep.IsValid() {
		return nil
	}
	var matches []string
	walkConcreteSSHHostNames(p.cfg, func(name string) bool {
		candEp, ok := p.resolveConcreteEndpoint(name)
		if !ok || !candEp.HostEqual(ep) {
			return true
		}
		matches = append(matches, name)
		return true
	})
	return matches
}

func (p *OpenSSHParser) resolveConcreteEndpoint(name string) (ssh.Endpoint, bool) {
	cleanHost, expErr := resolveOpenSSHHostName(p.cfg, name)
	if expErr != nil || cleanHost == "" {
		return ssh.Endpoint{}, false
	}
	portStr := strings.TrimSpace(p.getVal(name, "Port", "22"))
	parsedPort, parseErr := strconv.ParseUint(portStr, 10, 16)
	if parseErr != nil || parsedPort == 0 {
		return ssh.Endpoint{}, false
	}
	ep, err := ssh.NewEndpoint(cleanHost, int(parsedPort))
	if err != nil {
		return ssh.Endpoint{}, false
	}
	return ep, true
}

// ResolveEndpoint resolves the canonical (HostName, Port) Endpoint for alias
// in ssh_config (defaulting Port to 22).
func (p *OpenSSHParser) ResolveEndpoint(alias string) (ssh.Endpoint, error) {
	if p == nil || p.cfg == nil {
		return ssh.Endpoint{}, fmt.Errorf("openssh parser is empty")
	}
	cleanHost, err := resolveOpenSSHHostName(p.cfg, alias)
	if err != nil {
		return ssh.Endpoint{}, err
	}
	portStr := strings.TrimSpace(p.getVal(alias, "Port", "22"))
	parsedPort, parseErr := strconv.ParseUint(portStr, 10, 16)
	if parseErr != nil || parsedPort == 0 {
		return ssh.Endpoint{}, fmt.Errorf("invalid port %q for %q in ssh config", portStr, alias)
	}
	return ssh.NewEndpoint(cleanHost, int(parsedPort))
}

// ResolveProxySetting folds all matching ProxyJump and ProxyCommand directives
// for alias into a typed ssh.ProxySetting (preserving shadowed ProxyCommand
// fallback beneath a higher ProxyJump for associative cross-tier merging).
// Malformed ProxyJump/ProxyCommand directives return an error fail-closed.
func (p *OpenSSHParser) ResolveProxySetting(alias string) (ssh.ProxySetting, error) {
	return p.ResolveProxySettingWithCanonical(alias, "")
}

// ResolveProxySettingWithCanonical folds all matching ProxyJump and ProxyCommand
// directives across Pass 1 (originalAlias) and Pass 2 (canonicalHost).
// Malformed ProxyJump/ProxyCommand directives return an error fail-closed.
func (p *OpenSSHParser) ResolveProxySettingWithCanonical(originalAlias, canonicalHost string) (ssh.ProxySetting, error) {
	if p != nil && p.err != nil {
		return ssh.UnsetProxySetting(), p.err
	}
	if p == nil || p.cfg == nil || strings.TrimSpace(originalAlias) == "" {
		return ssh.UnsetProxySetting(), nil
	}
	cleanAlias, ok := stripOpenSSHSelectorForLookup(originalAlias)
	if !ok {
		if hasOpenSSHPrefix(strings.TrimSpace(originalAlias)) {
			return ssh.UnsetProxySetting(), fmt.Errorf("invalid openssh selector %q", originalAlias)
		}
		return ssh.UnsetProxySetting(), nil
	}
	lookupAlias, _, _, err := parseOpenSSHHostSpec(cleanAlias)
	if err != nil || lookupAlias == "" {
		lookupAlias = cleanAlias
	}
	passes := []string{lookupAlias}
	cleanCanon := StripHostBrackets(canonicalHost)
	if cleanCanon != "" && !strings.EqualFold(cleanCanon, lookupAlias) {
		passes = append(passes, cleanCanon)
	}
	return resolveOpenSSHProxySettingPasses(p.cfg, passes)
}

// GetVirtualNode 根据 alias 从 ssh_config 生成运行时的内存 Node / Host / Identity
func (p *OpenSSHParser) GetVirtualNode(alias string) (models.Node, models.Host, models.Identity, error) {
	return p.GetVirtualNodeWithCanonical(alias, "")
}

// GetVirtualNodeWithCanonical evaluates ssh_config across Pass 1 (originalAlias)
// and Pass 2 (canonicalHost) when canonicalHost differs from originalAlias.
func (p *OpenSSHParser) GetVirtualNodeWithCanonical(originalAlias, canonicalHost string) (models.Node, models.Host, models.Identity, error) {
	if p == nil {
		p = &OpenSSHParser{cfg: nil}
	}
	if p.err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, p.err
	}
	lookupAlias, userOverride, portOverride, err := parseOpenSSHHostSpec(originalAlias)
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("parse openssh host %q failed: %w", originalAlias, err)
	}
	return p.getVirtualNodeWithCanonical(lookupAlias, canonicalHost, userOverride, portOverride, originalAlias)
}

func (p *OpenSSHParser) resolveVirtualHostAndPasses(lookupAlias, canonicalHost string) ([]string, string, error) {
	cleanCanon := StripHostBrackets(canonicalHost)
	passes := []string{lookupAlias}
	if cleanCanon == "" || strings.EqualFold(cleanCanon, lookupAlias) {
		hostName, err := resolveOpenSSHHostName(p.cfg, lookupAlias)
		return passes, hostName, err
	}
	passes = append(passes, cleanCanon)
	if firstSSHConfigKeyValue(p.cfg, lookupAlias, "HostName") != "" {
		if hasControlOrLineSepChar(cleanCanon) {
			return nil, "", fmt.Errorf("HostName %q contains invalid control characters", cleanCanon)
		}
		return passes, cleanCanon, nil
	}
	hostName, err := resolveOpenSSHHostName(p.cfg, cleanCanon)
	return passes, hostName, err
}

func validateVirtualNodeInputs(lookupAlias, canonicalHost, userOverride, nodeAlias string) (cleanLookup, cleanUser, cleanNodeAlias string, err error) {
	if hasControlOrLineSepChar(lookupAlias) || hasInternalWhitespace(lookupAlias) {
		return "", "", "", fmt.Errorf("hostname %q contains invalid control or whitespace characters", lookupAlias)
	}
	cleanLookup = strings.TrimSpace(lookupAlias)
	if cleanLookup == "" {
		return "", "", "", fmt.Errorf("parse openssh host %q failed: host is empty", nodeAlias)
	}
	cleanNodeAlias = strings.TrimSpace(nodeAlias)
	if cleanNodeAlias == "" {
		cleanNodeAlias = cleanLookup
	}
	if hasControlOrLineSepChar(canonicalHost) || hasInternalWhitespace(canonicalHost) {
		return "", "", "", fmt.Errorf("hostname %q contains invalid control or whitespace characters", canonicalHost)
	}
	if hasControlOrLineSepChar(userOverride) || hasInternalWhitespace(userOverride) {
		return "", "", "", fmt.Errorf("user %q contains invalid control or whitespace characters", userOverride)
	}
	return cleanLookup, strings.TrimSpace(userOverride), cleanNodeAlias, nil
}

func (p *OpenSSHParser) getVirtualNodeWithCanonical(
	lookupAlias, canonicalHost, userOverride string,
	portOverride uint16,
	nodeAlias string,
) (models.Node, models.Host, models.Identity, error) {
	if p == nil {
		p = &OpenSSHParser{cfg: nil}
	}
	if p.err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, p.err
	}
	var inputErr error
	lookupAlias, userOverride, nodeAlias, inputErr = validateVirtualNodeInputs(lookupAlias, canonicalHost, userOverride, nodeAlias)
	if inputErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, inputErr
	}
	passes, hostName, expHostErr := p.resolveVirtualHostAndPasses(lookupAlias, canonicalHost)
	if expHostErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, expHostErr
	}

	user := firstSSHConfigKeyValuePasses(p.cfg, passes, "User")
	if user == "" {
		defUser, userErr := getCurrentUser()
		if userErr != nil {
			return models.Node{}, models.Host{}, models.Identity{}, userErr
		}
		user = defUser
	}
	portStr := strings.TrimSpace(firstSSHConfigKeyValuePasses(p.cfg, passes, "Port"))
	if portStr == "" {
		portStr = "22"
	}
	parsedPort, parseErr := strconv.ParseUint(portStr, 10, 16)
	if parseErr != nil || parsedPort == 0 {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("invalid port %q for %q in ssh config: must be between 1 and 65535", portStr, lookupAlias)
	}
	port := uint16(parsedPort)
	if userOverride != "" {
		user = userOverride
	}
	if portOverride != 0 {
		port = portOverride
	}

	identityFile, expErr := normalizeConfigIdentityKeyPath(firstSSHConfigKeyValuePasses(p.cfg, passes, "IdentityFile"))
	if expErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, expErr
	}

	proxySetting, proxyErr := resolveOpenSSHProxySettingPasses(p.cfg, passes)
	if proxyErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, proxyErr
	}
	proxyJump := ""
	if targets, ok := proxySetting.JumpTargets(); ok {
		proxyJump = parseOpenSSHProxyJump(strings.Join(targets, ","))
	}

	sshOpts, err := parseOpenSSHOptionsPasses(p.cfg, passes)
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, err
	}

	hostRef := FormatHostPort(hostName, port)
	identityRef := fmt.Sprintf("%s@%s", user, hostName)

	node := models.Node{
		HostRef:     hostRef,
		IdentityRef: identityRef,
		ProxyJump:   proxyJump,
		SudoMode:    models.SudoModeAuto, // 对于导入节点，依然支持 auto
		Tags:        []string{"openssh"}, // 打一个虚拟 tag
		Alias:       []string{nodeAlias},
		SSHOptions:  sshOpts,
	}

	host := models.Host{
		Address: hostName,
		Port:    port,
	}

	identity := models.Identity{
		User:     user,
		AuthType: "auto", // 我们会在 connector 中专门处理 auto 类型的增强 fallback 链
		KeyPath:  identityFile,
	}

	return node, host, identity, nil
}

// GetSSHOptions parses supported OpenSSH client options for a given alias/host in ssh_config.
func (p *OpenSSHParser) GetSSHOptions(alias string) (*ssh.Options, error) {
	return p.GetSSHOptionsWithCanonical(alias, "")
}

// GetSSHOptionsWithCanonical evaluates supported OpenSSH client options across
// Pass 1 (originalAlias) and Pass 2 (canonicalHost) when canonicalHost differs.
func (p *OpenSSHParser) GetSSHOptionsWithCanonical(originalAlias, canonicalHost string) (*ssh.Options, error) {
	if p != nil && p.err != nil {
		return nil, p.err
	}
	if p == nil || p.cfg == nil || originalAlias == "" {
		return nil, nil
	}
	cleanAlias, ok := stripOpenSSHSelectorForLookup(originalAlias)
	if !ok {
		if hasOpenSSHPrefix(strings.TrimSpace(originalAlias)) {
			return nil, fmt.Errorf("invalid openssh selector %q", originalAlias)
		}
		return nil, nil
	}
	lookupAlias, _, _, err := parseOpenSSHHostSpec(cleanAlias)
	if err != nil {
		lookupAlias = cleanAlias
	}
	passes := []string{lookupAlias}
	cleanCanon := StripHostBrackets(canonicalHost)
	if cleanCanon != "" && !strings.EqualFold(cleanCanon, lookupAlias) {
		passes = append(passes, cleanCanon)
	}
	return parseOpenSSHOptionsPasses(p.cfg, passes)
}

// GetControlConfig parses multiplexing options for a given alias/host in ssh_config.
func (p *OpenSSHParser) GetControlConfig(alias string) (*ssh.ControlConfig, error) {
	opts, err := p.GetSSHOptions(alias)
	if err != nil || opts == nil {
		return nil, err
	}
	return opts.ControlConfig(), nil
}

func parseOpenSSHOptions(doc *sshConfigDoc, host string) (*ssh.Options, error) {
	return parseOpenSSHOptionsPasses(doc, []string{host})
}

func parseOpenSSHOptionsPasses(doc *sshConfigDoc, passes []string) (*ssh.Options, error) {
	if doc == nil || len(passes) == 0 {
		return nil, nil
	}
	opts := &ssh.Options{}
	for _, spec := range ssh.RegisteredOptionSpecs() {
		if err := applyOpenSSHSpecOptionPasses(doc, passes, spec, opts); err != nil {
			return nil, err
		}
	}
	if opts.IsEmpty() {
		return nil, nil
	}
	return opts, nil
}

func applyOpenSSHSpecOptionPasses(doc *sshConfigDoc, passes []string, spec ssh.OptionSpec, opts *ssh.Options) error {
	// Enforce declarative Tier-4 (~/.ssh/config) inheritance policy so wildcard
	// host blocks cannot implicitly weaken host key verification.
	if spec.Tier4Policy == ssh.OptionTier4Deny {
		return nil
	}
	if spec.MultiValue {
		rawVals := allMatchingOpenSSHOptionsPasses(doc, passes, spec)
		if spec.MergeMode.SingleDirectivePerLayer() {
			// OpenSSH evaluates only the first matching directive in ssh_config
			// (e.g. SetEnv retains the first occurrence per key inside it).
			// Even if that first directive is invalid, lower blocks must not apply.
			if len(rawVals) > 0 {
				_ = opts.Append(spec.CanonicalKey, rawVals[0])
			}
			return nil
		}
		for _, rawVal := range rawVals {
			if err := opts.Append(spec.CanonicalKey, rawVal); err != nil {
				// Leniently skip invalid or unsupported multi-value entries
				// (e.g. malformed multi-value entries).
				continue
			}
		}
		return nil
	}
	val, skip, err := resolveOpenSSHSingleOptionPasses(doc, passes, spec)
	if err != nil {
		return err
	}
	if skip || val == "" {
		return nil
	}
	if spec.Tier4Policy == ssh.OptionTier4OneWayYes {
		trimmed := strings.TrimSpace(val)
		if !strings.EqualFold(trimmed, "yes") && !strings.EqualFold(trimmed, "true") {
			return nil
		}
	}
	if spec.AllowList {
		parsed, err := ssh.ParseOption(spec.CanonicalKey, val, ssh.OptionSourceOpenSSHConfig)
		if err != nil {
			return fmt.Errorf("invalid %s %q for %q in ssh config: %w", spec.OpenSSHName, val, passes[0], err)
		}
		if parsed.IsNoOp {
			if !parsed.AlgoPolicy.IsUnset() {
				opts.SetAlgoPolicy(parsed.AlgoPolicy)
			}
			return nil
		}
		val = parsed.Normalized
	}
	if err := opts.Set(spec.CanonicalKey, val); err != nil {
		// Preserve strict error reporting on options declared StrictInOpenSSHConfig,
		// while leniently skipping unsupported ~/.ssh/config values (e.g. ControlPath
		// tokens like %k or PubkeyAuthentication=unbound).
		if spec.StrictInOpenSSHConfig {
			hostLabel := passes[0]
			return fmt.Errorf("invalid %s %q for %q in ssh config: %w", spec.OpenSSHName, val, hostLabel, err)
		}
	}
	return nil
}

func sshConfigOptionValue(d *sshConfigDirective, spec ssh.OptionSpec) string {
	if d == nil {
		return ""
	}
	if spec.ConfigSyntax.PreservesRawValue() {
		return d.rawValue
	}
	return d.value
}

// allMatchingOpenSSHOptions resolves all entries for a multi-value option strictly
// top-to-bottom across matching ssh_config Host blocks (including Include files),
// matching OpenSSH readconf.c evaluation order for SendEnv, IdentityFile, SetEnv, etc.
func allMatchingOpenSSHOptionsPasses(doc *sshConfigDoc, passes []string, spec ssh.OptionSpec) []string {
	if doc == nil || len(passes) == 0 {
		return nil
	}
	keys := make([]string, 0, 1+len(spec.Aliases))
	keys = append(keys, spec.OpenSSHName)
	keys = append(keys, spec.Aliases...)

	multiPass := len(passes) > 1
	dedupAcrossPasses := multiPass && spec.MergeMode.IsNoneTerminated()
	var seen map[string]struct{}
	if dedupAcrossPasses {
		seen = make(map[string]struct{})
	}
	var seenDirectives map[*sshConfigDirective]struct{}
	if multiPass {
		seenDirectives = make(map[*sshConfigDirective]struct{})
	}
	var matches []string
	walkMatchingSSHConfigDirectivesPasses(doc, passes, func(passIndex int, _ string, d *sshConfigDirective) bool {
		if seenDirectives != nil && d != nil {
			if passIndex == 0 {
				seenDirectives[d] = struct{}{}
			} else if _, already := seenDirectives[d]; already {
				return true
			}
		}
		for _, candidate := range keys {
			if strings.EqualFold(d.key, candidate) {
				if v := sshConfigOptionValue(d, spec); v != "" {
					if dedupAcrossPasses {
						if _, ok := seen[v]; ok {
							break
						}
						seen[v] = struct{}{}
					}
					matches = append(matches, v)
				}
				break
			}
		}
		return true
	})
	return matches
}

func resolveOpenSSHSingleOptionPasses(doc *sshConfigDoc, passes []string, spec ssh.OptionSpec) (val string, skip bool, err error) {
	if spec.CanonicalKey == ssh.OptionProxyCommand {
		ps, pErr := resolveOpenSSHProxySettingPasses(doc, passes)
		if pErr != nil {
			return "", false, pErr
		}
		switch ps.Kind() {
		case ssh.ProxyJump:
			return "", true, nil
		case ssh.ProxyCommand:
			cmd, _ := ps.Command()
			return cmd, false, nil
		case ssh.ProxyDisabled:
			if !ps.IsJumpDisabledOnly() {
				return "none", false, nil
			}
			return "", false, nil
		default:
			return "", false, nil
		}
	}
	return firstMatchingOpenSSHOptionPasses(doc, passes, spec), false, nil
}

func firstMatchingOpenSSHOptionPasses(doc *sshConfigDoc, passes []string, spec ssh.OptionSpec) string {
	keys := make([]string, 0, 1+len(spec.Aliases))
	keys = append(keys, spec.OpenSSHName)
	keys = append(keys, spec.Aliases...)
	return firstSSHConfigKeyValueRawPasses(doc, passes, spec.ConfigSyntax.PreservesRawValue(), keys...)
}

func parseOpenSSHHostSpec(spec string) (host, userName string, port uint16, err error) {
	host, userName, port, _, err = parseTargetRefPlain(spec)
	return host, userName, port, err
}

// getVal 是封装获取的方法
func (p *OpenSSHParser) getVal(alias, key, defaultVal string) string {
	if p == nil || p.cfg == nil {
		return defaultVal
	}
	val := firstSSHConfigKeyValue(p.cfg, alias, key)
	if val == "" {
		return defaultVal
	}
	return val
}

var currentUserFn = func() (string, error) {
	currUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user failed: %w", err)
	}
	return currUser.Username, nil
}

// 辅助函数
func getCurrentUser() (string, error) {
	return currentUserFn()
}

func expandHomeDir(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	sep := strings.IndexAny(path[1:], `/\`)
	var userPart, rest string
	if sep < 0 {
		userPart = path[1:]
	} else {
		userPart = path[1 : 1+sep]
		rest = path[1+sep+1:]
	}
	var home string
	if userPart == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand home dir failed: %w", err)
		}
	} else {
		u, err := user.Lookup(userPart)
		if err != nil || u == nil || u.HomeDir == "" {
			return path, nil
		}
		home = u.HomeDir
	}
	if rest == "" {
		return home, nil
	}
	return filepath.Join(home, rest), nil
}

func normalizeConfigIdentityKeyPath(raw string) (string, error) {
	setting, err := ssh.ParseIdentityPathSetting(raw, true)
	if err != nil || !setting.Persistable() {
		return "", nil
	}
	expanded, err := expandHomeDir(setting.Raw)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(expanded, "~") {
		return "", nil
	}
	return expanded, nil
}

func parseOpenSSHProxyJump(raw string) string {
	if raw == "" || strings.EqualFold(strings.TrimSpace(raw), "none") {
		return ""
	}
	hops := strings.Split(raw, ",")
	var parsedHops []string
	for _, rawHop := range hops {
		hop := strings.TrimSpace(rawHop)
		if hop == "" || strings.EqualFold(hop, "none") {
			continue
		}
		parsedHops = append(parsedHops, OpenSSHNodePrefix+hop)
	}
	return strings.Join(parsedHops, ",")
}

// resolveOpenSSHProxySettingPasses folds all matching ProxyJump and ProxyCommand
// directives top-to-bottom into an associative typed ssh.ProxySetting, preserving
// any shadowed ProxyCommand fallback beneath a higher-priority ProxyJump.
// Malformed ProxyJump/ProxyCommand directives fail closed with an error.
func resolveOpenSSHProxySettingPasses(doc *sshConfigDoc, passes []string) (ssh.ProxySetting, error) {
	if doc == nil || len(passes) == 0 {
		return ssh.UnsetProxySetting(), nil
	}
	acc := ssh.UnsetProxySetting()
	var parseErr error
	walkMatchingSSHConfigDirectivesPasses(doc, passes, func(_ int, _ string, d *sshConfigDirective) bool {
		switch d.lowerKey {
		case "proxyjump":
			ps, err := ssh.ParseProxyJump(d.value)
			if err != nil {
				parseErr = fmt.Errorf("line %d: invalid ProxyJump %q for %q in ssh config: %w", d.line, d.value, passes[0], err)
				return false
			}
			acc = acc.Merge(ps)
		case "proxycommand":
			ps, err := ssh.ParseProxyCommand(d.rawValue)
			if err != nil {
				parseErr = fmt.Errorf("line %d: invalid ProxyCommand %q for %q in ssh config: %w", d.line, d.rawValue, passes[0], err)
				return false
			}
			acc = acc.Merge(ps)
		}
		return true
	})
	if parseErr != nil {
		return ssh.UnsetProxySetting(), parseErr
	}
	return acc, nil
}
