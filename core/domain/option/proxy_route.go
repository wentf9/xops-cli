package option

import (
	"slices"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

const (
	allowedProxyCmdPercentTokens = "%hnpr"
	forbiddenHopShellChars       = ";|&$`\\<>(){}!'\"*?"
)

// HopTarget 表示经严格校验的单个 ProxyJump 跳板目标（[user@]host[:port] 或别名）；零值恒无效。
// IPv6 字面量必须使用方括号包裹，规范化输出保留方括号而 Host() 返回无方括号规范主机名供 %j 使用。
//
//xops:opaque
//xops:failclosed
type HopTarget struct {
	user, host, raw string
	port            uint16
	valid           bool
}

// ParseHopTarget 校验并规范化单个 ProxyJump 跳板目标，复用 ParseUsername 校验用户段并强制 IPv6 方括号语法。
func ParseHopTarget(raw string) (HopTarget, error) {
	t := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || t == "" || len(t) > maxTokenLen || hasAnySpaceOrControl(t) ||
		strings.ContainsRune(t, ',') || strings.ContainsAny(t, forbiddenHopShellChars) || isNoneKeyword(t) {
		return HopTarget{}, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "hop_target"), domi18n.BoundStr("value", raw))
	}
	user, hostPart, hasAt := strings.Cut(t, "@")
	if !hasAt {
		user, hostPart = "", t
	} else if hostPart == "" || strings.ContainsRune(hostPart, '@') {
		return HopTarget{}, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "hop_target"), domi18n.BoundStr("value", t))
	} else if _, err := ParseUsername(user); err != nil {
		return HopTarget{}, wrapProxyErr(err)
	}
	host, port, err := parseHopHostPort(hostPart, t)
	if err != nil {
		return HopTarget{}, err
	}
	return HopTarget{user, host, formatCanonicalHop(user, host, port), port, true}, nil
}

func parseHopHostPort(hostPart, full string) (string, uint16, error) {
	if hostPart[0] == '[' {
		return parseBracketedHop(hostPart, full)
	}
	if strings.ContainsAny(hostPart, "[]") || strings.Count(hostPart, ":") > 1 {
		return "", 0, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "hop_target"), domi18n.BoundStr("value", full))
	}
	h, pStr, hasPort := strings.Cut(hostPart, ":")
	host, err := parseHopPlainHost(h, full)
	if err != nil || !hasPort {
		return host, 0, err
	}
	p, err := parseStrictPortNumber(pStr)
	return host, p, wrapProxyErr(err)
}

func wrapProxyErr(err error) error {
	if err == nil {
		return nil
	}
	return domi18n.WrapSentinel(ErrInvalidProxyRoute, err)
}

func parseHopPlainHost(h, full string) (string, error) {
	return parsePlainHostOrAlias(h, full, ErrInvalidProxyRoute)
}

// parsePlainHostOrAlias 校验非方括号主机或 OpenSSH/NodeID 别名：
// 合法 IP 字面量经 netaddr.ParseCanonicalHost 规范化；严格拦截畸形数值/八进制/十六进制 inet_aton SSRF 形态、
// 前导 '-'、首尾 '.'、".."、保留字 "none" 与非法元字符，同时放行合法非 IP 别名（如 bastion.01、gw.1、Prod_Bastion、UTF-8）。
func parsePlainHostOrAlias(h, full string, baseErr error) (string, error) {
	if h == "" || len(h) > maxTokenLen || hasAnySpaceOrControl(h) || h[0] == '-' ||
		h[0] == '.' || h[len(h)-1] == '.' || strings.Contains(h, "..") || isNoneKeyword(h) ||
		strings.ContainsAny(h, "@:/\\,[]"+forbiddenHopShellChars) {
		return "", domi18n.EF(baseErr, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "host"), domi18n.BoundStr("value", full))
	}
	if ch, err := netaddr.ParseCanonicalHost(h); err == nil && ch.IsIP() {
		return ch.String(), nil
	}
	if isNumericIPLike(h) {
		return "", domi18n.EF(baseErr, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "host"), domi18n.BoundStr("value", full))
	}
	return h, nil
}
func isNumericIPLike(h string) bool {
	for seg := range strings.SplitSeq(h, ".") {
		if !isNumericOrHexSeg(seg) {
			return false
		}
	}
	return true
}
func isNumericOrHexSeg(seg string) bool {
	if seg == "" {
		return false
	}
	if len(seg) > 2 && seg[0] == '0' && (seg[1] == 'x' || seg[1] == 'X') {
		return strings.IndexFunc(seg[2:], func(r rune) bool {
			return (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F')
		}) < 0
	}
	return isAllASCIIDigits(seg)
}

func parseBracketedHop(hostPart, full string) (string, uint16, error) {
	closeIdx := strings.IndexByte(hostPart, ']')
	if closeIdx < 2 {
		return "", 0, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "hop_target"), domi18n.BoundStr("value", full))
	}
	ch, err := netaddr.ParseCanonicalHost(hostPart[:closeIdx+1])
	if err != nil || !ch.IsIPv6() {
		return "", 0, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "hop_target"), domi18n.BoundStr("value", full))
	}
	rest := hostPart[closeIdx+1:]
	if rest == "" {
		return ch.String(), 0, nil
	}
	if rest[0] != ':' {
		return "", 0, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "hop_target"), domi18n.BoundStr("value", full))
	}
	p, err := parseStrictPortNumber(rest[1:])
	return ch.String(), p, wrapProxyErr(err)
}

func formatCanonicalHop(user, host string, port uint16) string {
	if strings.ContainsRune(host, ':') {
		host = "[" + host + "]"
	}
	if user != "" {
		host = user + "@" + host
	}
	if port != 0 {
		host += ":" + strconv.FormatUint(uint64(port), 10)
	}
	return host
}

// HopTarget 只读访问器与文本编解码方法。
func (h HopTarget) IsValid() bool          { return h.valid }
func (h HopTarget) IsZero() bool           { return !h.valid }
func (h HopTarget) User() string           { return h.user }
func (h HopTarget) Host() string           { return h.host }
func (h HopTarget) String() string         { return h.raw }
func (h HopTarget) Port() (uint16, bool)   { return h.port, h.valid && h.port != 0 }
func (h HopTarget) Equal(o HopTarget) bool { return h.valid && o.valid && h.raw == o.raw }
func (h HopTarget) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, h.raw, h.valid, ErrInvalidProxyRoute)
}
func (h HopTarget) MarshalText() ([]byte, error) { return h.AppendText(nil) }
func (h *HopTarget) UnmarshalText(text []byte) error {
	return unmarshalTextVia(h, text, ParseHopTarget)
}

// SanitizedCmd 表示经单行与安全字符校验的命令模板（ProxyCommand / LocalCommand）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type SanitizedCmd struct{ textToken }

// NewSanitizedCmd、NewProxySanitizedCmd 与 NewLocalSanitizedCmd 构造并校验单行命令模板。
// NewSanitizedCmd 默认强制 INV-D4 占位符白名单（%%/%C/%d/%h/%i/%j/%L/%l/%n/%p/%r/%u）；
// NewProxySanitizedCmd 进一步收紧为 ssh_config(5) ProxyCommand 占位符（%%/%h/%n/%p/%r）。
func NewSanitizedCmd(raw string) (SanitizedCmd, error) {
	t := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || t == "" || len(t) > maxCmdLen || isNoneKeyword(t) {
		return SanitizedCmd{}, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "command"))
	}
	if err := validateTemplateTokens(t, allowedPathPercentTokens, false); err != nil {
		return SanitizedCmd{}, domi18n.WrapSentinel(ErrInvalidProxyRoute, err)
	}
	return SanitizedCmd{textToken{t, true}}, nil
}
func NewProxySanitizedCmd(raw string) (SanitizedCmd, error) {
	cmd, err := NewSanitizedCmd(raw)
	if err == nil && !cmd.isValidProxyCmd() {
		return SanitizedCmd{}, domi18n.WrapSentinel(ErrInvalidProxyRoute, ErrInvalidPercentInput)
	}
	return cmd, err
}
func NewLocalSanitizedCmd(raw string) (SanitizedCmd, error) {
	cmd, err := NewSanitizedCmd(raw)
	if err != nil {
		err = domi18n.WrapSentinel(ErrInvalidOption, err)
	}
	return cmd, err
}
func (c SanitizedCmd) isValidProxyCmd() bool {
	return c.valid && hasValidTemplateTokens(c.raw, allowedProxyCmdPercentTokens, false)
}
func (c SanitizedCmd) Equal(o SanitizedCmd) bool { return c.valid && o.valid && c.raw == o.raw }
func (c SanitizedCmd) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, c.raw, c.valid, ErrInvalidProxyRoute)
}
func (c SanitizedCmd) MarshalText() ([]byte, error) { return c.AppendText(nil) }
func (c *SanitizedCmd) UnmarshalText(text []byte) error {
	return unmarshalTextVia(c, text, NewSanitizedCmd)
}

// ProxyRoute 表示 OpenSSH ProxyJump / ProxyCommand 路由配置的封闭和类型（Sealed Sum Type）。
// 四变体：*ProxyUnset、*ProxyDisabled（全禁用或仅禁跳板）、*ProxyJumpChain（含遮蔽命令槽）、*ProxyCommandSpec。
//
//xops:failclosed
type ProxyRoute interface{ sealedProxyRoute() }

type (
	proxyDisableScope uint8
	proxyCmdSlot      uint8
	proxyJumpSlotKind uint8
)

const (
	proxyDisableAll      proxyDisableScope = iota // 零值最严：ProxyCommand=none 全禁用
	proxyDisableJumpOnly                          // ProxyJump=none 仅取消低层 ProxyJump
)
const (
	proxyCmdSlotUnset proxyCmdSlot = iota
	proxyCmdSlotDisabled
	proxyCmdSlotActive
)
const (
	proxyJumpSlotUnset proxyJumpSlotKind = iota
	proxyJumpSlotBlocked
	proxyJumpSlotActive
)

// ProxyUnset、ProxyDisabled、ProxyJumpChain 与 ProxyCommandSpec 为 ProxyRoute 全部封闭变体。
//
//xops:opaque
//xops:failclosed
type ProxyUnset struct{}

//xops:opaque
//xops:failclosed
type ProxyDisabled struct{ scope proxyDisableScope }

//xops:opaque
//xops:failclosed
type ProxyJumpChain struct {
	hops     algebraic.NonEmpty[HopTarget]
	cmdSlot  proxyCmdSlot
	cmdValue SanitizedCmd
}

//xops:opaque
//xops:failclosed
type ProxyCommandSpec struct{ cmd SanitizedCmd }

func (*ProxyUnset) sealedProxyRoute()        {}
func (*ProxyDisabled) sealedProxyRoute()     {}
func (*ProxyJumpChain) sealedProxyRoute()    {}
func (*ProxyCommandSpec) sealedProxyRoute()  {}
func NewProxyUnset() *ProxyUnset             { return &ProxyUnset{} }
func NewProxyDisabled() *ProxyDisabled       { return &ProxyDisabled{proxyDisableAll} }
func NewProxyJumpDisabled() *ProxyDisabled   { return &ProxyDisabled{proxyDisableJumpOnly} }
func (d *ProxyDisabled) IsFullDisable() bool { return d == nil || d.scope == proxyDisableAll }
func (d *ProxyDisabled) IsJumpOnly() bool    { return d != nil && d.scope == proxyDisableJumpOnly }
func (j *ProxyJumpChain) IsValid() bool      { return j != nil && j.hops.IsValid() }
func (c *ProxyCommandSpec) IsValid() bool    { return c != nil && c.cmd.isValidProxyCmd() }
func (j *ProxyJumpChain) Hops() algebraic.NonEmpty[HopTarget] {
	if j != nil {
		return j.hops
	}
	var zero algebraic.NonEmpty[HopTarget]
	return zero
}
func (c *ProxyCommandSpec) Command() SanitizedCmd {
	if c != nil {
		return c.cmd
	}
	return SanitizedCmd{}
}
func NewProxyJumpChain(hops algebraic.NonEmpty[HopTarget]) (*ProxyJumpChain, error) {
	if !hops.IsValid() || slices.ContainsFunc(hops.Slice(), func(h HopTarget) bool { return !h.IsValid() }) {
		return nil, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "proxy_jump"))
	}
	return &ProxyJumpChain{hops: hops}, nil
}
func NewProxyCommandSpec(cmd SanitizedCmd) (*ProxyCommandSpec, error) {
	if !cmd.isValidProxyCmd() {
		return nil, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "proxy_command"))
	}
	return &ProxyCommandSpec{cmd}, nil
}

// ParseProxyJump 与 ParseProxyCommand 解析 OpenSSH 代理路由指令。
func ParseProxyJump(raw string) (ProxyRoute, error) {
	t, isNone, err := trimProxyDirective(raw, "ProxyJump")
	if err != nil {
		return nil, err
	}
	if isNone {
		return NewProxyJumpDisabled(), nil
	}
	var hops []HopTarget
	for part := range strings.SplitSeq(t, ",") {
		h, err := ParseHopTarget(part)
		if err != nil {
			return nil, err
		}
		hops = append(hops, h)
	}
	ne, err := algebraic.NonEmptyFromSlice(hops)
	if err != nil {
		return nil, wrapProxyErr(err)
	}
	return &ProxyJumpChain{hops: ne}, nil
}
func ParseProxyCommand(raw string) (ProxyRoute, error) {
	t, isNone, err := trimProxyDirective(raw, "ProxyCommand")
	if err != nil {
		return nil, err
	}
	if isNone {
		return NewProxyDisabled(), nil
	}
	cmd, err := NewProxySanitizedCmd(t)
	if err != nil {
		return nil, err
	}
	return &ProxyCommandSpec{cmd}, nil
}
func trimProxyDirective(raw, name string) (string, bool, error) {
	t := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || t == "" {
		return "", false, domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", name), domi18n.BoundStr("value", raw))
	}
	return t, isNoneKeyword(t), nil
}

// proxyPair 将 ProxyRoute 忠实嵌入直积幺半群 FirstWins[JumpSlot] × FirstWins[CmdSlot]，严格保证结合律。
type proxyPair struct {
	jumpKind proxyJumpSlotKind
	hops     algebraic.NonEmpty[HopTarget]
	cmdSlot  proxyCmdSlot
	cmdVal   SanitizedCmd
}

func toProxyPair(route ProxyRoute) (proxyPair, bool) {
	failClosed := proxyPair{jumpKind: proxyJumpSlotBlocked, cmdSlot: proxyCmdSlotDisabled}
	switch v := route.(type) {
	case nil, *ProxyUnset:
		return proxyPair{}, true
	case *ProxyDisabled:
		if v == nil || (v.scope != proxyDisableAll && v.scope != proxyDisableJumpOnly) {
			return failClosed, false
		}
		if v.scope == proxyDisableJumpOnly {
			return proxyPair{jumpKind: proxyJumpSlotBlocked}, true
		}
		return failClosed, true
	case *ProxyJumpChain:
		if !v.IsValid() || (v.cmdSlot == proxyCmdSlotActive && !v.cmdValue.isValidProxyCmd()) {
			return failClosed, false
		}
		return proxyPair{proxyJumpSlotActive, v.hops, v.cmdSlot, v.cmdValue}, true
	case *ProxyCommandSpec:
		if !v.IsValid() {
			return failClosed, false
		}
		return proxyPair{jumpKind: proxyJumpSlotBlocked, cmdSlot: proxyCmdSlotActive, cmdVal: v.cmd}, true
	default:
		return failClosed, false
	}
}
func fromProxyPair(p proxyPair) ProxyRoute {
	switch {
	case p.jumpKind == proxyJumpSlotUnset:
		return NewProxyUnset()
	case p.jumpKind == proxyJumpSlotActive:
		return &ProxyJumpChain{p.hops, p.cmdSlot, p.cmdVal}
	case p.cmdSlot == proxyCmdSlotActive:
		return &ProxyCommandSpec{p.cmdVal}
	case p.cmdSlot == proxyCmdSlotDisabled:
		return NewProxyDisabled()
	default:
		return NewProxyJumpDisabled()
	}
}

// ValidateProxyRoute、ComposeProxyRoute、FoldProxyRoutes 与 EqualProxyRoute 提供 ProxyRoute 校验、双槽复合、折叠与等价判定。
func ValidateProxyRoute(route ProxyRoute) error {
	if _, ok := toProxyPair(route); !ok {
		return domi18n.EF(ErrInvalidProxyRoute, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "proxy_route"))
	}
	return nil
}
func ComposeProxyRoute(higher, lower ProxyRoute) ProxyRoute {
	a, _ := toProxyPair(higher)
	b, _ := toProxyPair(lower)
	if a.jumpKind == proxyJumpSlotUnset {
		a.jumpKind, a.hops = b.jumpKind, b.hops
	}
	if a.cmdSlot == proxyCmdSlotUnset {
		a.cmdSlot, a.cmdVal = b.cmdSlot, b.cmdVal
	}
	return fromProxyPair(a)
}
func FoldProxyRoutes(layers ...ProxyRoute) ProxyRoute {
	return foldMonoid[ProxyRoute](NewProxyUnset(), ComposeProxyRoute, layers)
}
func EqualProxyRoute(a, b ProxyRoute) bool {
	pa, okA := toProxyPair(a)
	pb, okB := toProxyPair(b)
	return okA && okB && pa.jumpKind == pb.jumpKind && pa.cmdSlot == pb.cmdSlot &&
		(pa.jumpKind != proxyJumpSlotActive || slices.Equal(pa.hops.Slice(), pb.hops.Slice())) &&
		(pa.cmdSlot != proxyCmdSlotActive || pa.cmdVal.Equal(pb.cmdVal))
}
