package yamlcodec

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
)

// ProxyRouteDTO、ControlPolicyDTO、AlgoPolicyDTO、PathListDTO、KnownHostsListDTO、EnvFilterDTO 与 OptionLayerDTO
// 为 YAML vNext version: 2 持久化 OpenSSH 选项与代理路由的强判别式 DTO，严格零裸 time.Duration。
type (
	//xops:dto
	ProxyRouteDTO struct {
		Kind             string   `yaml:"kind"`
		Scope            string   `yaml:"scope,omitempty"`
		Hops             []string `yaml:"hops,omitempty"`
		Command          string   `yaml:"command,omitempty"`
		ShadowedCmd      string   `yaml:"shadowed_cmd,omitempty"`
		ShadowedDisabled bool     `yaml:"shadowed_disabled,omitempty"`
	}
	//xops:dto
	ControlPolicyDTO struct {
		Master      string `yaml:"master,omitempty"`
		Path        string `yaml:"path,omitempty"`
		LiteralPath bool   `yaml:"literal_path,omitempty"`
		Persist     string `yaml:"persist,omitempty"`
	}
	//xops:dto
	AlgoPolicyDTO struct {
		Op     string   `yaml:"op"`
		Tokens []string `yaml:"tokens,omitempty"`
	}
	//xops:dto
	PathListDTO struct {
		State      string   `yaml:"state"`
		Items      []string `yaml:"items,omitempty"`
		Terminated bool     `yaml:"terminated,omitempty"`
	}
	//xops:dto
	KnownHostsListDTO struct {
		State string   `yaml:"state"`
		Items []string `yaml:"items,omitempty"`
	}
	//xops:dto
	EnvFilterDTO struct {
		Clear []string `yaml:"clear,omitempty"`
		Added []string `yaml:"added,omitempty"`
	}
	//xops:dto
	OptionLayerDTO struct {
		HostName              string              `yaml:"hostname,omitempty"`
		Port                  *uint16             `yaml:"port,omitempty"`
		User                  string              `yaml:"user,omitempty"`
		Proxy                 *ProxyRouteDTO      `yaml:"proxy,omitempty"`
		Control               *ControlPolicyDTO   `yaml:"control,omitempty"`
		ConnectTimeout        *algebraic.Duration `yaml:"connect_timeout,omitempty"`
		ServerAliveInterval   *algebraic.Duration `yaml:"server_alive_interval,omitempty"`
		ServerAliveCountMax   *uint32             `yaml:"server_alive_count_max,omitempty"`
		Ciphers               *AlgoPolicyDTO      `yaml:"ciphers,omitempty"`
		MACs                  *AlgoPolicyDTO      `yaml:"macs,omitempty"`
		KexAlgorithms         *AlgoPolicyDTO      `yaml:"kex_algorithms,omitempty"`
		HostKeyAlgorithms     *AlgoPolicyDTO      `yaml:"host_key_algorithms,omitempty"`
		IdentityFiles         *PathListDTO        `yaml:"identity_files,omitempty"`
		CertificateFiles      *PathListDTO        `yaml:"certificate_files,omitempty"`
		IdentitiesOnly        *bool               `yaml:"identities_only,omitempty"`
		BatchMode             *bool               `yaml:"batch_mode,omitempty"`
		StrictHostKeyChecking string              `yaml:"strict_host_key_checking,omitempty"`
		UserKnownHostsFiles   *KnownHostsListDTO  `yaml:"user_known_hosts_files,omitempty"`
		ForwardAgent          *bool               `yaml:"forward_agent,omitempty"`
		SendEnv               *EnvFilterDTO       `yaml:"send_env,omitempty"`
		PermitLocalCommand    *bool               `yaml:"permit_local_command,omitempty"`
		LocalCommand          string              `yaml:"local_command,omitempty"`
	}
)

type proxyShadowJSON struct {
	ShadowedCmd string `json:"shadowed_cmd,omitzero"`
	ShadowedOff bool   `json:"shadowed_disabled,omitzero"`
}

func encodeProxyRouteDTO(route option.ProxyRoute) (*ProxyRouteDTO, error) {
	if route == nil {
		return nil, nil
	}
	switch v := route.(type) {
	case *option.ProxyUnset:
		return nil, nil
	case *option.ProxyDisabled:
		scope := "all"
		if v.IsJumpOnly() {
			scope = "jump_only"
		}
		return &ProxyRouteDTO{Kind: "disabled", Scope: scope}, nil
	case *option.ProxyJumpChain:
		return encodeProxyJumpChainDTO(v)
	case *option.ProxyCommandSpec:
		if !v.IsValid() {
			return nil, option.ErrInvalidProxyRoute
		}
		return &ProxyRouteDTO{Kind: "command", Command: v.Command().String()}, nil
	default:
		return nil, fmt.Errorf("%w: 未知 ProxyRoute 变体 %T", option.ErrInvalidProxyRoute, route)
	}
}

func encodeProxyJumpChainDTO(v *option.ProxyJumpChain) (*ProxyRouteDTO, error) {
	if !v.IsValid() {
		return nil, option.ErrInvalidProxyRoute
	}
	var buf bytes.Buffer
	if err := option.MarshalProxyRouteTo(jsontext.NewEncoder(&buf), v); err != nil {
		return nil, err
	}
	var shadow proxyShadowJSON
	if err := jsonv2.Unmarshal(buf.Bytes(), &shadow); err != nil {
		return nil, err
	}
	return &ProxyRouteDTO{
		Kind:             "jump",
		Hops:             toStrings(v.Hops().Slice()),
		ShadowedCmd:      shadow.ShadowedCmd,
		ShadowedDisabled: shadow.ShadowedOff,
	}, nil
}

func decodeProxyRouteDTO(dto *ProxyRouteDTO) (option.ProxyRoute, error) {
	if dto == nil {
		return option.NewProxyUnset(), nil
	}
	kind := strings.ToLower(strings.TrimSpace(dto.Kind))
	hasJump := len(dto.Hops) > 0 || dto.ShadowedCmd != "" || dto.ShadowedDisabled
	switch kind {
	case "unset":
		if hasJump || dto.Scope != "" || dto.Command != "" {
			return nil, fmt.Errorf("%w: unset 代理路由禁止携带多余字段", option.ErrInvalidProxyRoute)
		}
		return option.NewProxyUnset(), nil
	case "disabled":
		return decodeProxyDisabledDTO(dto, hasJump)
	case "jump":
		return decodeProxyJumpDTO(dto)
	case "command":
		if hasJump || dto.Scope != "" || strings.TrimSpace(dto.Command) == "" {
			return nil, fmt.Errorf("%w: command 代理路由字段组合非法", option.ErrInvalidProxyRoute)
		}
		cmd, err := option.NewProxySanitizedCmd(dto.Command)
		if err != nil {
			return nil, err
		}
		return option.NewProxyCommandSpec(cmd)
	default:
		return nil, fmt.Errorf("%w: 未知代理路由类别 %q", option.ErrInvalidProxyRoute, dto.Kind)
	}
}

func decodeProxyDisabledDTO(dto *ProxyRouteDTO, hasJump bool) (option.ProxyRoute, error) {
	if hasJump || dto.Command != "" {
		return nil, fmt.Errorf("%w: disabled 代理路由禁止携带跳板或命令", option.ErrInvalidProxyRoute)
	}
	switch strings.ToLower(strings.TrimSpace(dto.Scope)) {
	case "", "all":
		return option.NewProxyDisabled(), nil
	case "jump_only":
		return option.NewProxyJumpDisabled(), nil
	default:
		return nil, fmt.Errorf("%w: 无效代理禁用范围 %q", option.ErrInvalidProxyRoute, dto.Scope)
	}
}

func decodeProxyJumpDTO(dto *ProxyRouteDTO) (option.ProxyRoute, error) {
	if dto.Scope != "" || dto.Command != "" || len(dto.Hops) == 0 || (dto.ShadowedDisabled && dto.ShadowedCmd != "") {
		return nil, fmt.Errorf("%w: jump 代理路由字段组合非法", option.ErrInvalidProxyRoute)
	}
	hops, err := mapSliceErr(dto.Hops, option.ParseHopTarget)
	if err != nil {
		return nil, err
	}
	ne, err := algebraic.NonEmptyFromSlice(hops)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", option.ErrInvalidProxyRoute, err)
	}
	jc, err := option.NewProxyJumpChain(ne)
	if err != nil {
		return nil, err
	}
	if dto.ShadowedDisabled {
		return option.ComposeProxyRoute(jc, option.NewProxyDisabled()), nil
	}
	if dto.ShadowedCmd != "" {
		cmd, cErr := option.NewProxySanitizedCmd(dto.ShadowedCmd)
		if cErr != nil {
			return nil, cErr
		}
		cs, csErr := option.NewProxyCommandSpec(cmd)
		if csErr != nil {
			return nil, csErr
		}
		return option.ComposeProxyRoute(jc, cs), nil
	}
	return jc, nil
}

// EncodeOptionLayerDTO 将不可变 OpenSSH 选项层无损编码为 YAML vNext OptionLayerDTO（全未设置时返回 nil）。
func EncodeOptionLayerDTO(layer option.OptionLayer) (*OptionLayerDTO, error) {
	if err := layer.Validate(); err != nil {
		return nil, err
	}
	if layer.IsUnset() {
		return nil, nil
	}
	proxyDTO, err := encodeProxyRouteDTO(layer.Proxy())
	if err != nil {
		return nil, err
	}
	return &OptionLayerDTO{
		HostName:              optStr(layer.HostName()),
		Port:                  optPtr(layer.Port()),
		User:                  optStr(layer.User()),
		Proxy:                 proxyDTO,
		Control:               encodeControlPolicyDTO(layer.Control()),
		ConnectTimeout:        optPtr(layer.ConnectTimeout()),
		ServerAliveInterval:   optPtr(layer.ServerAliveInterval()),
		ServerAliveCountMax:   optPtr(layer.ServerAliveCountMax()),
		Ciphers:               encodeAlgoPolicyDTO(layer.Ciphers()),
		MACs:                  encodeAlgoPolicyDTO(layer.MACs()),
		KexAlgorithms:         encodeAlgoPolicyDTO(layer.KexAlgorithms()),
		HostKeyAlgorithms:     encodeAlgoPolicyDTO(layer.HostKeyAlgorithms()),
		IdentityFiles:         encodePathListDTO(layer.IdentityFiles()),
		CertificateFiles:      encodePathListDTO(layer.CertificateFiles()),
		IdentitiesOnly:        optPtr(layer.IdentitiesOnly()),
		BatchMode:             optPtr(layer.BatchMode()),
		StrictHostKeyChecking: optStr(layer.StrictHostKeyChecking()),
		UserKnownHostsFiles:   encodeKnownHostsListDTO(layer.UserKnownHostsFiles()),
		ForwardAgent:          optPtr(layer.ForwardAgent()),
		SendEnv:               encodeEnvFilterDTO(layer.SendEnv()),
		PermitLocalCommand:    optPtr(layer.PermitLocalCommand()),
		LocalCommand:          optStr(layer.LocalCommand()),
	}, nil
}

// DecodeOptionLayerDTO 严格校验并将 YAML vNext OptionLayerDTO 解码为不可变 option.OptionLayer。
func DecodeOptionLayerDTO(dto *OptionLayerDTO) (option.OptionLayer, error) {
	if dto == nil {
		return option.UnsetOptionLayer(), nil
	}
	l := option.UnsetOptionLayer()
	var err error
	if l, err = applyOptionScalars(l, dto); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyOptionCompositeFields(l, dto); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if err := l.Validate(); err != nil {
		return option.UnsetOptionLayer(), err
	}
	return l, nil
}

func applyOptionScalars(l option.OptionLayer, dto *OptionLayerDTO) (option.OptionLayer, error) {
	var err error
	if l, err = applyOptStr(l, dto.HostName, option.ParseHostNameSpec, option.OptionLayer.WithHostName); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if dto.Port != nil {
		if *dto.Port == 0 {
			return option.UnsetOptionLayer(), fmt.Errorf("%w: options.port 不能为 0", option.ErrInvalidOption)
		}
		l = l.WithPort(*dto.Port)
	}
	if l, err = applyOptStr(l, dto.User, option.ParseUsername, option.OptionLayer.WithUser); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyNonNegDuration(l, dto.ConnectTimeout, "connect_timeout", option.OptionLayer.WithConnectTimeout); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyNonNegDuration(l, dto.ServerAliveInterval, "server_alive_interval", option.OptionLayer.WithServerAliveInterval); err != nil {
		return option.UnsetOptionLayer(), err
	}
	l = applyOptVal(l, dto.ServerAliveCountMax, option.OptionLayer.WithServerAliveCountMax)
	l = applyOptVal(l, dto.IdentitiesOnly, option.OptionLayer.WithIdentitiesOnly)
	l = applyOptVal(l, dto.BatchMode, option.OptionLayer.WithBatchMode)
	l = applyOptVal(l, dto.ForwardAgent, option.OptionLayer.WithForwardAgent)
	l = applyOptVal(l, dto.PermitLocalCommand, option.OptionLayer.WithPermitLocalCommand)
	if l, err = applyOptStr(l, dto.StrictHostKeyChecking, option.ParseStrictHostKeyChecking, option.OptionLayer.WithStrictHostKeyChecking); err != nil {
		return option.UnsetOptionLayer(), err
	}
	return applyOptStr(l, dto.LocalCommand, option.NewLocalSanitizedCmd, option.OptionLayer.WithLocalCommand)
}

func applyOptionCompositeFields(l option.OptionLayer, dto *OptionLayerDTO) (option.OptionLayer, error) {
	var err error
	if l, err = applyOptDTO(l, dto.Proxy, decodeProxyRouteDTO, option.OptionLayer.WithProxyRoute); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyOptDTO(l, dto.Control, decodeControlPolicyDTO, option.OptionLayer.WithControlPolicy); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyOptDTO(l, dto.Ciphers, decodeAlgoPolicyDTO, option.OptionLayer.WithCiphers); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyOptDTO(l, dto.MACs, decodeAlgoPolicyDTO, option.OptionLayer.WithMACs); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyOptDTO(l, dto.KexAlgorithms, decodeAlgoPolicyDTO, option.OptionLayer.WithKexAlgorithms); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyOptDTO(l, dto.HostKeyAlgorithms, decodeAlgoPolicyDTO, option.OptionLayer.WithHostKeyAlgorithms); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyOptDTO(l, dto.IdentityFiles, decodePathListDTO, option.OptionLayer.WithIdentityFiles); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyOptDTO(l, dto.CertificateFiles, decodePathListDTO, option.OptionLayer.WithCertificateFiles); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if l, err = applyOptDTO(l, dto.UserKnownHostsFiles, decodeKnownHostsListDTO, option.OptionLayer.WithUserKnownHostsFiles); err != nil {
		return option.UnsetOptionLayer(), err
	}
	return applyOptDTO(l, dto.SendEnv, decodeEnvFilterDTO, option.OptionLayer.WithSendEnv)
}

func applyOptVal[T any](l option.OptionLayer, p *T, set func(option.OptionLayer, T) option.OptionLayer) option.OptionLayer {
	if p == nil {
		return l
	}
	return set(l, *p)
}

func applyNonNegDuration(l option.OptionLayer, d *algebraic.Duration, name string, set func(option.OptionLayer, algebraic.Duration) option.OptionLayer) (option.OptionLayer, error) {
	if d == nil {
		return l, nil
	}
	if d.IsNegative() {
		return option.UnsetOptionLayer(), fmt.Errorf("%w: %s 不能为负", option.ErrInvalidOption, name)
	}
	return set(l, *d), nil
}

func applyOptStr[V any](l option.OptionLayer, raw string, parse func(string) (V, error), set func(option.OptionLayer, V) option.OptionLayer) (option.OptionLayer, error) {
	if raw == "" {
		return l, nil
	}
	v, err := parse(raw)
	if err != nil {
		return option.UnsetOptionLayer(), err
	}
	return set(l, v), nil
}

func applyOptDTO[S, V any](l option.OptionLayer, p *S, dec func(*S) (V, error), set func(option.OptionLayer, V) option.OptionLayer) (option.OptionLayer, error) {
	if p == nil {
		return l, nil
	}
	v, err := dec(p)
	if err != nil {
		return option.UnsetOptionLayer(), err
	}
	return set(l, v), nil
}

func encodeControlPolicyDTO(c option.ControlPolicy) *ControlPolicyDTO {
	if c.IsUnset() {
		return nil
	}
	return &ControlPolicyDTO{
		Master:      c.Master().String(),
		Path:        c.Path().String(),
		LiteralPath: c.Path().IsLiteral(),
		Persist:     c.Persist().String(),
	}
}

func decodeControlPolicyDTO(dto *ControlPolicyDTO) (option.ControlPolicy, error) {
	if dto.LiteralPath && (strings.TrimSpace(dto.Path) == "" || strings.EqualFold(strings.TrimSpace(dto.Path), "none")) {
		return option.UnsetControlPolicy(), fmt.Errorf("%w: literal_path 要求有效字面路径", option.ErrInvalidControlPolicy)
	}
	cp := option.UnsetControlPolicy()
	if dto.Master != "" {
		m, err := option.ParseControlMasterMode(dto.Master)
		if err != nil {
			return option.UnsetControlPolicy(), err
		}
		cp = cp.WithMaster(m)
	}
	if dto.Path != "" {
		p, err := decodeControlPath(dto.Path, dto.LiteralPath)
		if err != nil {
			return option.UnsetControlPolicy(), err
		}
		cp = cp.WithPath(p)
	}
	if dto.Persist != "" {
		per, err := option.ParseControlPersist(dto.Persist)
		if err != nil {
			return option.UnsetControlPolicy(), err
		}
		cp = cp.WithPersist(per)
	}
	return cp, nil
}

func decodeControlPath(raw string, literal bool) (option.ControlPathSpec, error) {
	if literal {
		return option.NewLiteralControlPath(raw)
	}
	return option.ParseControlPath(raw)
}

func encodeAlgoPolicyDTO(p option.AlgoPolicy) *AlgoPolicyDTO {
	if p.IsUnset() {
		return nil
	}
	return &AlgoPolicyDTO{Op: p.Op().String(), Tokens: p.Tokens()}
}

// decodeAlgoPolicyDTO 严格校验算子判别式与逐项算法令牌，禁止在 exact 令牌中走私前导 +/-/^ 或内嵌逗号篡改策略语义。
func decodeAlgoPolicyDTO(dto *AlgoPolicyDTO) (option.AlgoPolicy, error) {
	op := strings.ToLower(strings.TrimSpace(dto.Op))
	if op == "unset" && len(dto.Tokens) == 0 {
		return option.UnsetAlgoPolicy(), nil
	}
	if len(dto.Tokens) == 0 {
		return option.UnsetAlgoPolicy(), fmt.Errorf("%w: 算法策略 %q 缺少 tokens", option.ErrInvalidAlgoPolicy, dto.Op)
	}
	spec, ok := map[string]struct {
		prefix string
		op     option.AlgoOp
	}{
		"exact":   {"", option.AlgoOpExact},
		"append":  {"+", option.AlgoOpAppend},
		"remove":  {"-", option.AlgoOpRemove},
		"prepend": {"^", option.AlgoOpPrepend},
	}[op]
	if !ok {
		return option.UnsetAlgoPolicy(), fmt.Errorf("%w: 未知算法算子 %q", option.ErrInvalidAlgoPolicy, dto.Op)
	}
	for _, tok := range dto.Tokens {
		if tok == "" || strings.TrimSpace(tok) != tok || strings.ContainsRune(tok, ',') ||
			tok[0] == '+' || tok[0] == '-' || tok[0] == '^' {
			return option.UnsetAlgoPolicy(), fmt.Errorf("%w: 算法令牌 %q 包含非法算子前缀、空白或逗号", option.ErrInvalidAlgoPolicy, tok)
		}
	}
	ap, err := option.ParseAlgoPolicy(spec.prefix + strings.Join(dto.Tokens, ","))
	if err != nil {
		return option.UnsetAlgoPolicy(), err
	}
	if ap.Op() != spec.op || len(ap.Tokens()) != len(dto.Tokens) {
		return option.UnsetAlgoPolicy(), fmt.Errorf("%w: 算法策略算子或令牌数与判别式 %q 不一致", option.ErrInvalidAlgoPolicy, dto.Op)
	}
	return ap, nil
}

func encodePathListDTO(p option.PathList) *PathListDTO {
	if p.IsUnset() {
		return nil
	}
	return &PathListDTO{State: p.State().String(), Items: p.RawItems(), Terminated: p.Terminated()}
}

// decodePathListDTO 严格校验 state 判别式，state=set 下逐项经 option.ParsePathEntry 构造强类型列表，阻断 "none" 伪装或首尾空白走私。
func decodePathListDTO(dto *PathListDTO) (option.PathList, error) {
	st := strings.ToLower(strings.TrimSpace(dto.State))
	switch {
	case st == "unset" && len(dto.Items) == 0 && !dto.Terminated:
		return option.UnsetPathList(), nil
	case st == "disabled" && len(dto.Items) == 0:
		return option.DisabledPathList(), nil
	case st == "set" && len(dto.Items) > 0:
		entries, err := parseStrictSetPathEntries(dto.Items)
		if err != nil {
			return option.UnsetPathList(), err
		}
		pl, err := option.NewPathList(entries...)
		if err != nil {
			return option.UnsetPathList(), err
		}
		if dto.Terminated {
			pl = pl.Compose(option.DisabledPathList())
		}
		return pl, nil
	default:
		return option.UnsetPathList(), fmt.Errorf("%w: 非法 PathList 状态 %q", option.ErrInvalidPathList, dto.State)
	}
}

func encodeKnownHostsListDTO(k option.KnownHostsList) *KnownHostsListDTO {
	if k.IsUnset() {
		return nil
	}
	return &KnownHostsListDTO{State: k.State().String(), Items: k.RawItems()}
}

// decodeKnownHostsListDTO 严格校验 state 判别式，state=set 下逐项经 option.ParsePathEntry 构造强类型列表，阻断 "none" 伪装或首尾空白走私。
func decodeKnownHostsListDTO(dto *KnownHostsListDTO) (option.KnownHostsList, error) {
	st := strings.ToLower(strings.TrimSpace(dto.State))
	switch {
	case st == "unset" && len(dto.Items) == 0:
		return option.UnsetKnownHostsList(), nil
	case st == "disabled" && len(dto.Items) == 0:
		return option.DisabledKnownHostsList(), nil
	case st == "set" && len(dto.Items) > 0:
		entries, err := parseStrictSetPathEntries(dto.Items)
		if err != nil {
			return option.UnsetKnownHostsList(), err
		}
		return option.NewKnownHostsList(entries...)
	default:
		return option.UnsetKnownHostsList(), fmt.Errorf("%w: 非法 KnownHostsList 状态 %q", option.ErrInvalidPathList, dto.State)
	}
}

func parseStrictSetPathEntries(items []string) ([]option.PathEntry, error) {
	entries := make([]option.PathEntry, 0, len(items))
	for _, raw := range items {
		if strings.TrimSpace(raw) != raw {
			return nil, fmt.Errorf("%w: state=set 路径项 %q 禁止包含首尾空白", option.ErrInvalidPathList, raw)
		}
		entry, err := option.ParsePathEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: state=set 路径项 %q 非法: %w", option.ErrInvalidPathList, raw, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func encodeEnvFilterDTO(f option.EnvFilter) *EnvFilterDTO {
	if f.IsUnset() {
		return nil
	}
	return &EnvFilterDTO{Clear: f.ClearPatterns(), Added: f.Patterns()}
}

func decodeEnvFilterDTO(dto *EnvFilterDTO) (option.EnvFilter, error) {
	if len(dto.Clear) == 0 && len(dto.Added) == 0 {
		return option.UnsetEnvFilter(), nil
	}
	tokens := make([]string, 0, len(dto.Clear)+len(dto.Added))
	for _, c := range dto.Clear {
		if strings.HasPrefix(c, "-") {
			return option.UnsetEnvFilter(), fmt.Errorf("%w: clear 模式 %q 不得重复携带 '-' 前缀", option.ErrInvalidEnvFilter, c)
		}
		tokens = append(tokens, "-"+c)
	}
	for _, a := range dto.Added {
		if strings.HasPrefix(a, "-") {
			return option.UnsetEnvFilter(), fmt.Errorf("%w: added 模式 %q 禁止以 '-' 开头", option.ErrInvalidEnvFilter, a)
		}
		tokens = append(tokens, a)
	}
	return option.ParseEnvFilterTokens(tokens)
}
