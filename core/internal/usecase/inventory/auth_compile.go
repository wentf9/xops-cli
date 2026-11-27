package inventory

import (
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/ports"
)

// compileHopAuth 依据已求解的 EffectivePolicy 编译单跳零明文封闭 inventory.AuthMethod：
//   - 若显式传入 explicit 认证方式，则直接使用；
//   - 严格遵守 IdentityFile=none（禁止回退默认 ~/.ssh/id_*，INV-D1）；
//   - 严格遵守 IdentitiesOnly=yes（禁用未限定 SSH Agent 枚举）；
//   - 严格遵守 BatchMode=yes（禁用交互式 Keyboard-Interactive 质询回退）；
//   - 自动展开 IdentityFile / CertificateFile 中的 OpenSSH % 占位符与 ${ENV} 引用。
func compileHopAuth(policy option.EffectivePolicy, user option.Username, env ports.EnvPort, explicit inventory.AuthMethod) (inventory.AuthMethod, error) {
	if explicit != nil {
		if !explicit.IsValid() {
			return nil, domi18n.WrapSentinel(ErrNoAuthMethod, domi18n.E(domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ExplicitAuth")))
		}
		return explicit, nil
	}
	tc := buildTokenContext(policy, user, env)
	certs, err := expandOptionPaths(policy.CertificateFiles(), "CertificateFile", tc, env, inventory.ParseCertPathSpec)
	var privKey, agentAuth, kiAuth inventory.AuthMethod
	if err == nil {
		privKey, err = compilePrivateKeyAuth(policy.IdentityFiles(), certs, tc, env)
	}
	if err == nil && !policy.IdentitiesOnly() {
		agentAuth, err = inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	}
	if err == nil && !policy.BatchMode() {
		kiAuth, err = buildInteractiveFallbackAuth()
	}
	if err != nil {
		return nil, err
	}
	return assembleOrderedAuth(policy.IdentityFiles().IsSet(), privKey, agentAuth, kiAuth)
}

func assembleOrderedAuth(explicitKeys bool, privKey, agentAuth, kiAuth inventory.AuthMethod) (inventory.AuthMethod, error) {
	// 显式指定 IdentityFile 时私钥优先，否则按 OpenSSH 默认顺序 Agent -> 私钥 -> 质询。
	raw := pickIf(explicitKeys, [3]inventory.AuthMethod{privKey, agentAuth, kiAuth}, [3]inventory.AuthMethod{agentAuth, privKey, kiAuth})
	methods := make([]inventory.AuthMethod, 0, 3)
	for _, m := range raw {
		if m != nil && m.IsValid() {
			methods = append(methods, m)
		}
	}
	switch len(methods) {
	case 0:
		return nil, domi18n.WrapSentinel(ErrNoAuthMethod, ports.ErrAuthFailed)
	case 1:
		return methods[0], nil
	default:
		ne, err := algebraic.NonEmptyFromSlice(methods)
		if err != nil {
			return nil, err
		}
		return inventory.NewAuthComposite(ne)
	}
}

func compilePrivateKeyAuth(idFiles option.PathList, certs []inventory.CertPathSpec, tc option.TokenContext, env ports.EnvPort) (inventory.AuthMethod, error) {
	if idFiles.IsDisabled() {
		return nil, nil
	}
	var specs []inventory.KeyPathSpec
	var err error
	if idFiles.IsSet() {
		specs, err = expandOptionPaths(idFiles, "IdentityFile", tc, env, inventory.ParseKeyPathSpec)
	} else if tc.HomeDir != "" {
		specs, err = defaultIdentityKeySpecs()
	}
	if err != nil || len(specs) == 0 {
		return nil, err
	}
	ne, err := algebraic.NonEmptyFromSlice(specs)
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthPrivateKey(ne, algebraic.None[inventory.KeyPassphraseBinding](), certs)
}

func expandOptionPaths[T any](list option.PathList, label string, tc option.TokenContext, env ports.EnvPort, parse func(string) (T, error)) ([]T, error) {
	if !list.IsSet() {
		return nil, nil
	}
	items := list.Items()
	out := make([]T, 0, len(items))
	for _, entry := range items {
		expanded, err := expandOptionPathEntry(entry, tc, env)
		if err != nil {
			return nil, err
		}
		v, err := parse(expanded)
		if err != nil {
			return nil, domi18n.WrapS(ErrInvalidTarget, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", label), domi18n.BoundStr("value", entry.String()))
		}
		out = append(out, v)
	}
	return out, nil
}

func defaultIdentityKeySpecs() ([]inventory.KeyPathSpec, error) {
	out := make([]inventory.KeyPathSpec, 0, 3)
	for _, raw := range [3]string{"~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_rsa"} {
		kp, err := inventory.ParseKeyPathSpec(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, kp)
	}
	return out, nil
}

// buildInteractiveFallbackAuth 构造永不静态命中的哨兵规则，使 sshnet/dial 遇到服务端质询时
// 统一落入 planInteractiveKIQuestion（自动遵守 BatchMode 与 InteractionPort.CanInteract 门控）。
func buildInteractiveFallbackAuth() (inventory.AuthMethod, error) {
	rule, err := inventory.NewRuleLoginPassword(inventory.ChallengeRuleMeta{Name: "interactive_fallback", PromptPattern: "a^"})
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthKeyboardInteractive(algebraic.NewNonEmpty[inventory.ChallengeRule](rule))
}

func buildTokenContext(policy option.EffectivePolicy, user option.Username, env ports.EnvPort) option.TokenContext {
	jumpHost := ""
	if hops := proxyJumpHopHosts(policy.Proxy()); len(hops) > 0 {
		jumpHost = hops[len(hops)-1]
	}
	tc := option.TokenContext{
		TargetHost: policy.Endpoint().Host().String(), Port: policy.Endpoint().Port(),
		RemoteUser: user.String(), OriginalHost: policy.OriginalHost().String(), JumpHost: jumpHost,
	}
	if env != nil {
		if id, err := env.LookupLocalIdentity(); err == nil {
			tc = id.ApplyToTokenContext(tc)
		}
	}
	return tc
}

// expandOptionPathEntry 是 KeyPathSpec/CertPathSpec 编译前的单一权威 % 与 ${VAR} 展开边界：
// 按单遍次序先展开 OpenSSH % 占位符再展开 ${ENV} 引用；由于 domain/inventory.KeyPathSpec 禁止含 '%'，
// 若展开结果仍残留字面 '%'（如 %% 或环境变量值中带 '%'）或未展开 "${"，立即失败关闭，
// 彻底杜绝任何 '%' 跨入下游 sshnet/dial 造成二次展开（如 %%h 被误展为主机名）。
func expandOptionPathEntry(entry option.PathEntry, tc option.TokenContext, env ports.EnvPort) (string, error) {
	raw := entry.String()
	if !entry.IsTemplate() {
		return raw, nil
	}
	expanded, err := raw, error(nil)
	if strings.ContainsRune(expanded, '%') {
		expanded, err = option.ExpandPathTokens(expanded, tc)
	}
	if err == nil && strings.Contains(expanded, "${") {
		expanded, err = expandEnvBraces(expanded, env)
	}
	if err != nil {
		return "", domi18n.WrapS(ErrInvalidTarget, err, domi18n.KeyCommonPathTemplateFailed, domi18n.BoundStr("target", raw))
	}
	if strings.ContainsRune(expanded, '%') || strings.Contains(expanded, "${") {
		return "", domi18n.EF(ErrInvalidTarget, domi18n.KeyUCInvTemplateToken, domi18n.BoundStr("template", raw))
	}
	return expanded, nil
}

func expandEnvBraces(raw string, env ports.EnvPort) (string, error) {
	if env == nil {
		return "", domi18n.E(domi18n.KeyCommonMissingDep, domi18n.Str("component", "EnvPort"))
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		idx := strings.Index(raw[i:], "${")
		if idx < 0 {
			b.WriteString(raw[i:])
			break
		}
		b.WriteString(raw[i : i+idx])
		end := strings.IndexByte(raw[i+idx+2:], '}')
		if end <= 0 {
			return "", domi18n.E(domi18n.KeyUCInvEnvVarPlaceholder)
		}
		name := raw[i+idx+2 : i+idx+2+end]
		val, ok := env.LookupEnv(name)
		if !ok || val == "" {
			return "", domi18n.E(domi18n.KeyUCInvEnvVarMissing, domi18n.BoundStr("name", name))
		}
		b.WriteString(val)
		i += idx + 2 + end + 1
	}
	return b.String(), nil
}
