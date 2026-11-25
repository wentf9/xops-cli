package inventory

import (
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
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
func compileHopAuth(
	policy option.EffectivePolicy,
	user option.Username,
	env ports.EnvPort,
	explicit inventory.AuthMethod,
) (inventory.AuthMethod, error) {
	if explicit != nil {
		if !explicit.IsValid() {
			return nil, fmt.Errorf("%w: 显式 AuthMethod 无效", ErrNoAuthMethod)
		}
		return explicit, nil
	}
	tc := buildTokenContext(policy, user, env)
	certs, err := compileCertPaths(policy.CertificateFiles(), tc, env)
	if err != nil {
		return nil, err
	}
	privKey, err := compilePrivateKeyAuth(policy.IdentityFiles(), certs, tc, env)
	if err != nil {
		return nil, err
	}
	var agentAuth inventory.AuthMethod
	if !policy.IdentitiesOnly() {
		agentAuth, err = inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
		if err != nil {
			return nil, err
		}
	}
	var kiAuth inventory.AuthMethod
	if !policy.BatchMode() {
		kiAuth, err = buildInteractiveFallbackAuth()
		if err != nil {
			return nil, err
		}
	}
	return assembleOrderedAuth(policy.IdentityFiles().IsSet(), privKey, agentAuth, kiAuth)
}

func assembleOrderedAuth(explicitKeys bool, privKey, agentAuth, kiAuth inventory.AuthMethod) (inventory.AuthMethod, error) {
	var raw [3]inventory.AuthMethod
	if explicitKeys {
		// 显式指定 -i / IdentityFile 时优先尝试指定私钥，其次 SSH Agent（未启 IdentitiesOnly 时），最后质询。
		raw = [3]inventory.AuthMethod{privKey, agentAuth, kiAuth}
	} else {
		// 默认回退路径按 OpenSSH 顺序先尝试 SSH Agent，再尝试默认私钥，最后交互质询。
		raw = [3]inventory.AuthMethod{agentAuth, privKey, kiAuth}
	}
	methods := make([]inventory.AuthMethod, 0, 3)
	for _, m := range raw {
		if m != nil && m.IsValid() {
			methods = append(methods, m)
		}
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrNoAuthMethod, ports.ErrAuthFailed)
	}
	if len(methods) == 1 {
		return methods[0], nil
	}
	ne, err := algebraic.NonEmptyFromSlice(methods)
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthComposite(ne)
}

func compilePrivateKeyAuth(
	idFiles option.PathList,
	certs []inventory.CertPathSpec,
	tc option.TokenContext,
	env ports.EnvPort,
) (inventory.AuthMethod, error) {
	if idFiles.IsDisabled() {
		return nil, nil
	}
	var specs []inventory.KeyPathSpec
	if idFiles.IsSet() {
		items := idFiles.Items()
		specs = make([]inventory.KeyPathSpec, 0, len(items))
		for _, entry := range items {
			expanded, err := expandOptionPathEntry(entry, tc, env)
			if err != nil {
				return nil, err
			}
			kp, err := inventory.ParseKeyPathSpec(expanded)
			if err != nil {
				return nil, fmt.Errorf("%w: IdentityFile %q 无效: %w", ErrInvalidTarget, entry.String(), err)
			}
			specs = append(specs, kp)
		}
	} else if tc.HomeDir != "" {
		var err error
		specs, err = defaultIdentityKeySpecs()
		if err != nil {
			return nil, err
		}
	}
	if len(specs) == 0 {
		return nil, nil
	}
	ne, err := algebraic.NonEmptyFromSlice(specs)
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthPrivateKey(ne, algebraic.None[inventory.KeyPassphraseBinding](), certs)
}

func compileCertPaths(certFiles option.PathList, tc option.TokenContext, env ports.EnvPort) ([]inventory.CertPathSpec, error) {
	if !certFiles.IsSet() {
		return nil, nil
	}
	items := certFiles.Items()
	out := make([]inventory.CertPathSpec, 0, len(items))
	for _, entry := range items {
		expanded, err := expandOptionPathEntry(entry, tc, env)
		if err != nil {
			return nil, err
		}
		cp, err := inventory.ParseCertPathSpec(expanded)
		if err != nil {
			return nil, fmt.Errorf("%w: CertificateFile %q 无效: %w", ErrInvalidTarget, entry.String(), err)
		}
		out = append(out, cp)
	}
	return out, nil
}

func defaultIdentityKeySpecs() ([]inventory.KeyPathSpec, error) {
	defaults := [3]string{"~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_rsa"}
	out := make([]inventory.KeyPathSpec, 0, len(defaults))
	for _, raw := range defaults {
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
	rule, err := inventory.NewRuleLoginPassword(inventory.ChallengeRuleMeta{
		Name:          "interactive_fallback",
		PromptPattern: "a^",
	})
	if err != nil {
		return nil, err
	}
	ne, err := algebraic.NonEmptyFromSlice([]inventory.ChallengeRule{rule})
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthKeyboardInteractive(ne)
}

func buildTokenContext(policy option.EffectivePolicy, user option.Username, env ports.EnvPort) option.TokenContext {
	tc := option.TokenContext{
		TargetHost:   policy.Endpoint().Host().String(),
		Port:         policy.Endpoint().Port(),
		RemoteUser:   user.String(),
		OriginalHost: policy.OriginalHost().String(),
		JumpHost:     activeJumpHostName(policy.Proxy()),
	}
	if env != nil {
		if id, err := env.LookupLocalIdentity(); err == nil {
			tc = id.ApplyToTokenContext(tc)
		}
	}
	return tc
}

func activeJumpHostName(route option.ProxyRoute) string {
	switch v := route.(type) {
	case nil, *option.ProxyUnset, *option.ProxyDisabled, *option.ProxyCommandSpec:
		return ""
	case *option.ProxyJumpChain:
		if !v.IsValid() {
			return ""
		}
		hops := v.Hops().Slice()
		return hops[len(hops)-1].Host()
	default:
		return ""
	}
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
	expanded := raw
	if strings.ContainsRune(expanded, '%') {
		out, err := option.ExpandPathTokens(expanded, tc)
		if err != nil {
			return "", fmt.Errorf("%w: 展开路径模板 %q 失败: %w", ErrInvalidTarget, raw, err)
		}
		expanded = out
	}
	if strings.Contains(expanded, "${") {
		out, err := expandEnvBraces(expanded, env)
		if err != nil {
			return "", fmt.Errorf("%w: 展开环境变量模板 %q 失败: %w", ErrInvalidTarget, raw, err)
		}
		expanded = out
	}
	if strings.ContainsRune(expanded, '%') || strings.Contains(expanded, "${") {
		return "", fmt.Errorf("%w: 路径模板 %q 展开后包含受禁字符 '%%' 或 '${'（拒绝以防下游二次展开）", ErrInvalidTarget, raw)
	}
	return expanded, nil
}

func expandEnvBraces(raw string, env ports.EnvPort) (string, error) {
	if env == nil {
		return "", fmt.Errorf("未注入 EnvPort，无法展开环境变量引用")
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
			return "", fmt.Errorf("存在未闭合或空的环境变量占位符")
		}
		name := raw[i+idx+2 : i+idx+2+end]
		val, ok := env.LookupEnv(name)
		if !ok || val == "" {
			return "", fmt.Errorf("环境变量 %q 未设置或为空", name)
		}
		b.WriteString(val)
		i += idx + 2 + end + 1
	}
	return b.String(), nil
}
