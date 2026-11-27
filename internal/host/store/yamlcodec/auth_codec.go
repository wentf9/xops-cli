package yamlcodec

import (
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// IdentityDTO、AuthMethodDTO 与 ChallengeRuleDTO 为 YAML vNext version: 2 认证身份的强判别式 DTO，
// 强制私钥口令引用与公钥指纹成对出现（INV-F1），所有超时统一使用 algebraic.Duration（零裸 time.Duration）。
type (
	//xops:dto
	IdentityDTO struct {
		User        string        `yaml:"user"`
		Auth        AuthMethodDTO `yaml:"auth"`
		Description string        `yaml:"description,omitempty"`
		Tags        []string      `yaml:"tags,omitempty"`
	}
	//xops:dto
	AuthMethodDTO struct {
		Kind           string             `yaml:"kind"`
		PasswordRef    *SecretRefDTO      `yaml:"password_ref,omitempty"`
		KeyPaths       []string           `yaml:"key_paths,omitempty"`
		PassphraseRef  *SecretRefDTO      `yaml:"passphrase_ref,omitempty"`
		KeyFingerprint string             `yaml:"key_fingerprint,omitempty"`
		CertPaths      []string           `yaml:"cert_paths,omitempty"`
		AgentSpec      string             `yaml:"agent_spec,omitempty"`
		Rules          []ChallengeRuleDTO `yaml:"rules,omitempty"`
		Methods        []AuthMethodDTO    `yaml:"methods,omitempty"`
	}
	//xops:dto
	ChallengeRuleDTO struct {
		Kind               string              `yaml:"kind"`
		Name               string              `yaml:"name,omitempty"`
		PromptPattern      string              `yaml:"prompt_pattern"`
		InstructionPattern string              `yaml:"instruction_pattern,omitempty"`
		TOTPSecretRef      *SecretRefDTO       `yaml:"totp_secret_ref,omitempty"`
		SecretRef          *SecretRefDTO       `yaml:"secret_ref,omitempty"`
		Command            string              `yaml:"command,omitempty"`
		Args               []string            `yaml:"args,omitempty"`
		Timeout            *algebraic.Duration `yaml:"timeout,omitempty"`
	}
)

func encodeIdentityDTO(id inventory.Identity) (IdentityDTO, error) {
	authDTO, err := encodeAuthMethodDTO(id.Auth())
	if err != nil {
		return IdentityDTO{}, err
	}
	return IdentityDTO{User: id.User().String(), Auth: authDTO, Description: id.Description(), Tags: toStrings(id.Tags())}, nil
}

func decodeIdentityDTO(rawID string, dto IdentityDTO) (z inventory.Identity, err error) {
	iid, err := inventory.ParseIdentityID(rawID)
	if err != nil {
		return z, err
	}
	user, err := option.ParseUsername(dto.User)
	if err != nil {
		return z, err
	}
	auth, err := decodeAuthMethodDTO(dto.Auth)
	if err != nil {
		return z, err
	}
	tags, err := mapSliceErr(dto.Tags, inventory.ParseTag)
	if err != nil {
		return z, err
	}
	return inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: user, Auth: auth, Description: dto.Description, Tags: tags})
}

func encodeAuthMethodDTO(auth inventory.AuthMethod) (AuthMethodDTO, error) {
	if auth == nil || !auth.IsValid() {
		return AuthMethodDTO{}, inventory.ErrInvalidAuthMethod
	}
	switch v := auth.(type) {
	case *inventory.AuthPassword:
		return AuthMethodDTO{Kind: v.Kind().String(), PasswordRef: encodeSecretRefDTO(v.PasswordRef())}, nil
	case *inventory.AuthPrivateKey:
		dto := AuthMethodDTO{Kind: v.Kind().String(), KeyPaths: toStrings(v.KeyPaths().Slice()), CertPaths: toStrings(v.CertPaths())}
		if pb, ok := v.Passphrase().Get(); ok {
			dto.PassphraseRef, dto.KeyFingerprint = encodeSecretRefDTO(pb.PassphraseRef()), pb.KeyFingerprint().String()
		}
		return dto, nil
	case *inventory.AuthAgent:
		dto := AuthMethodDTO{Kind: v.Kind().String()}
		if sp, ok := v.Spec().Get(); ok {
			dto.AgentSpec = sp.String()
		}
		return dto, nil
	case *inventory.AuthKeyboardInteractive:
		rules, err := mapSliceErr(v.Rules(), encodeChallengeRuleDTO)
		return AuthMethodDTO{Kind: v.Kind().String(), Rules: rules}, err
	case *inventory.AuthComposite:
		methods, err := mapSliceErr(v.Methods(), encodeAuthMethodDTO)
		return AuthMethodDTO{Kind: v.Kind().String(), Methods: methods}, err
	default:
		return AuthMethodDTO{}, inventory.ErrInvalidAuthMethod
	}
}

func decodeAuthMethodDTO(dto AuthMethodDTO) (inventory.AuthMethod, error) {
	kind, err := inventory.ParseAuthMethodKind(dto.Kind)
	if err != nil {
		return nil, err
	}
	mask := fieldMask(
		dto.PasswordRef != nil,
		len(dto.KeyPaths) > 0 || dto.PassphraseRef != nil || dto.KeyFingerprint != "" || len(dto.CertPaths) > 0,
		dto.AgentSpec != "",
		len(dto.Rules) > 0,
		len(dto.Methods) > 0,
	)
	switch kind {
	case inventory.AuthMethodKindPassword:
		return decodeAuthPasswordDTO(dto, mask)
	case inventory.AuthMethodKindPrivateKey:
		return decodeAuthPrivateKeyDTO(dto, mask)
	case inventory.AuthMethodKindAgent:
		return decodeAuthAgentDTO(dto, mask)
	case inventory.AuthMethodKindKeyboardInteractive:
		return decodeAuthListDTO(mask == 8 && len(dto.Rules) > 0, dto.Rules, decodeChallengeRuleDTO, inventory.NewAuthKeyboardInteractive)
	case inventory.AuthMethodKindComposite:
		return decodeAuthListDTO(mask == 16 && len(dto.Methods) > 0, dto.Methods, decodeAuthMethodDTO, inventory.NewAuthComposite)
	default:
		return nil, inventory.ErrInvalidAuthMethod
	}
}

func decodeAuthPasswordDTO(dto AuthMethodDTO, mask uint8) (inventory.AuthMethod, error) {
	if mask != 1 || dto.PasswordRef == nil {
		return nil, i18n.EF(inventory.ErrInvalidAuthMethod, i18n.KeyHostYAMLInvalidFieldCombo, i18n.Str("kind", "password"))
	}
	ref, err := decodeSecretRefDTO(dto.PasswordRef)
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthPassword(ref)
}

func decodeAuthPrivateKeyDTO(dto AuthMethodDTO, mask uint8) (inventory.AuthMethod, error) {
	if mask != 2 || len(dto.KeyPaths) == 0 {
		return nil, i18n.EF(inventory.ErrInvalidAuthMethod, i18n.KeyHostYAMLInvalidFieldCombo, i18n.Str("kind", "private_key"))
	}
	kps, err := mapSliceErr(dto.KeyPaths, inventory.ParseKeyPathSpec)
	if err != nil {
		return nil, err
	}
	ne, err := algebraic.NonEmptyFromSlice(kps)
	if err != nil {
		return nil, err
	}
	pbOpt, err := decodePassphraseBindingDTO(dto.PassphraseRef, dto.KeyFingerprint)
	if err != nil {
		return nil, err
	}
	certs, err := mapSliceErr(dto.CertPaths, inventory.ParseCertPathSpec)
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthPrivateKey(ne, pbOpt, certs)
}

func decodePassphraseBindingDTO(refDTO *SecretRefDTO, rawFP string) (algebraic.Option[inventory.KeyPassphraseBinding], error) {
	if refDTO == nil && rawFP == "" {
		return algebraic.None[inventory.KeyPassphraseBinding](), nil
	}
	if refDTO == nil || rawFP == "" {
		return algebraic.None[inventory.KeyPassphraseBinding](), i18n.EF(inventory.ErrInvalidKeySpec, i18n.KeyHostYAMLPassphraseBindingPair)
	}
	ref, err := decodeSecretRefDTO(refDTO)
	if err != nil {
		return algebraic.None[inventory.KeyPassphraseBinding](), err
	}
	fp, err := inventory.ParseKeyFingerprint(rawFP)
	if err != nil {
		return algebraic.None[inventory.KeyPassphraseBinding](), err
	}
	pb, err := inventory.NewKeyPassphraseBinding(ref, fp)
	if err != nil {
		return algebraic.None[inventory.KeyPassphraseBinding](), err
	}
	return algebraic.Some(pb), nil
}

func decodeAuthAgentDTO(dto AuthMethodDTO, mask uint8) (inventory.AuthMethod, error) {
	if mask&^4 != 0 {
		return nil, i18n.EF(inventory.ErrInvalidAuthMethod, i18n.KeyHostYAMLInvalidFieldCombo, i18n.Str("kind", "agent"))
	}
	spOpt, err := parseOptional(dto.AgentSpec, inventory.ParseAgentSpec)
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthAgent(spOpt)
}

func decodeAuthListDTO[W, T any, R inventory.AuthMethod](ok bool, raw []W, decFn func(W) (T, error), build func(algebraic.NonEmpty[T]) (R, error)) (inventory.AuthMethod, error) {
	if !ok {
		return nil, i18n.EF(inventory.ErrInvalidAuthMethod, i18n.KeyHostYAMLInvalidFieldCombo, i18n.Str("kind", "auth_list"))
	}
	items, err := mapSliceErr(raw, decFn)
	if err != nil {
		return nil, err
	}
	ne, err := algebraic.NonEmptyFromSlice(items)
	if err != nil {
		return nil, err
	}
	return build(ne)
}

func encodeChallengeRuleDTO(r inventory.ChallengeRule) (ChallengeRuleDTO, error) {
	if r == nil || !r.IsValid() {
		return ChallengeRuleDTO{}, inventory.ErrInvalidChallengeRule
	}
	dto := ChallengeRuleDTO{
		Kind: r.Kind().String(), Name: r.Name(), PromptPattern: r.PromptPattern(), InstructionPattern: r.InstructionPattern(),
	}
	switch v := r.(type) {
	case *inventory.RuleTOTP:
		dto.TOTPSecretRef = encodeSecretRefDTO(v.TOTPSecretRef())
	case *inventory.RuleSecretRef:
		dto.SecretRef = encodeSecretRefDTO(v.SecretRef())
	case *inventory.RuleCommand:
		dto.Command, dto.Args = v.Command(), v.Args()
		if d, ok := v.Timeout().Get(); ok {
			dto.Timeout = ptrOf(d)
		}
	case *inventory.RuleLoginPassword:
	default:
		return ChallengeRuleDTO{}, inventory.ErrInvalidChallengeRule
	}
	return dto, nil
}

func decodeChallengeRuleDTO(dto ChallengeRuleDTO) (inventory.ChallengeRule, error) {
	kind, err := inventory.ParseChallengeRuleKind(dto.Kind)
	if err != nil {
		return nil, err
	}
	meta := inventory.ChallengeRuleMeta{Name: dto.Name, PromptPattern: dto.PromptPattern, InstructionPattern: dto.InstructionPattern}
	mask := fieldMask(dto.TOTPSecretRef != nil, dto.SecretRef != nil, dto.Command != "" || len(dto.Args) > 0 || dto.Timeout != nil)
	switch kind {
	case inventory.ChallengeRuleKindTOTP:
		return decodeChallengeSecretRule(mask == 1, dto.TOTPSecretRef, meta, inventory.NewRuleTOTP)
	case inventory.ChallengeRuleKindSecretRef:
		return decodeChallengeSecretRule(mask == 2, dto.SecretRef, meta, inventory.NewRuleSecretRef)
	case inventory.ChallengeRuleKindCommand:
		if mask == 4 && dto.Command != "" {
			return inventory.NewRuleCommand(meta, dto.Command, dto.Args, algebraic.OptionFromPtr(dto.Timeout))
		}
	case inventory.ChallengeRuleKindLoginPassword:
		if mask == 0 {
			return inventory.NewRuleLoginPassword(meta)
		}
	}
	return nil, i18n.EF(inventory.ErrInvalidChallengeRule, i18n.KeyHostYAMLInvalidFieldCombo, i18n.BoundStr("kind", dto.Kind))
}

func decodeChallengeSecretRule[R inventory.ChallengeRule](
	maskOK bool,
	refDTO *SecretRefDTO,
	meta inventory.ChallengeRuleMeta,
	build func(inventory.ChallengeRuleMeta, secret.Ref) (R, error),
) (inventory.ChallengeRule, error) {
	if !maskOK || refDTO == nil {
		return nil, i18n.EF(inventory.ErrInvalidChallengeRule, i18n.KeyHostYAMLInvalidFieldCombo, i18n.Str("kind", "secret_rule"))
	}
	ref, err := decodeSecretRefDTO(refDTO)
	if err != nil {
		return nil, err
	}
	return build(meta, ref)
}
