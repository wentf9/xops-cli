package option

import (
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// ParsedOption 表示经严格语法与值域校验的单条 OpenSSH 选项解析结果；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ParsedOption struct {
	key      OptionKey
	spec     OptionSpec
	rawValue string
	layer    OptionLayer
	valid    bool
}

// IsValid、Key、Spec、RawValue 与 Layer 为 ParsedOption 只读访问器。
func (p ParsedOption) IsValid() bool      { return p.valid }
func (p ParsedOption) Key() OptionKey     { return p.key }
func (p ParsedOption) Spec() OptionSpec   { return p.spec }
func (p ParsedOption) RawValue() string   { return p.rawValue }
func (p ParsedOption) Layer() OptionLayer { return p.layer.clone() }

// ParseOption、ParseOptionKV 与 ParseOptionLayer 严格解析并折叠单条或多条 OpenSSH 指令（大小写无关，未知/畸形/注入一律失败关闭）。
func ParseOption(directive string) (ParsedOption, error) {
	t := strings.TrimSpace(directive)
	if hasForbiddenControlChar(directive) || t == "" || t[0] == '#' || t[0] == '-' {
		return ParsedOption{}, domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "directive"), domi18n.BoundStr("value", directive))
	}
	rawKey, rawVal, err := splitDirectiveKV(t)
	if err != nil {
		return ParsedOption{}, err
	}
	return parseOptionWithRawValue(rawKey, rawVal)
}
func ParseOptionKV(key, value string) (ParsedOption, error) {
	t := strings.TrimSpace(value)
	if hasForbiddenControlChar(key) || hasForbiddenControlChar(value) || t == "" {
		return ParsedOption{}, domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "option"))
	}
	return parseOptionWithRawValue(key, t)
}
func ParseOptionLayer(directives ...string) (OptionLayer, error) {
	acc := UnsetOptionLayer()
	for _, raw := range directives {
		parsed, err := ParseOption(raw)
		if err != nil {
			return UnsetOptionLayer(), err
		}
		acc = acc.ApplyParsedOption(parsed)
	}
	return acc, nil
}

func parseOptionWithRawValue(rawKey, rawVal string) (ParsedOption, error) {
	key, ok := CanonicalOptionKey(rawKey)
	if !ok {
		return ParsedOption{}, domi18n.EF(ErrUnknownOption, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "option"), domi18n.BoundStr("value", rawKey))
	}
	spec, _ := LookupOptionSpec(key)
	tokens, rawOut, err := parseDirectiveValues(rawVal, spec)
	if err != nil {
		return ParsedOption{}, err
	}
	var l OptionLayer
	if err := applyOptionField(&l, spec.Key, tokens, rawOut); err != nil {
		return ParsedOption{}, err
	}
	return ParsedOption{spec.Key, spec, rawOut, l, true}, nil
}

func splitDirectiveKV(t string) (key, val string, err error) {
	i := strings.IndexFunc(t, func(r rune) bool { return r > 127 || (!isASCIIAlphaNum(byte(r)) && r != '_') })
	if i <= 0 {
		return "", "", domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "directive"), domi18n.BoundStr("value", t))
	}
	key, rest := t[:i], t[i:]
	switch rest[0] {
	case '=':
		val = strings.TrimSpace(rest[1:])
	case ' ', '\t':
		val = strings.TrimSpace(strings.TrimPrefix(strings.TrimLeft(rest, " \t"), "="))
	default:
		return "", "", domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "separator"))
	}
	if val == "" {
		return "", "", domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldEmpty, domi18n.BoundStr("field", key))
	}
	return key, val, nil
}
func parseDirectiveValues(raw string, spec OptionSpec) ([]string, string, error) {
	if spec.WholeLineCommand {
		cmd, err := parseWholeLineCommand(raw, spec.OpenSSHName)
		return []string{cmd}, cmd, err
	}
	if spec.Key == KeySendEnv || spec.Key == KeyUserKnownHostsFile {
		tokens, err := splitQuotedTokens(raw, spec.OpenSSHName)
		if err != nil || len(tokens) == 0 {
			return nil, "", domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", spec.OpenSSHName))
		}
		return tokens, strings.Join(tokens, " "), nil
	}
	v, err := unquoteSingleValue(raw, spec.OpenSSHName)
	return []string{v}, v, err
}
func parseWholeLineCommand(raw, name string) (string, error) {
	if raw[0] != '"' && raw[0] != '\'' {
		_, err := splitQuotedTokens(raw, name)
		return raw, err
	}
	seg, next, err := scanQuotedSpan(raw, 0, name)
	if err != nil || strings.TrimSpace(seg) == "" {
		return "", domi18n.EF(ErrInvalidOption, domi18n.KeyOptionQuotedSyntax, domi18n.Str("option", name))
	}
	if next == len(raw) {
		return seg, nil
	}
	if raw[next] != ' ' && raw[next] != '\t' {
		return "", domi18n.EF(ErrInvalidOption, domi18n.KeyOptionQuotedSyntax, domi18n.Str("option", name))
	}
	_, err = splitQuotedTokens(raw[next:], name)
	return raw, err
}
func unquoteSingleValue(raw, name string) (string, error) {
	if raw[0] != '"' && raw[0] != '\'' {
		if strings.ContainsAny(raw, " \t\"'") {
			return "", domi18n.EF(ErrInvalidOption, domi18n.KeyOptionQuotedSyntax, domi18n.Str("option", name))
		}
		return raw, nil
	}
	if seg, next, err := scanQuotedSpan(raw, 0, name); err == nil && next == len(raw) && seg != "" {
		return seg, nil
	}
	return "", domi18n.EF(ErrInvalidOption, domi18n.KeyOptionQuotedSyntax, domi18n.Str("option", name))
}
func splitQuotedTokens(raw, name string) ([]string, error) {
	var tokens []string
	for i := 0; i < len(raw); {
		if raw[i] == ' ' || raw[i] == '\t' {
			i++
			continue
		}
		tok, next, err := readNextQuotedToken(raw, i, name)
		if err != nil {
			return nil, err
		}
		tokens, i = append(tokens, tok), next
	}
	return tokens, nil
}
func readNextQuotedToken(raw string, i int, name string) (string, int, error) {
	var b strings.Builder
	for i < len(raw) && raw[i] != ' ' && raw[i] != '\t' {
		if raw[i] == '"' || raw[i] == '\'' {
			seg, next, err := scanQuotedSpan(raw, i, name)
			if err != nil {
				return "", 0, err
			}
			b.WriteString(seg)
			i = next
			continue
		}
		b.WriteByte(raw[i])
		i++
	}
	return b.String(), i, nil
}
func scanQuotedSpan(raw string, start int, name string) (string, int, error) {
	q := raw[start]
	var b strings.Builder
	for i := start + 1; i < len(raw); i++ {
		if q == '"' && raw[i] == '\\' && i+1 < len(raw) && (raw[i+1] == '"' || raw[i+1] == '\\') {
			i++
			b.WriteByte(raw[i])
			continue
		}
		if raw[i] == q {
			return b.String(), i + 1, nil
		}
		b.WriteByte(raw[i])
	}
	return "", 0, domi18n.EF(ErrInvalidOption, domi18n.KeyOptionQuotedSyntax, domi18n.Str("option", name))
}

func applyWith[A, T any](l *OptionLayer, arg A, parse func(A) (T, error), set func(OptionLayer, T) OptionLayer) error {
	v, err := parse(arg)
	if err == nil {
		*l = set(*l, v)
	}
	return err
}
func applyOptionField(l *OptionLayer, key OptionKey, tokens []string, val string) error {
	switch key {
	case KeyHostName:
		return applyWith(l, val, ParseHostNameSpec, OptionLayer.WithHostName)
	case KeyPort:
		return applyWith(l, val, parseStrictPortNumber, OptionLayer.WithPort)
	case KeyUser:
		return applyWith(l, val, ParseUsername, OptionLayer.WithUser)
	case KeyProxyJump:
		return applyWith(l, val, ParseProxyJump, OptionLayer.WithProxyRoute)
	case KeyProxyCommand:
		return applyWith(l, val, ParseProxyCommand, OptionLayer.WithProxyRoute)
	case KeyControlMaster:
		return applyControl(l, val, ParseControlMasterMode, ControlPolicy.WithMaster)
	case KeyControlPath:
		return applyControl(l, val, ParseControlPath, ControlPolicy.WithPath)
	case KeyControlPersist:
		return applyControl(l, val, ParseControlPersist, ControlPolicy.WithPersist)
	case KeyConnectTimeout, KeyServerAliveInterval:
		allowNone := key == KeyConnectTimeout
		set := map[OptionKey]func(OptionLayer, algebraic.Duration) OptionLayer{KeyConnectTimeout: OptionLayer.WithConnectTimeout, KeyServerAliveInterval: OptionLayer.WithServerAliveInterval}[key]
		return applyWith(l, val, func(s string) (algebraic.Duration, error) { return parseNonNegativeOpenSSHDuration(s, allowNone) }, set)
	case KeyServerAliveCountMax:
		return applyWith(l, val, parseNonNegativeUint32, OptionLayer.WithServerAliveCountMax)
	case KeyCiphers, KeyMACs, KeyKexAlgorithms, KeyHostKeyAlgorithms:
		return applyWith(l, val, ParseAlgoPolicy, map[OptionKey]func(OptionLayer, AlgoPolicy) OptionLayer{
			KeyCiphers: OptionLayer.WithCiphers, KeyMACs: OptionLayer.WithMACs,
			KeyKexAlgorithms: OptionLayer.WithKexAlgorithms, KeyHostKeyAlgorithms: OptionLayer.WithHostKeyAlgorithms,
		}[key])
	case KeyIdentityFile, KeyCertificateFile:
		return applyWith(l, tokens, ParsePathListEntries, map[OptionKey]func(OptionLayer, PathList) OptionLayer{
			KeyIdentityFile: OptionLayer.WithIdentityFiles, KeyCertificateFile: OptionLayer.WithCertificateFiles,
		}[key])
	case KeyUserKnownHostsFile:
		return applyWith(l, tokens, ParseKnownHostsList, OptionLayer.WithUserKnownHostsFiles)
	case KeyStrictHostKeyChecking:
		return applyWith(l, val, ParseStrictHostKeyChecking, OptionLayer.WithStrictHostKeyChecking)
	case KeySendEnv:
		return applyWith(l, tokens, ParseEnvFilterTokens, OptionLayer.WithSendEnv)
	case KeyLocalCommand:
		return applyWith(l, val, NewLocalSanitizedCmd, OptionLayer.WithLocalCommand)
	case KeyIdentitiesOnly, KeyBatchMode, KeyForwardAgent, KeyPermitLocalCommand:
		return applyWith(l, val, parseSSHBool, map[OptionKey]func(OptionLayer, bool) OptionLayer{
			KeyIdentitiesOnly: OptionLayer.WithIdentitiesOnly, KeyBatchMode: OptionLayer.WithBatchMode,
			KeyForwardAgent: OptionLayer.WithForwardAgent, KeyPermitLocalCommand: OptionLayer.WithPermitLocalCommand,
		}[key])
	default:
		return domi18n.EF(ErrUnknownOption, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "option"), domi18n.BoundStr("value", string(key)))
	}
}
func applyControl[T any](l *OptionLayer, val string, parse func(string) (T, error), with func(ControlPolicy, T) ControlPolicy) error {
	v, err := parse(val)
	if err == nil {
		*l = l.WithControlPolicy(with(UnsetControlPolicy(), v))
	}
	return err
}
func parseSSHBool(raw string) (bool, error) {
	if b, ok := map[string]bool{"yes": true, "true": true, "no": false, "false": false}[strings.ToLower(strings.TrimSpace(raw))]; ok {
		return b, nil
	}
	return false, domi18n.EF(ErrInvalidOption, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "bool"), domi18n.BoundStr("value", raw))
}
