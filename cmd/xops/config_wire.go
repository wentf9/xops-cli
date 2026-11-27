package main

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/host/store"
)

type runtimeMode uint8

const (
	runtimeModeCLI runtimeMode = iota + 1
	runtimeModeMCP
)

type resolvedPolicyConfig struct {
	profile       engine.PolicyProfile
	guardrail     engine.GuardrailConfig
	globalOptions option.OptionLayer
	auditRootDir  pathalg.LocalDir
	auditFileOpt  algebraic.Option[pathalg.LocalRootedDest]
}

// resolveDocumentConfig 将持久化 YAML vNext ConfigDocument 解码为运行期 Tier-3 GlobalOptions、
// 生效 PolicyProfile（CLI --policy 覆写优先，缺省回落配置档默认值）、GuardrailConfig（含 NodeOverrides）
// 与受控审计日志存储位置。
func resolveDocumentConfig(
	doc store.ConfigDocument,
	cliOverride engine.PolicyProfile,
	mode runtimeMode,
	stateDir, homeDir pathalg.LocalDir,
) (resolvedPolicyConfig, error) {
	globalOpts, err := decodeGlobalOptions(doc.Options)
	if err != nil {
		return resolvedPolicyConfig{}, err
	}
	profile, err := resolveEffectiveProfile(cliOverride, doc.Policy, mode)
	if err != nil {
		return resolvedPolicyConfig{}, err
	}
	guardrail, err := buildGuardrailFromPolicy(doc.Policy)
	if err != nil {
		return resolvedPolicyConfig{}, err
	}
	auditRoot, auditFileOpt, err := resolveAuditLocation(stateDir, homeDir, doc.Policy)
	if err != nil {
		return resolvedPolicyConfig{}, err
	}
	return resolvedPolicyConfig{
		profile:       profile,
		guardrail:     guardrail,
		globalOptions: globalOpts,
		auditRootDir:  auditRoot,
		auditFileOpt:  auditFileOpt,
	}, nil
}

func decodeGlobalOptions(dto *store.OptionLayerDTO) (option.OptionLayer, error) {
	if dto == nil {
		return option.UnsetOptionLayer(), nil
	}
	layer, err := store.DecodeOptionLayerDTO(dto)
	if err != nil {
		return option.UnsetOptionLayer(), fmt.Errorf("decode config.yaml global options failed: %w", err)
	}
	return layer, nil
}

func resolveEffectiveProfile(cliOverride engine.PolicyProfile, pol *store.PolicyConfigDTO, mode runtimeMode) (engine.PolicyProfile, error) {
	if cliOverride.IsValid() {
		return cliOverride, nil
	}
	raw := ""
	if pol != nil {
		if mode == runtimeModeMCP {
			raw = strings.TrimSpace(pol.MCPDefault)
		} else {
			raw = strings.TrimSpace(pol.CLIDefault)
		}
	}
	if raw != "" {
		parsed, err := engine.ParsePolicyProfile(raw)
		if err != nil {
			return engine.PolicyProfileInvalid, fmt.Errorf("invalid policy default profile %q: %w", raw, err)
		}
		return parsed, nil
	}
	if mode == runtimeModeMCP {
		return engine.PolicyProfileStrictAgent, nil
	}
	return engine.PolicyProfileDirectOperator, nil
}

func buildGuardrailFromPolicy(pol *store.PolicyConfigDTO) (engine.GuardrailConfig, error) {
	cfg := engine.DefaultGuardrailConfig()
	if pol == nil || pol.Guardrail == nil {
		return cfg, nil
	}
	g := pol.Guardrail
	if err := applyGuardrailScalars(&cfg, g); err != nil {
		return engine.GuardrailConfig{}, err
	}
	if len(g.ProtectedPaths) > 0 {
		cfg.ProtectedPatterns = slices.Clone(g.ProtectedPaths)
	}
	if len(g.NodeOverrides) > 0 {
		ov, err := store.DecodeNodeOverridesDTO(g.NodeOverrides)
		if err != nil {
			return engine.GuardrailConfig{}, fmt.Errorf("decode policy.guardrail.node_overrides failed: %w", err)
		}
		cfg.NodeOverrides = algebraic.Some(ov)
	}
	if g.ApprovalTTL != nil {
		cfg.ApprovalTTL = algebraic.Some(*g.ApprovalTTL)
	}
	return cfg, nil
}

func applyGuardrailScalars(cfg *engine.GuardrailConfig, g *store.GuardrailConfigDTO) error {
	if raw := strings.TrimSpace(g.ApprovalThreshold); raw != "" {
		lvl, err := security.ParseRiskLevel(raw)
		if err != nil {
			return fmt.Errorf("invalid policy.guardrail.approval_threshold %q: %w", raw, err)
		}
		cfg.ApprovalThreshold = lvl
	}
	if raw := strings.TrimSpace(g.NoElicitFallback); raw != "" {
		fb, err := engine.ParseNoElicitFallback(raw)
		if err != nil {
			return fmt.Errorf("invalid policy.guardrail.no_elicit_fallback %q: %w", raw, err)
		}
		cfg.NoElicitFallback = fb
	}
	return nil
}

func resolveAuditLocation(
	stateDir, homeDir pathalg.LocalDir,
	pol *store.PolicyConfigDTO,
) (pathalg.LocalDir, algebraic.Option[pathalg.LocalRootedDest], error) {
	if pol == nil || pol.Guardrail == nil || strings.TrimSpace(pol.Guardrail.AuditLog) == "" {
		return stateDir, algebraic.None[pathalg.LocalRootedDest](), nil
	}
	raw := expandTildePrefix(strings.TrimSpace(pol.Guardrail.AuditLog), homeDir)
	if rel, err := pathalg.ParseLocalRootedDest(raw); err == nil {
		return stateDir, algebraic.Some(rel), nil
	}
	return splitAbsoluteAuditLocation(raw)
}

func splitAbsoluteAuditLocation(raw string) (pathalg.LocalDir, algebraic.Option[pathalg.LocalRootedDest], error) {
	norm := strings.ReplaceAll(raw, `\`, "/")
	dirPart := path.Dir(norm)
	basePart := path.Base(norm)
	if dirPart == "." || dirPart == "" || basePart == "." || basePart == "/" || basePart == "" {
		return zeroVal[pathalg.LocalDir](), algebraic.None[pathalg.LocalRootedDest](), fmt.Errorf("invalid policy.guardrail.audit_log path %q", raw)
	}
	// Windows 盘符根目录（如 "C:"）补全斜杠以满足 ParseLocalDir。
	if len(dirPart) == 2 && dirPart[1] == ':' {
		dirPart += "/"
	}
	rootDir, err := pathalg.ParseLocalDir(dirPart)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), algebraic.None[pathalg.LocalRootedDest](), fmt.Errorf("invalid policy.guardrail.audit_log dir %q: %w", raw, err)
	}
	fileDest, err := pathalg.ParseLocalRootedDest(basePart)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), algebraic.None[pathalg.LocalRootedDest](), fmt.Errorf("invalid policy.guardrail.audit_log file %q: %w", raw, err)
	}
	return rootDir, algebraic.Some(fileDest), nil
}

func expandTildePrefix(raw string, homeDir pathalg.LocalDir) string {
	if strings.HasPrefix(raw, "~/") || strings.HasPrefix(raw, `~\`) {
		return strings.TrimRight(homeDir.String(), `/\`) + "/" + raw[2:]
	}
	return raw
}

func joinRootedDestDir(base pathalg.LocalDir, rel pathalg.LocalRootedDest) (pathalg.LocalDir, error) {
	cur := base
	for comp := range strings.SplitSeq(rel.String(), "/") {
		if comp == "" {
			continue
		}
		var err error
		cur, err = cur.JoinComponent(comp)
		if err != nil {
			return zeroVal[pathalg.LocalDir](), err
		}
	}
	return cur, nil
}
