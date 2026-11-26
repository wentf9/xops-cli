package store

import (
	"errors"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/internal/host/store/yamlcodec"
)

// 以下类型别名与转发表暴露 internal/host/store/yamlcodec 的完整 YAML vNext version: 2 编解码契约，
// 保持 store 包既有公开接口稳定且不增加跨包适配噪音。
type (
	ConfigDocument     = yamlcodec.ConfigDocument
	VaultConfigDTO     = yamlcodec.VaultConfigDTO
	VaultStoreDTO      = yamlcodec.VaultStoreDTO
	PolicyConfigDTO    = yamlcodec.PolicyConfigDTO
	NodeOverrideDTO    = yamlcodec.NodeOverrideDTO
	GuardrailConfigDTO = yamlcodec.GuardrailConfigDTO
	InventoryConfigDTO = yamlcodec.InventoryConfigDTO
	SecretRefDTO       = yamlcodec.SecretRefDTO
	HostDTO            = yamlcodec.HostDTO
	LaunchProfileDTO   = yamlcodec.LaunchProfileDTO
	NodeOriginDTO      = yamlcodec.NodeOriginDTO
	NodeDTO            = yamlcodec.NodeDTO
	IdentityDTO        = yamlcodec.IdentityDTO
	AuthMethodDTO      = yamlcodec.AuthMethodDTO
	ChallengeRuleDTO   = yamlcodec.ChallengeRuleDTO
	ProxyRouteDTO      = yamlcodec.ProxyRouteDTO
	ControlPolicyDTO   = yamlcodec.ControlPolicyDTO
	AlgoPolicyDTO      = yamlcodec.AlgoPolicyDTO
	PathListDTO        = yamlcodec.PathListDTO
	KnownHostsListDTO  = yamlcodec.KnownHostsListDTO
	EnvFilterDTO       = yamlcodec.EnvFilterDTO
	OptionLayerDTO     = yamlcodec.OptionLayerDTO
)

// DecodeConfigDocumentYAML 严格以 KnownFields(true) 解码 YAML vNext version: 2 文档并校验全部全图不变量。
func DecodeConfigDocumentYAML(raw []byte) (ConfigDocument, inventory.Graph, error) {
	doc, graph, err := yamlcodec.DecodeConfigDocumentYAML(raw)
	if errors.Is(err, yamlcodec.ErrUnsupportedSchemaVersion) {
		return doc, graph, fmt.Errorf("%w: %w", ErrUnsupportedSchemaVersion, err)
	}
	return doc, graph, err
}

// EncodeConfigDocumentYAML 将 version: 2 文档确定性编码为规范 2 空格缩进 YAML 字节流。
func EncodeConfigDocumentYAML(doc ConfigDocument) ([]byte, error) {
	out, err := yamlcodec.EncodeConfigDocumentYAML(doc)
	if errors.Is(err, yamlcodec.ErrUnsupportedSchemaVersion) {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedSchemaVersion, err)
	}
	return out, err
}

// EncodeInventoryGraphDTO 将不可变 inventory.Graph 无损编码为 YAML vNext InventoryConfigDTO。
func EncodeInventoryGraphDTO(g inventory.Graph) (InventoryConfigDTO, error) {
	return yamlcodec.EncodeInventoryGraphDTO(g)
}

// DecodeOptionLayerDTO 将 YAML vNext OptionLayerDTO 解码为不可变 option.OptionLayer（供 Tier-3 全局选项装配）。
func DecodeOptionLayerDTO(dto *OptionLayerDTO) (option.OptionLayer, error) {
	return yamlcodec.DecodeOptionLayerDTO(dto)
}

// EncodeOptionLayerDTO 将不可变 option.OptionLayer 无损编码为 YAML vNext OptionLayerDTO。
func EncodeOptionLayerDTO(layer option.OptionLayer) (*OptionLayerDTO, error) {
	return yamlcodec.EncodeOptionLayerDTO(layer)
}

// DecodeNodeOverridesDTO 将 YAML node_overrides 映射解码为不可变 security.NodeOverrides 格集合。
func DecodeNodeOverridesDTO(entries map[string]NodeOverrideDTO) (security.NodeOverrides, error) {
	return yamlcodec.DecodeNodeOverridesDTO(entries)
}

// EncodeNodeOverridesDTO 将不可变 security.NodeOverrides 无损编码为 YAML DTO 映射。
func EncodeNodeOverridesDTO(ov security.NodeOverrides) (map[string]NodeOverrideDTO, error) {
	return yamlcodec.EncodeNodeOverridesDTO(ov)
}
