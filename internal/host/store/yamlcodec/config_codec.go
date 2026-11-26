package yamlcodec

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/ports"
	"go.yaml.in/yaml/v3"
)

// ConfigDocument 及各子段定义 XOps v2 YAML vNext（version: 2）完整强判别式持久化文档模型（ADR-006 / RFC §4.2）。
// 所有持久化时长字段强制使用 algebraic.Duration（零裸 time.Duration），零 v1 迁移与兼容字段。
type (
	//xops:dto
	ConfigDocument struct {
		Version   int                `yaml:"version"`
		Revision  uint64             `yaml:"revision,omitempty"`
		Vault     *VaultConfigDTO    `yaml:"vault,omitempty"`
		Policy    *PolicyConfigDTO   `yaml:"policy,omitempty"`
		Inventory InventoryConfigDTO `yaml:"inventory"`
	}
	//xops:dto
	VaultConfigDTO struct {
		DefaultStore     string                   `yaml:"default_store,omitempty"`
		RememberPrompted string                   `yaml:"remember_prompted,omitempty"`
		Stores           map[string]VaultStoreDTO `yaml:"stores,omitempty"`
	}
	//xops:dto
	VaultStoreDTO struct {
		Kind    string              `yaml:"kind"`
		Path    string              `yaml:"path,omitempty"`
		Command string              `yaml:"command,omitempty"`
		Args    []string            `yaml:"args,omitempty"`
		Timeout *algebraic.Duration `yaml:"timeout,omitempty"`
	}
	//xops:dto
	PolicyConfigDTO struct {
		CLIDefault string              `yaml:"cli_default,omitempty"`
		MCPDefault string              `yaml:"mcp_default,omitempty"`
		Guardrail  *GuardrailConfigDTO `yaml:"guardrail,omitempty"`
	}
	//xops:dto
	GuardrailConfigDTO struct {
		ApprovalThreshold string              `yaml:"approval_threshold,omitempty"`
		NoElicitFallback  string              `yaml:"no_elicit_fallback,omitempty"`
		AuditLog          string              `yaml:"audit_log,omitempty"`
		ProtectedPaths    []string            `yaml:"protected_paths,omitempty"`
		ApprovalTTL       *algebraic.Duration `yaml:"approval_ttl,omitempty"`
	}
	//xops:dto
	InventoryConfigDTO struct {
		KnownStores []string               `yaml:"known_stores,omitempty"`
		Hosts       map[string]HostDTO     `yaml:"hosts,omitempty"`
		Identities  map[string]IdentityDTO `yaml:"identities,omitempty"`
		Nodes       map[string]NodeDTO     `yaml:"nodes,omitempty"`
	}
	//xops:dto
	SecretRefDTO struct {
		Store string `yaml:"store"`
		Item  string `yaml:"item"`
	}
	//xops:dto
	HostDTO struct {
		Address     string   `yaml:"address"`
		Port        *uint16  `yaml:"port,omitempty"`
		Alias       string   `yaml:"alias,omitempty"`
		Description string   `yaml:"description,omitempty"`
		Tags        []string `yaml:"tags,omitempty"`
	}
	//xops:dto
	LaunchProfileDTO struct {
		LaunchDialect string `yaml:"launch_dialect,omitempty"`
		Interpreter   string `yaml:"interpreter"`
		Login         string `yaml:"login"`
	}
	//xops:dto
	NodeOriginDTO struct {
		Kind        string `yaml:"kind"`
		HostPattern string `yaml:"host_pattern,omitempty"`
		BaseAlias   string `yaml:"base_alias,omitempty"`
		SourceFile  string `yaml:"source_file,omitempty"`
		ParentNode  string `yaml:"parent_node,omitempty"`
	}
	//xops:dto
	NodeDTO struct {
		Host                 string            `yaml:"host"`
		Identity             string            `yaml:"identity"`
		Aliases              []string          `yaml:"aliases,omitempty"`
		Tags                 []string          `yaml:"tags,omitempty"`
		Proxy                *ProxyRouteDTO    `yaml:"proxy,omitempty"`
		Execution            *LaunchProfileDTO `yaml:"execution,omitempty"`
		Options              *OptionLayerDTO   `yaml:"options,omitempty"`
		PrivilegePasswordRef *SecretRefDTO     `yaml:"privilege_password_ref,omitempty"`
		Origin               *NodeOriginDTO    `yaml:"origin,omitempty"`
		Description          string            `yaml:"description,omitempty"`
	}
)

// DecodeConfigDocumentYAML 严格以 KnownFields(true) 解码 YAML vNext version: 2 文档并校验全部全图不变量。
// 任何非 version: 2（含 v1）、未知字段、多文档尾随数据或图不变量违例均严格失败关闭并返回包装 ports.ErrCorruptData 的错误。
func DecodeConfigDocumentYAML(raw []byte) (doc ConfigDocument, graph inventory.Graph, err error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return doc, graph, fmt.Errorf("%w: 配置文件为空", ports.ErrCorruptData)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err = dec.Decode(&doc); err != nil {
		return ConfigDocument{}, graph, fmt.Errorf("%w: YAML vNext 解析失败: %w", ports.ErrCorruptData, err)
	}
	if err = rejectTrailingYAMLDocs(dec); err != nil {
		return ConfigDocument{}, graph, err
	}
	if doc.Version != SchemaVersionV2 {
		return ConfigDocument{}, graph, fmt.Errorf("%w: %w (got=%d)", ports.ErrCorruptData, ErrUnsupportedSchemaVersion, doc.Version)
	}
	if err = validateTopSections(doc.Vault, doc.Policy); err != nil {
		return ConfigDocument{}, graph, fmt.Errorf("%w: %w", ports.ErrCorruptData, err)
	}
	if graph, err = decodeInventoryGraph(doc.Inventory, doc.Vault); err != nil {
		return ConfigDocument{}, zeroVal[inventory.Graph](), fmt.Errorf("%w: %w", ports.ErrCorruptData, err)
	}
	return doc, graph, nil
}

func rejectTrailingYAMLDocs(dec *yaml.Decoder) error {
	var extra yaml.Node
	if err := dec.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("%w: 存在非法尾随 YAML 文档: %w", ports.ErrCorruptData, err)
	}
	return fmt.Errorf("%w: 配置文件禁止包含多份 YAML 文档", ports.ErrCorruptData)
}

// EncodeConfigDocumentYAML 将 version: 2 文档确定性编码为规范 2 空格缩进 YAML 字节流。
func EncodeConfigDocumentYAML(doc ConfigDocument) ([]byte, error) {
	if doc.Version != SchemaVersionV2 {
		return nil, fmt.Errorf("%w: 仅允许编码 version=%d", ErrUnsupportedSchemaVersion, SchemaVersionV2)
	}
	if err := validateTopSections(doc.Vault, doc.Policy); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	encErr := enc.Encode(&doc)
	closeErr := enc.Close()
	if err := errors.Join(encErr, closeErr); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodeInventoryGraphDTO 将不可变 inventory.Graph 无损编码为 YAML vNext InventoryConfigDTO。
func EncodeInventoryGraphDTO(g inventory.Graph) (InventoryConfigDTO, error) {
	if !g.IsValid() {
		return InventoryConfigDTO{}, inventory.ErrInvalidGraph
	}
	dto := InventoryConfigDTO{KnownStores: g.KnownStores()}
	if hosts := g.Hosts(); len(hosts) > 0 {
		dto.Hosts = make(map[string]HostDTO, len(hosts))
		for _, h := range hosts {
			dto.Hosts[h.ID().String()] = encodeHostDTO(h)
		}
	}
	var err error
	if dto.Identities, err = encodeMapValues(g.Identities(), func(id inventory.Identity) string { return id.ID().String() }, encodeIdentityDTO); err != nil {
		return InventoryConfigDTO{}, err
	}
	if dto.Nodes, err = encodeMapValues(g.Nodes(), func(n inventory.Node) string { return n.ID().String() }, encodeNodeDTO); err != nil {
		return InventoryConfigDTO{}, err
	}
	return dto, nil
}

func validateTopSections(v *VaultConfigDTO, p *PolicyConfigDTO) error {
	return errors.Join(validateVaultConfigDTO(v), validatePolicyConfigDTO(p))
}

func validateVaultConfigDTO(v *VaultConfigDTO) error {
	if v == nil {
		return nil
	}
	if !isEmptyOrIn(v.RememberPrompted, "always", "ask", "never") {
		return fmt.Errorf("vault.remember_prompted=%q 非法", v.RememberPrompted)
	}
	for name, st := range v.Stores {
		if strings.TrimSpace(name) == "" || !isIn(st.Kind, "offline_aead", "os_keychain", "external_helper", "none") {
			return fmt.Errorf("vault.stores.%s 名称或 kind=%q 非法", name, st.Kind)
		}
		if st.Timeout != nil && !st.Timeout.IsPositive() {
			return fmt.Errorf("vault.stores.%s.timeout 必须为正时长", name)
		}
	}
	if v.DefaultStore != "" && len(v.Stores) > 0 {
		if _, ok := v.Stores[v.DefaultStore]; !ok {
			return fmt.Errorf("vault.default_store=%q 未在 vault.stores 中声明", v.DefaultStore)
		}
	}
	return nil
}

func validatePolicyConfigDTO(p *PolicyConfigDTO) error {
	if p == nil {
		return nil
	}
	if !isEmptyOrIn(p.CLIDefault, "direct_operator", "strict") || !isEmptyOrIn(p.MCPDefault, "strict_agent", "direct_operator") {
		return fmt.Errorf("policy 默认策略配置非法")
	}
	if g := p.Guardrail; g != nil {
		if !isEmptyOrIn(g.ApprovalThreshold, "safe", "moderate", "dangerous", "critical") || !isEmptyOrIn(g.NoElicitFallback, "deny", "ask") {
			return fmt.Errorf("policy.guardrail 阈值或降级策略非法")
		}
		if g.ApprovalTTL != nil && !g.ApprovalTTL.IsPositive() {
			return fmt.Errorf("policy.guardrail.approval_ttl 必须为正时长")
		}
	}
	return nil
}

func decodeInventoryGraph(dto InventoryConfigDTO, vault *VaultConfigDTO) (z inventory.Graph, err error) {
	hosts, err := decodeSortedMap("hosts", dto.Hosts, decodeHostDTO)
	if err != nil {
		return z, err
	}
	idents, err := decodeSortedMap("identities", dto.Identities, decodeIdentityDTO)
	if err != nil {
		return z, err
	}
	nodes, err := decodeSortedMap("nodes", dto.Nodes, decodeNodeDTO)
	if err != nil {
		return z, err
	}
	knownStores := mergeKnownStores(dto.KnownStores, vault)
	return inventory.NewGraph(inventory.GraphSpec{Hosts: hosts, Identities: idents, Nodes: nodes, KnownStores: knownStores})
}

// mergeKnownStores 将 inventory.known_stores 与 vault.stores 键取去重有序并集，
// 防止 CommitCAS 落盘 inventory.known_stores 后用户再于 vault.stores 新增存储名时触发 ErrUnknownSecretStore。
func mergeKnownStores(declared []string, vault *VaultConfigDTO) []string {
	if vault == nil || len(vault.Stores) == 0 {
		return slices.Clone(declared)
	}
	out := make([]string, 0, len(declared)+len(vault.Stores))
	out = append(out, declared...)
	for k := range maps.Keys(vault.Stores) {
		out = append(out, k)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func encodeHostDTO(h inventory.Host) HostDTO {
	ep := h.Endpoint()
	return HostDTO{
		Address: ep.Host().String(), Port: ptrOf(ep.Port()),
		Alias: optStr(h.Alias()), Description: h.Description(), Tags: toStrings(h.Tags()),
	}
}

func decodeHostDTO(rawID string, dto HostDTO) (z inventory.Host, err error) {
	hid, err := inventory.ParseHostID(rawID)
	if err != nil {
		return z, err
	}
	ch, err := netaddr.ParseCanonicalHost(dto.Address)
	if err != nil {
		return z, err
	}
	port := netaddr.DefaultSSHPort
	if dto.Port != nil {
		if *dto.Port == 0 {
			return z, fmt.Errorf("%w: host port 不能为 0", inventory.ErrInvalidHost)
		}
		port = *dto.Port
	}
	ep, err := netaddr.NewEndpoint(ch, port)
	if err != nil {
		return z, err
	}
	aliasOpt, err := parseOptional(dto.Alias, inventory.ParseAlias)
	if err != nil {
		return z, err
	}
	tags, err := mapSliceErr(dto.Tags, inventory.ParseTag)
	if err != nil {
		return z, err
	}
	return inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep, Alias: aliasOpt, Description: dto.Description, Tags: tags})
}

func encodeNodeDTO(n inventory.Node) (NodeDTO, error) {
	proxyDTO, err := encodeProxyRouteDTO(n.Proxy())
	if err != nil {
		return NodeDTO{}, err
	}
	optDTO, err := encodeOptionLayerDTO(n.Options())
	if err != nil {
		return NodeDTO{}, err
	}
	originDTO, err := encodeNodeOriginDTO(n.Origin())
	if err != nil {
		return NodeDTO{}, err
	}
	dto := NodeDTO{
		Host: n.HostRef().String(), Identity: n.IdentityRef().String(),
		Aliases: toStrings(n.Aliases()), Tags: toStrings(n.Tags()),
		Proxy: proxyDTO, Execution: encodeLaunchProfileDTO(n.Execution()),
		Options: optDTO, Origin: originDTO, Description: n.Description(),
	}
	if ref, ok := n.PrivilegePasswordRef().Get(); ok {
		dto.PrivilegePasswordRef = encodeSecretRefDTO(ref)
	}
	return dto, nil
}

func decodeNodeDTO(rawID string, dto NodeDTO) (z inventory.Node, err error) {
	nid, err := inventory.ParseNodeID(rawID)
	if err != nil {
		return z, err
	}
	hid, err := inventory.ParseHostID(dto.Host)
	if err != nil {
		return z, err
	}
	iid, err := inventory.ParseIdentityID(dto.Identity)
	if err != nil {
		return z, err
	}
	aliases, err := mapSliceErr(dto.Aliases, inventory.ParseAlias)
	if err != nil {
		return z, err
	}
	tags, err := mapSliceErr(dto.Tags, inventory.ParseTag)
	if err != nil {
		return z, err
	}
	return buildDecodedNode(nid, hid, iid, aliases, tags, dto)
}

func buildDecodedNode(nid inventory.NodeID, hid inventory.HostID, iid inventory.IdentityID, aliases []inventory.Alias, tags []inventory.Tag, dto NodeDTO) (z inventory.Node, err error) {
	proxy, err := decodeProxyRouteDTO(dto.Proxy)
	if err != nil {
		return z, err
	}
	execOpt, err := decodeLaunchProfileDTO(dto.Execution)
	if err != nil {
		return z, err
	}
	opts, err := decodeOptionLayerDTO(dto.Options)
	if err != nil {
		return z, err
	}
	privOpt, err := decodeOptionalSecretRefDTO(dto.PrivilegePasswordRef)
	if err != nil {
		return z, err
	}
	origin, err := decodeNodeOriginDTO(dto.Origin)
	if err != nil {
		return z, err
	}
	return inventory.NewNode(inventory.NodeSpec{
		ID: nid, HostRef: hid, IdentityRef: iid, Aliases: aliases, Tags: tags,
		Proxy: proxy, Execution: execOpt, Options: opts, PrivilegePasswordRef: privOpt,
		Origin: origin, Description: dto.Description,
	})
}

func encodeLaunchProfileDTO(opt algebraic.Option[execution.LaunchProfile]) *LaunchProfileDTO {
	lp, ok := opt.Get()
	if !ok {
		return nil
	}
	return &LaunchProfileDTO{
		LaunchDialect: optStr(lp.DialectOption()),
		Interpreter:   lp.Interpreter().String(),
		Login:         lp.LoginMode().String(),
	}
}

func decodeLaunchProfileDTO(dto *LaunchProfileDTO) (algebraic.Option[execution.LaunchProfile], error) {
	if dto == nil {
		return algebraic.None[execution.LaunchProfile](), nil
	}
	dialectOpt, err := parseOptional(dto.LaunchDialect, execution.ParseLaunchDialect)
	if err != nil {
		return algebraic.None[execution.LaunchProfile](), err
	}
	interp, err := execution.ParseInterpreter(dto.Interpreter)
	if err != nil {
		return algebraic.None[execution.LaunchProfile](), err
	}
	login, err := execution.ParseLoginMode(dto.Login)
	if err != nil {
		return algebraic.None[execution.LaunchProfile](), err
	}
	lp, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{Dialect: dialectOpt, Interpreter: interp, Login: login})
	if err != nil {
		return algebraic.None[execution.LaunchProfile](), err
	}
	return algebraic.Some(lp), nil
}

func encodeNodeOriginDTO(origin inventory.NodeOrigin) (*NodeOriginDTO, error) {
	if origin == nil || !origin.IsValid() {
		return nil, inventory.ErrInvalidNodeOrigin
	}
	switch v := origin.(type) {
	case *inventory.OriginManaged:
		return nil, nil
	case *inventory.OriginOpenSSHVirtual:
		return &NodeOriginDTO{Kind: v.Kind().String(), HostPattern: v.HostPattern(), SourceFile: v.SourceFile()}, nil
	case *inventory.OriginOpenSSHDerived:
		return &NodeOriginDTO{Kind: v.Kind().String(), BaseAlias: v.BaseAlias(), SourceFile: v.SourceFile()}, nil
	case *inventory.OriginAdHoc:
		dto := &NodeOriginDTO{Kind: v.Kind().String()}
		if pid, ok := v.ParentNode().Get(); ok {
			dto.ParentNode = pid.String()
		}
		return dto, nil
	default:
		return nil, inventory.ErrInvalidNodeOrigin
	}
}

func decodeNodeOriginDTO(dto *NodeOriginDTO) (inventory.NodeOrigin, error) {
	if dto == nil {
		return inventory.NewOriginManaged(), nil
	}
	kind, err := option.ParseOriginKind(dto.Kind)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", inventory.ErrInvalidNodeOrigin, err)
	}
	mask := fieldMask(dto.HostPattern != "", dto.BaseAlias != "", dto.SourceFile != "", dto.ParentNode != "")
	switch kind {
	case option.OriginManaged:
		if mask == 0 {
			return inventory.NewOriginManaged(), nil
		}
	case option.OriginOpenSSHVirtual:
		if mask&^5 == 0 {
			return inventory.NewOriginOpenSSHVirtual(dto.HostPattern, dto.SourceFile)
		}
	case option.OriginOpenSSHDerived:
		if mask&^6 == 0 {
			return inventory.NewOriginOpenSSHDerived(dto.BaseAlias, dto.SourceFile)
		}
	case option.OriginAdHoc:
		return decodeAdHocOriginDTO(dto.ParentNode, mask)
	}
	return nil, fmt.Errorf("%w: 节点来源 %q 字段组合非法", inventory.ErrInvalidNodeOrigin, dto.Kind)
}

func decodeAdHocOriginDTO(parentRaw string, mask uint8) (inventory.NodeOrigin, error) {
	if mask&^8 != 0 {
		return nil, fmt.Errorf("%w: ad_hoc 来源字段组合非法", inventory.ErrInvalidNodeOrigin)
	}
	parentOpt, err := parseOptional(parentRaw, inventory.ParseNodeID)
	if err != nil {
		return nil, err
	}
	return inventory.NewOriginAdHoc(parentOpt)
}

func encodeSecretRefDTO(ref secret.Ref) *SecretRefDTO {
	return &SecretRefDTO{Store: ref.Store(), Item: ref.Item()}
}

func decodeSecretRefDTO(dto *SecretRefDTO) (secret.Ref, error) {
	if dto == nil {
		return zeroVal[secret.Ref](), secret.ErrInvalidRef
	}
	return secret.NewRef(dto.Store, dto.Item)
}

func decodeOptionalSecretRefDTO(dto *SecretRefDTO) (algebraic.Option[secret.Ref], error) {
	if dto == nil {
		return algebraic.None[secret.Ref](), nil
	}
	ref, err := decodeSecretRefDTO(dto)
	if err != nil {
		return algebraic.None[secret.Ref](), err
	}
	return algebraic.Some(ref), nil
}
