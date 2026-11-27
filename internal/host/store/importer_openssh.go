package store

import (
	"context"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/openssh"
	"github.com/wentf9/xops-cli/internal/i18n"
)

const openSSHFormatName = "openssh"

// OpenSSHImporter 实现 ports.FormatImporter，复用 internal/host/openssh 同源纯内存流解析器
// （单一 t4 自上而下 ApplyParsedOption 折叠），将 OpenSSH ssh_config(5) 转换为 inventory.ImportBundle：
//   - 100% 零磁盘环境访问（Include 指令不触碰本地文件，而是产出结构化 ImportWarning）；
//   - 产出 OriginOpenSSHDerived 节点，完整保留代理路由与 OpenSSH OptionLayer 策略；
//   - 100% 零 v1 代码、零 nolint 抑制指令。
//
//xops:opaque
//xops:failclosed
type OpenSSHImporter struct {
	maxImportBytes int64
	localIdentity  algebraic.Option[ports.LocalIdentityInfo]
	defaultUser    algebraic.Option[option.Username]
	valid          bool
}

// NewOpenSSHImporter 校验读取字节上限、可选 LocalIdentity 与默认用户名后构造 OpenSSHImporter。
func NewOpenSSHImporter(spec OpenSSHImporterSpec) (*OpenSSHImporter, error) {
	maxBytes, err := normalizeBoundedLimit(spec.MaxImportBytes, defaultMaxImportBytes, maxAllowedImportBytes, "MaxImportBytes")
	if err != nil {
		return nil, err
	}
	if id, ok := spec.LocalIdentity.Get(); ok && !id.IsValid() {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "LocalIdentity"))
	}
	if u, ok := spec.DefaultUser.Get(); ok && !u.IsValid() {
		return nil, i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "DefaultUser"))
	}
	return &OpenSSHImporter{
		maxImportBytes: maxBytes,
		localIdentity:  spec.LocalIdentity,
		defaultUser:    spec.DefaultUser,
		valid:          true,
	}, nil
}

// Format 返回规范小写格式标识 "openssh"。
func (i *OpenSSHImporter) Format() string { return openSSHFormatName }

// Import 解析单份 OpenSSH 配置流并构造格式无关 inventory.ImportBundle。
func (i *OpenSSHImporter) Import(ctx context.Context, sourceName string, r io.Reader) (inventory.ImportBundle, error) {
	if err := checkCtxReady(ctx, i != nil && i.valid, "OpenSSHImporter"); err != nil {
		return zeroVal[inventory.ImportBundle](), err
	}
	if r == nil {
		return zeroVal[inventory.ImportBundle](), i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNilDependency, i18n.Str("field", "r"))
	}
	raw, err := readBoundedStream(r, i.maxImportBytes)
	if err != nil {
		return zeroVal[inventory.ImportBundle](), err
	}
	srcName := strings.TrimSpace(sourceName)
	if srcName == "" {
		srcName = "ssh_config"
	}
	parsed, err := openssh.ParseConfigStream(srcName, raw, i.localIdentity)
	if err != nil {
		return zeroVal[inventory.ImportBundle](), domi18n.WrapSentinel(ports.ErrCorruptData, err)
	}
	return i.convertParsedStream(srcName, parsed)
}

func (i *OpenSSHImporter) convertParsedStream(srcName string, parsed openssh.ParsedStreamResult) (inventory.ImportBundle, error) {
	spec := inventory.ImportBundleSpec{SourceFormat: openSSHFormatName}
	for _, d := range parsed.Diagnostics {
		if msg, ok := d.Localized.Get(); ok && msg.IsValid() {
			appendLocalizedImportWarning(&spec, d.Code, d.Subject, msg)
			continue
		}
		appendImportWarning(&spec, d.Code, d.Subject, d.Message)
	}
	for _, vh := range parsed.Hosts {
		if err := i.appendVirtualHost(&spec, srcName, vh); err != nil {
			return zeroVal[inventory.ImportBundle](), err
		}
	}
	if len(spec.Nodes) == 0 {
		return zeroVal[inventory.ImportBundle](), i18n.EF(ports.ErrCorruptData, i18n.KeyHostStoreOpenSSHNoNodes)
	}
	return inventory.NewImportBundle(spec)
}

func (i *OpenSSHImporter) appendVirtualHost(spec *inventory.ImportBundleSpec, srcName string, vh ports.OpenSSHVirtualHost) error {
	nid, err := inventory.ParseNodeID(vh.Alias())
	if err != nil {
		appendLocalizedImportWarning(spec, "alias_skipped", vh.Alias(), i18n.NewMessage(i18n.KeyHostStoreImportWarnAlias))
		return nil
	}
	ep, hasEP := vh.Endpoint().Get()
	if !hasEP || !ep.IsValid() {
		appendLocalizedImportWarning(spec, "host_unresolved", vh.Alias(), i18n.NewMessage(i18n.KeyHostStoreImportWarnHost))
		return nil
	}
	user, uErr := i.resolveImportUser(vh)
	if uErr != nil {
		appendLocalizedImportWarning(spec, "user_missing", vh.Alias(), i18n.NewMessage(i18n.KeyHostStoreImportWarnUser))
		return nil
	}
	auth, err := buildOpenSSHImportAuth(spec, vh.Alias(), vh.Layer())
	if err != nil {
		return err
	}
	return appendDerivedOpenSSHEntities(spec, srcName, nid, vh, ep, user, auth)
}

func (i *OpenSSHImporter) resolveImportUser(vh ports.OpenSSHVirtualHost) (option.Username, error) {
	if u, ok := vh.User().Get(); ok && u.IsValid() {
		return u, nil
	}
	if u, ok := i.defaultUser.Get(); ok && u.IsValid() {
		return u, nil
	}
	if id, ok := i.localIdentity.Get(); ok {
		return option.ParseUsername(id.LocalUser())
	}
	return zeroVal[option.Username](), i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "user"))
}

func buildOpenSSHImportAuth(spec *inventory.ImportBundleSpec, alias string, layer option.OptionLayer) (inventory.AuthMethod, error) {
	keys := collectLiteralSpecs(spec, alias, layer.IdentityFiles(), inventory.ParseKeyPathSpec, "template_key_skipped", "IdentityFile")
	certs := collectLiteralSpecs(spec, alias, layer.CertificateFiles(), inventory.ParseCertPathSpec, "template_cert_skipped", "CertificateFile")
	if len(keys) == 0 {
		if len(certs) > 0 {
			appendLocalizedImportWarning(spec, "cert_without_key_skipped", alias, i18n.NewMessage(i18n.KeyHostStoreImportWarnCertNoKey))
		}
		return inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	}
	neKeys, err := algebraic.NonEmptyFromSlice(keys)
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthPrivateKey(neKeys, algebraic.None[inventory.KeyPassphraseBinding](), certs)
}

func collectLiteralSpecs[T any](
	spec *inventory.ImportBundleSpec, alias string, pl option.PathList,
	parseFn func(string) (T, error), warnCode, directive string,
) []T {
	if !pl.IsSet() {
		return nil
	}
	var out []T
	for _, raw := range pl.RawItems() {
		v, err := parseFn(raw)
		if err != nil {
			msg := i18n.NewMessage(
				i18n.KeyHostStoreImportWarnDirective,
				i18n.BoundStr("directive", directive),
				i18n.BoundStr("value", raw),
			)
			appendLocalizedImportWarning(spec, warnCode, alias, msg)
			continue
		}
		out = append(out, v)
	}
	return out
}

func appendDerivedOpenSSHEntities(
	spec *inventory.ImportBundleSpec, srcName string, nid inventory.NodeID,
	vh ports.OpenSSHVirtualHost, ep netaddr.Endpoint, user option.Username, auth inventory.AuthMethod,
) error {
	h, id, err := buildImportedHostIdentity(nid, ep, user, auth)
	if err != nil {
		return err
	}
	origin, err := inventory.NewOriginOpenSSHDerived(vh.Alias(), srcName)
	if err != nil {
		return err
	}
	n, err := inventory.NewNode(inventory.NodeSpec{
		ID: nid, HostRef: h.ID(), IdentityRef: id.ID(), Proxy: vh.Proxy(), Options: vh.Layer(), Origin: origin,
	})
	if err != nil {
		return err
	}
	spec.Hosts = append(spec.Hosts, h)
	spec.Identities = append(spec.Identities, id)
	spec.Nodes = append(spec.Nodes, n)
	return nil
}

func appendImportWarning(spec *inventory.ImportBundleSpec, code, subject, msg string) {
	if w, err := inventory.NewImportWarning(code, subject, msg); err == nil {
		spec.Warnings = append(spec.Warnings, w)
	}
}

func appendLocalizedImportWarning(spec *inventory.ImportBundleSpec, code, subject string, msg domi18n.Message) {
	if w, err := inventory.NewLocalizedImportWarning(code, subject, msg); err == nil {
		spec.Warnings = append(spec.Warnings, w)
	}
}
