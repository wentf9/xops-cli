package memtree

import (
	"crypto/sha256"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/ports"
)

// ParseCSVImportBundle 解析整段 CSV 资产文本（跳过空行与 # 注释）并构造不可变 ImportBundle。
func ParseCSVImportBundle(format string, raw []byte) (out inventory.ImportBundle, err error) {
	spec := inventory.ImportBundleSpec{SourceFormat: format}
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			if err = AppendCSVAsset(&spec, line); err != nil {
				return out, err
			}
		}
	}
	if len(spec.Nodes) == 0 {
		return out, ports.ErrCorruptData
	}
	return inventory.NewImportBundle(spec)
}

// ResolveSimTier4 按原始别名与可选规范化端点折叠匹配虚拟主机的 Tier-4 选项层。
func ResolveSimTier4(hosts []ports.OpenSSHVirtualHost, target option.OriginalHostSpec, endpoint algebraic.Option[netaddr.Endpoint]) option.OptionLayer {
	ep, hasReqEP := endpoint.Get()
	acc := option.UnsetOptionLayer()
	for _, h := range hosts {
		if h.Alias() != target.String() {
			continue
		}
		if hEP, hasEP := h.Endpoint().Get(); !hasReqEP || !hasEP || hEP.Equal(ep) {
			acc = acc.Compose(h.Layer())
		}
	}
	return acc
}

// SignSimKey 对仿真密钥指纹、算法与载荷计算确定性 SHA-256 签名（零真实私钥材料）。
func SignSimKey(prefix string, key inventory.KeyFingerprint, algorithm string, data []byte) (ports.Signature, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(prefix + key.String() + ":" + algorithm))
	_, _ = h.Write(data)
	return ports.NewSignature(algorithm, h.Sum(nil))
}

// BuildHostTrustCheck 按 Endpoint 信任列表与吊销表构造确定性 HostTrustCheck 结论。
func BuildHostTrustCheck(req ports.HostTrustRequest, known []ports.PublicKeyInfo, revoked bool) (ports.HostTrustCheck, error) {
	spec := ports.HostTrustCheckSpec{Endpoint: req.Endpoint(), Presented: req.Presented(), Status: ports.HostTrustMismatch, Reason: "fingerprint mismatch"}
	switch {
	case revoked:
		spec.Status, spec.Reason = ports.HostTrustRevoked, "key revoked"
	case len(known) == 0:
		spec.Status, spec.Reason = ports.HostTrustUnknown, "unknown host key"
	default:
		for _, k := range known {
			spec.ExpectedFingerprints = append(spec.ExpectedFingerprints, k.Fingerprint())
			if k.Fingerprint().Equal(spec.Presented.Fingerprint()) {
				spec.Status, spec.Reason = ports.HostTrustTrusted, ""
			}
		}
	}
	return ports.NewHostTrustCheck(spec)
}

// PreferredAlgosFromKeys 从端点已信任公钥切片提取去重且保序的偏好密钥算法列表。
func PreferredAlgosFromKeys(known []ports.PublicKeyInfo) (out []string) {
	for _, k := range known {
		if !slices.Contains(out, k.Algorithm()) {
			out = append(out, k.Algorithm())
		}
	}
	return out
}
