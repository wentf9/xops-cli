package yamlcodec_test

import (
	"bytes"
	"errors"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/store/yamlcodec"
)

// TestYAMLCodecRoundTripAndFailClosedBoundaries 直接验证 yamlcodec 纯内存子包的
// v2 往返一致性（含路径内空格、algebraic.Duration、KnownStores 并集）与 v1/伪造判别式失败关闭。
func TestYAMLCodecRoundTripAndFailClosedBoundaries(t *testing.T) {
	defer goleak.VerifyNone(t)

	rawYAML := []byte(`version: 2
vault:
  default_store: extra
  stores:
    extra:
      kind: offline_aead
inventory:
  known_stores:
    - primary
  hosts:
    h1:
      address: 192.0.2.10
      port: 2222
  identities:
    i1:
      user: ops
      auth:
        kind: agent
  nodes:
    n1:
      host: h1
      identity: i1
      options:
        connect_timeout: 15s
        user_known_hosts_files:
          state: set
          items:
            - "C:/Users/Alice Smith/.ssh/known_hosts"
`)
	doc, g, err := yamlcodec.DecodeConfigDocumentYAML(rawYAML)
	if err != nil {
		t.Fatalf("DecodeConfigDocumentYAML 失败: %v", err)
	}
	if !g.IsValid() || len(g.Nodes()) != 1 {
		t.Fatalf("解码后的 InventoryGraph 异常: valid=%v nodes=%d", g.IsValid(), len(g.Nodes()))
	}
	invDTO, err := yamlcodec.EncodeInventoryGraphDTO(g)
	if err != nil {
		t.Fatalf("EncodeInventoryGraphDTO 失败: %v", err)
	}
	doc.Inventory = invDTO
	encoded, err := yamlcodec.EncodeConfigDocumentYAML(doc)
	if err != nil {
		t.Fatalf("EncodeConfigDocumentYAML 失败: %v", err)
	}
	doc2, g2, err := yamlcodec.DecodeConfigDocumentYAML(encoded)
	if err != nil {
		t.Fatalf("往返 DecodeConfigDocumentYAML 失败: %v", err)
	}
	invDTO2, err := yamlcodec.EncodeInventoryGraphDTO(g2)
	if err != nil {
		t.Fatalf("二次 EncodeInventoryGraphDTO 失败: %v", err)
	}
	doc2.Inventory = invDTO2
	encoded2, err := yamlcodec.EncodeConfigDocumentYAML(doc2)
	if err != nil {
		t.Fatalf("二次 EncodeConfigDocumentYAML 失败: %v", err)
	}
	if !bytes.Equal(encoded, encoded2) {
		t.Fatalf("YAML v2 规范编解码不幂等:\nfirst:\n%s\nsecond:\n%s", string(encoded), string(encoded2))
	}

	// 验证零 v1 兼容：version: 1 必须明确返回 ErrUnsupportedSchemaVersion。
	if _, _, err := yamlcodec.DecodeConfigDocumentYAML([]byte("version: 1\ninventory: {}\n")); !errors.Is(err, yamlcodec.ErrUnsupportedSchemaVersion) {
		t.Fatalf("version: 1 返回 %v, 期望 ErrUnsupportedSchemaVersion", err)
	}
	// 验证伪造算法算子判别式返回 ports.ErrCorruptData。
	badAlgo := []byte("version: 2\ninventory:\n  hosts:\n    h1: { address: 192.0.2.1 }\n  identities:\n    i1: { user: ops, auth: { kind: agent } }\n  nodes:\n    n1:\n      host: h1\n      identity: i1\n      options:\n        ciphers: { op: exact, tokens: ['^aes256-gcm@openssh.com'] }\n")
	if _, _, err := yamlcodec.DecodeConfigDocumentYAML(badAlgo); !errors.Is(err, ports.ErrCorruptData) {
		t.Fatalf("伪造 algo exact 判别式返回 %v, 期望 ErrCorruptData", err)
	}
}
