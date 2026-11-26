package store

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/ports"
)

const csvFormatName = "csv"

// CSVImporter 实现 ports.FormatImporter，将规范 CSV 清单流解析为格式无关 inventory.ImportBundle（ADR-006）：
//   - 同时支持带规范表头的 CSV（alias/name, address/host, port, user, key_path, cert_path, proxy_jump, aliases, tags, description）
//     与无表头 4 列紧凑格式（alias,address,port,user）；
//   - 严格拒绝任何明文密码/机密列（password/passwd/passphrase/secret/token/private_key/totp_secret）；
//   - 100% 零 v1 代码、零磁盘访问、零 nolint 抑制指令。
//
//xops:opaque
//xops:failclosed
type CSVImporter struct {
	maxImportBytes int64
	defaultPort    uint16
	valid          bool
}

// NewCSVImporter 校验读取字节上限与默认端口后构造 CSVImporter。
func NewCSVImporter(spec CSVImporterSpec) (*CSVImporter, error) {
	maxBytes, err := normalizeBoundedLimit(spec.MaxImportBytes, defaultMaxImportBytes, maxAllowedImportBytes, "MaxImportBytes")
	if err != nil {
		return nil, err
	}
	defPort := spec.DefaultPort
	if defPort == 0 {
		defPort = netaddr.DefaultSSHPort
	}
	return &CSVImporter{maxImportBytes: maxBytes, defaultPort: defPort, valid: true}, nil
}

// Format 返回规范小写格式标识 "csv"。
func (i *CSVImporter) Format() string { return csvFormatName }

// Import 从有界只读流解析 CSV 资产清单并产出经全量唯一性校验的不可变 inventory.ImportBundle。
func (i *CSVImporter) Import(ctx context.Context, _ string, r io.Reader) (inventory.ImportBundle, error) {
	if err := checkCtxReady(ctx, i != nil && i.valid && r != nil, "CSVImporter 或输入流"); err != nil {
		return zeroVal[inventory.ImportBundle](), err
	}
	raw, err := readBoundedStream(r, i.maxImportBytes)
	if err != nil {
		return zeroVal[inventory.ImportBundle](), err
	}
	return i.parseCSVBytes(ctx, raw)
}

type csvColumnMap struct {
	hasHeader   bool
	alias       int
	address     int
	port        int
	user        int
	keyPath     int
	certPath    int
	proxyJump   int
	aliases     int
	tags        int
	description int
}

func defaultHeaderlessCSVColumns() csvColumnMap {
	return csvColumnMap{
		alias: 0, address: 1, port: 2, user: 3,
		keyPath: -1, certPath: -1, proxyJump: -1, aliases: -1, tags: -1, description: -1,
	}
}

func (i *CSVImporter) parseCSVBytes(ctx context.Context, raw []byte) (inventory.ImportBundle, error) {
	cleaned := bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	cr := csv.NewReader(bytes.NewReader(cleaned))
	cr.Comment = '#'
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true

	rows, err := readNonBlankCSVRows(ctx, cr)
	if err != nil {
		return zeroVal[inventory.ImportBundle](), err
	}
	if len(rows) == 0 {
		return zeroVal[inventory.ImportBundle](), fmt.Errorf("%w: %w: CSV 输入为空", ports.ErrCorruptData, ErrInvalidCSV)
	}
	cols, dataRows, err := resolveCSVColumns(rows)
	if err != nil {
		return zeroVal[inventory.ImportBundle](), err
	}
	if len(dataRows) == 0 {
		return zeroVal[inventory.ImportBundle](), fmt.Errorf("%w: %w: CSV 缺少数据行", ports.ErrCorruptData, ErrInvalidCSV)
	}
	return i.buildBundleFromCSVRows(cols, dataRows)
}

func readNonBlankCSVRows(ctx context.Context, cr *csv.Reader) ([][]string, error) {
	var rows [][]string
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return rows, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w: %w", ports.ErrCorruptData, ErrInvalidCSV, err)
		}
		if isBlankCSVRow(rec) {
			continue
		}
		if len(rows) >= defaultMaxCSVRecords {
			return nil, fmt.Errorf("%w: CSV 行数超过上限 %d", ports.ErrLimitExceeded, defaultMaxCSVRecords)
		}
		rows = append(rows, rec)
	}
}

func isBlankCSVRow(rec []string) bool {
	return !slices.ContainsFunc(rec, func(s string) bool { return strings.TrimSpace(s) != "" })
}

func resolveCSVColumns(rows [][]string) (csvColumnMap, [][]string, error) {
	first := rows[0]
	if isCSVHeaderRow(first) {
		cols, err := parseCSVHeader(first)
		if err != nil {
			return csvColumnMap{}, nil, err
		}
		return cols, rows[1:], nil
	}
	return defaultHeaderlessCSVColumns(), rows, nil
}

func isCSVHeaderRow(row []string) bool {
	if len(row) == 0 {
		return false
	}
	for _, cell := range row {
		if isForbiddenSecretCSVColumn(normalizeCSVHeader(cell)) {
			return true
		}
	}
	first := normalizeCSVHeader(row[0])
	return slices.Contains([]string{"name", "alias", "id", "node", "node_id", "host", "address", "hostname"}, first)
}

func parseCSVHeader(header []string) (csvColumnMap, error) {
	cols := csvColumnMap{
		hasHeader: true,
		alias:     -1, address: -1, port: -1, user: -1,
		keyPath: -1, certPath: -1, proxyJump: -1, aliases: -1, tags: -1, description: -1,
	}
	seen := make(map[string]bool, len(header))
	for idx, raw := range header {
		key := normalizeCSVHeader(raw)
		if isForbiddenSecretCSVColumn(key) {
			return csvColumnMap{}, fmt.Errorf("%w: %w (列 %q)", ports.ErrInvalidArgument, ErrPlaintextSecretForbidden, raw)
		}
		if key == "" || seen[key] {
			return csvColumnMap{}, fmt.Errorf("%w: %w: 表头包含空列或重复列 %q", ports.ErrCorruptData, ErrInvalidCSV, raw)
		}
		seen[key] = true
		if err := assignCSVColumn(&cols, key, idx); err != nil {
			return csvColumnMap{}, err
		}
	}
	if cols.alias < 0 || cols.address < 0 || cols.user < 0 {
		return csvColumnMap{}, fmt.Errorf("%w: %w: CSV 表头必须包含 name/alias、address/host 与 user 列", ports.ErrCorruptData, ErrInvalidCSV)
	}
	return cols, nil
}

func assignCSVColumn(cols *csvColumnMap, key string, idx int) error {
	switch key {
	case "name", "alias", "id", "node", "node_id":
		return setUniqueCol(&cols.alias, idx, key)
	case "host", "address", "hostname":
		return setUniqueCol(&cols.address, idx, key)
	case "port":
		return setUniqueCol(&cols.port, idx, key)
	case "user", "username":
		return setUniqueCol(&cols.user, idx, key)
	case "key_path", "key_paths", "identity_file":
		return setUniqueCol(&cols.keyPath, idx, key)
	case "cert_path", "cert_paths", "certificate_file":
		return setUniqueCol(&cols.certPath, idx, key)
	case "proxy_jump", "jump":
		return setUniqueCol(&cols.proxyJump, idx, key)
	case "aliases":
		return setUniqueCol(&cols.aliases, idx, key)
	case "tags":
		return setUniqueCol(&cols.tags, idx, key)
	case "description", "desc":
		return setUniqueCol(&cols.description, idx, key)
	default:
		return fmt.Errorf("%w: %w: 未知 CSV 列 %q", ports.ErrCorruptData, ErrInvalidCSV, key)
	}
}

func setUniqueCol(slot *int, idx int, key string) error {
	if *slot >= 0 {
		return fmt.Errorf("%w: %w: 语义重复列 %q", ports.ErrCorruptData, ErrInvalidCSV, key)
	}
	*slot = idx
	return nil
}

func normalizeCSVHeader(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func isForbiddenSecretCSVColumn(col string) bool {
	return slices.Contains([]string{
		"password", "passwd", "pass", "passphrase", "secret", "token",
		"private_key", "key_content", "totp_secret", "sudo_password", "privilege_password",
	}, col)
}

func (i *CSVImporter) buildBundleFromCSVRows(cols csvColumnMap, rows [][]string) (inventory.ImportBundle, error) {
	spec := inventory.ImportBundleSpec{
		SourceFormat: csvFormatName,
		Hosts:        make([]inventory.Host, 0, len(rows)),
		Identities:   make([]inventory.Identity, 0, len(rows)),
		Nodes:        make([]inventory.Node, 0, len(rows)),
	}
	for rowIdx, rec := range rows {
		if !cols.hasHeader && len(rec) != 4 {
			return zeroVal[inventory.ImportBundle](), fmt.Errorf("%w: %w: 第 %d 行期望 4 列（alias,address,port,user），实际 %d 列", ports.ErrCorruptData, ErrInvalidCSV, rowIdx+1, len(rec))
		}
		h, id, n, err := i.decodeCSVRow(cols, rec, rowIdx+1)
		if err != nil {
			return zeroVal[inventory.ImportBundle](), err
		}
		spec.Hosts = append(spec.Hosts, h)
		spec.Identities = append(spec.Identities, id)
		spec.Nodes = append(spec.Nodes, n)
	}
	return inventory.NewImportBundle(spec)
}

func (i *CSVImporter) decodeCSVRow(cols csvColumnMap, rec []string, rowNo int) (h inventory.Host, id inventory.Identity, n inventory.Node, err error) {
	nid, err := inventory.ParseNodeID(csvCell(rec, cols.alias))
	if err != nil {
		return h, id, n, fmt.Errorf("%w: 第 %d 行节点名非法: %w", ErrInvalidCSV, rowNo, err)
	}
	ep, err := parseCSVEndpoint(csvCell(rec, cols.address), csvCell(rec, cols.port), i.defaultPort)
	if err != nil {
		return h, id, n, fmt.Errorf("%w: 第 %d 行端点非法: %w", ErrInvalidCSV, rowNo, err)
	}
	user, err := option.ParseUsername(csvCell(rec, cols.user))
	if err != nil {
		return h, id, n, fmt.Errorf("%w: 第 %d 行用户名非法: %w", ErrInvalidCSV, rowNo, err)
	}
	auth, err := parseCSVAuth(csvCell(rec, cols.keyPath), csvCell(rec, cols.certPath))
	if err != nil {
		return h, id, n, fmt.Errorf("%w: 第 %d 行认证配置非法: %w", ErrInvalidCSV, rowNo, err)
	}
	return buildCSVEntities(nid, ep, user, auth, cols, rec, rowNo)
}

func buildCSVEntities(
	nid inventory.NodeID, ep netaddr.Endpoint, user option.Username, auth inventory.AuthMethod,
	cols csvColumnMap, rec []string, rowNo int,
) (h inventory.Host, id inventory.Identity, n inventory.Node, err error) {
	h, id, err = buildImportedHostIdentity(nid, ep, user, auth)
	if err != nil {
		return h, id, n, err
	}
	proxy, err := parseCSVProxy(csvCell(rec, cols.proxyJump))
	if err != nil {
		return h, id, n, fmt.Errorf("%w: 第 %d 行 proxy_jump 非法: %w", ErrInvalidCSV, rowNo, err)
	}
	aliases, err := mapSliceErr(splitCSVMultiVal(csvCell(rec, cols.aliases)), inventory.ParseAlias)
	if err != nil {
		return h, id, n, fmt.Errorf("%w: 第 %d 行 aliases 非法: %w", ErrInvalidCSV, rowNo, err)
	}
	tags, err := mapSliceErr(splitCSVMultiVal(csvCell(rec, cols.tags)), inventory.ParseTag)
	if err != nil {
		return h, id, n, fmt.Errorf("%w: 第 %d 行 tags 非法: %w", ErrInvalidCSV, rowNo, err)
	}
	n, err = inventory.NewNode(inventory.NodeSpec{
		ID: nid, HostRef: h.ID(), IdentityRef: id.ID(), Aliases: aliases, Tags: tags,
		Proxy: proxy, Options: option.UnsetOptionLayer(), Origin: inventory.NewOriginManaged(), Description: csvCell(rec, cols.description),
	})
	return h, id, n, err
}

func buildImportedHostIdentity(nid inventory.NodeID, ep netaddr.Endpoint, user option.Username, auth inventory.AuthMethod) (h inventory.Host, id inventory.Identity, err error) {
	hid, err := inventory.ParseHostID("host-" + nid.String())
	if err != nil {
		return h, id, err
	}
	iid, err := inventory.ParseIdentityID("ident-" + nid.String())
	if err != nil {
		return h, id, err
	}
	if h, err = inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep}); err != nil {
		return h, id, err
	}
	id, err = inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: user, Auth: auth})
	return h, id, err
}

func csvCell(rec []string, idx int) string {
	if idx < 0 || idx >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[idx])
}

func parseCSVEndpoint(rawHost, rawPort string, defPort uint16) (netaddr.Endpoint, error) {
	ch, err := netaddr.ParseCanonicalHost(rawHost)
	if err != nil {
		return zeroVal[netaddr.Endpoint](), err
	}
	port := defPort
	if rawPort != "" {
		v, pErr := strconv.ParseUint(rawPort, 10, 16)
		if pErr != nil || v == 0 {
			return zeroVal[netaddr.Endpoint](), fmt.Errorf("端口 %q 超出 1..65535 范围", rawPort)
		}
		port = uint16(v)
	}
	return netaddr.NewEndpoint(ch, port)
}

func parseCSVAuth(rawKeys, rawCerts string) (inventory.AuthMethod, error) {
	keyStrs, certStrs := splitCSVMultiVal(rawKeys), splitCSVMultiVal(rawCerts)
	if len(keyStrs) == 0 {
		if len(certStrs) > 0 {
			return nil, fmt.Errorf("配置 cert_path 时必须同时提供 key_path")
		}
		return inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	}
	keys, err := mapSliceErr(keyStrs, inventory.ParseKeyPathSpec)
	if err != nil {
		return nil, err
	}
	ne, err := algebraic.NonEmptyFromSlice(keys)
	if err != nil {
		return nil, err
	}
	certs, err := mapSliceErr(certStrs, inventory.ParseCertPathSpec)
	if err != nil {
		return nil, err
	}
	return inventory.NewAuthPrivateKey(ne, algebraic.None[inventory.KeyPassphraseBinding](), certs)
}

func parseCSVProxy(raw string) (option.ProxyRoute, error) {
	if raw == "" {
		return option.NewProxyUnset(), nil
	}
	return option.ParseProxyJump(raw)
}

func splitCSVMultiVal(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for part := range strings.SplitSeq(raw, ";") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}
