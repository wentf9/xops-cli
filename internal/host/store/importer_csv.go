package store

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
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
	if err := checkCtxReady(ctx, i != nil && i.valid, "CSVImporter"); err != nil {
		return zeroVal[inventory.ImportBundle](), err
	}
	if r == nil {
		return zeroVal[inventory.ImportBundle](), i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNilDependency, i18n.Str("field", "r"))
	}
	raw, err := readBoundedStream(r, i.maxImportBytes)
	if err != nil {
		return zeroVal[inventory.ImportBundle](), err
	}
	return i.parseCSVBytes(ctx, raw)
}

type csvColumnMap struct {
	hasHeader   bool
	headerLen   int
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
		return zeroVal[inventory.ImportBundle](), domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrInvalidCSV, i18n.KeyHostStoreCSVEmpty))
	}
	cols, dataRows, err := resolveCSVColumns(rows)
	if err != nil {
		return zeroVal[inventory.ImportBundle](), err
	}
	if len(dataRows) == 0 {
		return zeroVal[inventory.ImportBundle](), domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrInvalidCSV, i18n.KeyHostStoreCSVEmpty))
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
			return nil, domi18n.WrapSentinel(ports.ErrCorruptData, domi18n.WrapSentinel(ErrInvalidCSV, err))
		}
		if isBlankCSVRow(rec) {
			continue
		}
		if len(rows) >= defaultMaxCSVRecords {
			return nil, i18n.EF(ports.ErrLimitExceeded, i18n.KeyHostStoreCSVTooManyRows, i18n.Int("max", defaultMaxCSVRecords))
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

// isCSVHeaderRow 按与列顺序无关的语义特征判定首行是否为表头：
//   - 含任一明文机密列名 -> 判定为表头并交由 parseCSVHeader 失败关闭返回 ErrPlaintextSecretForbidden；
//   - 所有非空列均为已知表头关键字（支持任意列顺序，如 user,name,address,port）-> 判定为表头；
//   - 含 >=2 个已知表头关键字且不符合无表头 4 列数据形态（第 3 列不是合法端口号）-> 判定为表头，
//     防止把名为 "host"/"node" 的无表头 4 列数据行（如 host,192.0.2.1,22,ops）误判为表头。
func isCSVHeaderRow(row []string) bool {
	if len(row) == 0 {
		return false
	}
	knownCount, nonEmptyCount := 0, 0
	for _, cell := range row {
		key := normalizeCSVHeader(cell)
		if isForbiddenSecretCSVColumn(key) {
			return true
		}
		if key == "" {
			continue
		}
		nonEmptyCount++
		if isKnownCSVHeaderColumn(key) {
			knownCount++
		}
	}
	if nonEmptyCount == 0 {
		return false
	}
	if knownCount == nonEmptyCount {
		return true
	}
	if len(row) == 4 && isNumericCSVPort(row[2]) {
		return false
	}
	return knownCount >= 2
}

func isKnownCSVHeaderColumn(key string) bool {
	return slices.Contains([]string{
		"name", "alias", "id", "node", "node_id",
		"host", "address", "hostname", "port", "user", "username",
		"key_path", "key_paths", "identity_file",
		"cert_path", "cert_paths", "certificate_file",
		"proxy_jump", "jump", "aliases", "tags", "description", "desc",
	}, key)
}

func isNumericCSVPort(raw string) bool {
	t := strings.TrimSpace(raw)
	if t == "" || len(t) > 5 {
		return false
	}
	val := 0
	for i := 0; i < len(t); i++ {
		if t[i] < '0' || t[i] > '9' {
			return false
		}
		val = val*10 + int(t[i]-'0')
	}
	return val >= 1 && val <= 65535
}

func parseCSVHeader(header []string) (csvColumnMap, error) {
	cols := csvColumnMap{
		hasHeader: true,
		headerLen: len(header),
		alias:     -1, address: -1, port: -1, user: -1,
		keyPath: -1, certPath: -1, proxyJump: -1, aliases: -1, tags: -1, description: -1,
	}
	seen := make(map[string]bool, len(header))
	for idx, raw := range header {
		key := normalizeCSVHeader(raw)
		if isForbiddenSecretCSVColumn(key) {
			return csvColumnMap{}, domi18n.WrapSentinel(ports.ErrInvalidArgument, i18n.EF(ErrPlaintextSecretForbidden, i18n.KeyHostStoreCSVForbiddenColumn, i18n.BoundStr("column", raw)))
		}
		if key == "" || seen[key] {
			return csvColumnMap{}, domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrInvalidCSV, i18n.KeyHostStoreCSVDupOrEmptyColumn, i18n.BoundStr("column", raw)))
		}
		seen[key] = true
		if err := assignCSVColumn(&cols, key, idx); err != nil {
			return csvColumnMap{}, err
		}
	}
	if cols.alias < 0 || cols.address < 0 || cols.user < 0 {
		return csvColumnMap{}, domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrInvalidCSV, i18n.KeyHostStoreCSVMissingReqColumns))
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
		return domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrInvalidCSV, i18n.KeyHostStoreCSVUnknownColumn, i18n.BoundStr("column", key)))
	}
}

func setUniqueCol(slot *int, idx int, key string) error {
	if *slot >= 0 {
		return domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrInvalidCSV, i18n.KeyHostStoreCSVDupOrEmptyColumn, i18n.BoundStr("column", key)))
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
		if cols.hasHeader && len(rec) != cols.headerLen {
			return zeroVal[inventory.ImportBundle](), domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrInvalidCSV, i18n.KeyHostStoreCSVColumnCountMismatch, i18n.Int("row", rowIdx+1), i18n.Int("got", len(rec)), i18n.Int("want", cols.headerLen)))
		}
		if !cols.hasHeader && len(rec) != 4 {
			return zeroVal[inventory.ImportBundle](), domi18n.WrapSentinel(ports.ErrCorruptData, i18n.EF(ErrInvalidCSV, i18n.KeyHostStoreCSVColumnCountMismatch, i18n.Int("row", rowIdx+1), i18n.Int("got", len(rec)), i18n.Int("want", 4)))
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
		return h, id, n, i18n.WrapS(ErrInvalidCSV, err, i18n.KeyHostStoreCSVRowInvalidField, i18n.Int("row", rowNo), i18n.Str("field", "alias"))
	}
	ep, err := parseCSVEndpoint(csvCell(rec, cols.address), csvCell(rec, cols.port), i.defaultPort)
	if err != nil {
		return h, id, n, i18n.WrapS(ErrInvalidCSV, err, i18n.KeyHostStoreCSVRowInvalidField, i18n.Int("row", rowNo), i18n.Str("field", "endpoint"))
	}
	user, err := option.ParseUsername(csvCell(rec, cols.user))
	if err != nil {
		return h, id, n, i18n.WrapS(ErrInvalidCSV, err, i18n.KeyHostStoreCSVRowInvalidField, i18n.Int("row", rowNo), i18n.Str("field", "user"))
	}
	auth, err := parseCSVAuth(csvCell(rec, cols.keyPath), csvCell(rec, cols.certPath))
	if err != nil {
		return h, id, n, i18n.WrapS(ErrInvalidCSV, err, i18n.KeyHostStoreCSVRowInvalidField, i18n.Int("row", rowNo), i18n.Str("field", "auth"))
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
		return h, id, n, i18n.WrapS(ErrInvalidCSV, err, i18n.KeyHostStoreCSVRowInvalidField, i18n.Int("row", rowNo), i18n.Str("field", "proxy_jump"))
	}
	aliases, err := mapSliceErr(splitCSVMultiVal(csvCell(rec, cols.aliases)), inventory.ParseAlias)
	if err != nil {
		return h, id, n, i18n.WrapS(ErrInvalidCSV, err, i18n.KeyHostStoreCSVRowInvalidField, i18n.Int("row", rowNo), i18n.Str("field", "aliases"))
	}
	tags, err := mapSliceErr(splitCSVMultiVal(csvCell(rec, cols.tags)), inventory.ParseTag)
	if err != nil {
		return h, id, n, i18n.WrapS(ErrInvalidCSV, err, i18n.KeyHostStoreCSVRowInvalidField, i18n.Int("row", rowNo), i18n.Str("field", "tags"))
	}
	n, err = inventory.NewNode(inventory.NodeSpec{
		ID: nid, HostRef: h.ID(), IdentityRef: id.ID(), Aliases: aliases, Tags: tags,
		Proxy: proxy, Options: option.UnsetOptionLayer(), Origin: inventory.NewOriginManaged(), Description: csvCell(rec, cols.description),
	})
	return h, id, n, err
}

func buildImportedHostIdentity(nid inventory.NodeID, ep netaddr.Endpoint, user option.Username, auth inventory.AuthMethod) (h inventory.Host, id inventory.Identity, err error) {
	hid, err := inventory.ParseHostID(deriveScopedEntityID("host-", nid))
	if err != nil {
		return h, id, err
	}
	iid, err := inventory.ParseIdentityID(deriveScopedEntityID("ident-", nid))
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
			return zeroVal[netaddr.Endpoint](), i18n.E(i18n.KeyHostStoreCSVInvalidPort, i18n.BoundStr("port", rawPort))
		}
		port = uint16(v)
	}
	return netaddr.NewEndpoint(ch, port)
}

func parseCSVAuth(rawKeys, rawCerts string) (inventory.AuthMethod, error) {
	keyStrs, certStrs := splitCSVMultiVal(rawKeys), splitCSVMultiVal(rawCerts)
	if len(keyStrs) == 0 {
		if len(certStrs) > 0 {
			return nil, i18n.E(i18n.KeyHostStoreCSVCertRequiresKey)
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
