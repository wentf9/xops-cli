package openssh

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/ports"
)

// StreamDiagnostic 描述纯内存流式解析 OpenSSH 配置时产生的非致命结构化告警
// （例如因无磁盘访问而跳过的 Include，或按安全策略失败关闭忽略的 Match exec / canonical）。
type StreamDiagnostic struct {
	Code    string
	Line    int
	Subject string
	Message string
}

// ParsedStreamResult 封装对单份内存 OpenSSH 配置流执行纯只读解析后的全部虚拟主机视图与诊断告警。
type ParsedStreamResult struct {
	Hosts       []ports.OpenSSHVirtualHost
	Diagnostics []StreamDiagnostic
}

// ParseConfigStream 在 100% 零磁盘 I/O 与零 Include 文件展开的前提下，使用与 ConfigSource 完全同源的
// 词法解析器、Match 校验器及单一 t4 自上而下 ApplyParsedOption 折叠器解析单份 OpenSSH 配置字节流，
// 供上层 FormatImporter（如 internal/host/store）复用，严禁双份解析器漂移。
func ParseConfigStream(sourceName string, raw []byte, localID algebraic.Option[ports.LocalIdentityInfo]) (ParsedStreamResult, error) {
	name := strings.TrimSpace(sourceName)
	if name == "" {
		name = "ssh_config"
	}
	if id, ok := localID.Get(); ok && !id.IsValid() {
		return ParsedStreamResult{}, fmt.Errorf("%w: LocalIdentity 无效", ports.ErrInvalidArgument)
	}
	doc, diags, err := parseStreamBytes(name, raw)
	if err != nil {
		return ParsedStreamResult{}, err
	}
	aliases := collectConcreteAliases(doc)
	if len(aliases) == 0 {
		return ParsedStreamResult{Diagnostics: diags}, nil
	}
	localUser := ""
	if id, ok := localID.Get(); ok {
		localUser = id.LocalUser()
	}
	hosts := make([]ports.OpenSSHVirtualHost, 0, len(aliases))
	for _, cand := range aliases {
		layer, evalErr := evaluateParsedDocument(doc, cand.origHost, algebraic.None[netaddr.Endpoint](), localUser)
		if evalErr != nil {
			return ParsedStreamResult{}, evalErr
		}
		vh, buildErr := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
			Alias:      cand.alias,
			SourceFile: cand.sourceFile,
			Endpoint:   deriveVirtualHostEndpoint(cand.origHost, layer),
			User:       layer.User(),
			Proxy:      layer.Proxy(),
			Layer:      layer,
		})
		if buildErr != nil {
			return ParsedStreamResult{}, buildErr
		}
		hosts = append(hosts, vh)
	}
	return ParsedStreamResult{Hosts: hosts, Diagnostics: diags}, nil
}

func evaluateParsedDocument(doc *parsedFile, target option.OriginalHostSpec, endpoint algebraic.Option[netaddr.Endpoint], localUser string) (option.OptionLayer, error) {
	ec := &evalContext{
		target:    target,
		endpoint:  endpoint,
		localUser: localUser,
		layer:     option.UnsetOptionLayer(),
	}
	if err := ec.evalFile(doc, true, false, false); err != nil {
		return option.UnsetOptionLayer(), err
	}
	if doc != nil && doc.hasFinal {
		if err := ec.evalFile(doc, true, true, false); err != nil {
			return option.UnsetOptionLayer(), err
		}
	}
	return ec.layer, nil
}

func parseStreamBytes(sourceName string, raw []byte) (*parsedFile, []StreamDiagnostic, error) {
	doc := &parsedFile{path: sourceName}
	var diags []StreamDiagnostic
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 4096), int(min(int64(len(raw))+1024, 1<<20)))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		stmt, ok, lineDiag, err := parseStreamLine(sourceName, lineNo, sc.Text())
		if err != nil {
			return nil, nil, err
		}
		if lineDiag.Code != "" {
			diags = append(diags, lineDiag)
		}
		if ok {
			doc.stmts = append(doc.stmts, stmt)
			if stmt.matchFinal {
				doc.hasFinal = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("%w: 读取 %s 失败: %w", ErrInvalidConfig, sourceName, err)
	}
	return doc, diags, nil
}

func parseStreamLine(sourceName string, lineNo int, rawLine string) (configStmt, bool, StreamDiagnostic, error) {
	trimmed := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
	if trimmed == "" || trimmed[0] == '#' {
		return configStmt{}, false, StreamDiagnostic{}, nil
	}
	key, val, err := splitConfigKeywordValue(trimmed)
	if err != nil {
		return configStmt{}, false, StreamDiagnostic{}, fmt.Errorf("%w: %s:%d: %w", ErrInvalidConfig, sourceName, lineNo, err)
	}
	switch strings.ToLower(key) {
	case "host":
		stmt, ok, pErr := parseHostStmt(sourceName, lineNo, key, val)
		return stmt, ok, StreamDiagnostic{}, pErr
	case "match":
		stmt, ok, pErr := parseMatchStmt(sourceName, lineNo, key, val)
		if pErr != nil {
			return configStmt{}, false, StreamDiagnostic{}, pErr
		}
		return stmt, ok, matchStreamDiagnostic(stmt), nil
	case "include":
		return parseStreamInclude(sourceName, lineNo, key, val)
	default:
		stmt, ok, pErr := parseDirectiveStmt(sourceName, lineNo, key, val)
		return stmt, ok, StreamDiagnostic{}, pErr
	}
}

func parseStreamInclude(sourceName string, lineNo int, key, val string) (configStmt, bool, StreamDiagnostic, error) {
	pats, err := splitConfigTokens(val)
	if err != nil || len(pats) == 0 {
		return configStmt{}, false, StreamDiagnostic{}, fmt.Errorf("%w: %s:%d: Include 路径非法", ErrInvalidConfig, sourceName, lineNo)
	}
	diag := StreamDiagnostic{
		Code:    "include_skipped",
		Line:    lineNo,
		Subject: pats[0],
		Message: fmt.Sprintf("第 %d 行 Include %q 在纯流式导入中未展开本地文件", lineNo, strings.Join(pats, " ")),
	}
	return configStmt{kind: stmtInclude, file: sourceName, line: lineNo, key: key, rawVal: val, patterns: pats}, true, diag, nil
}

func matchStreamDiagnostic(stmt configStmt) StreamDiagnostic {
	if stmt.matchCanonical {
		return StreamDiagnostic{
			Code:    "match_canonical_ignored",
			Line:    stmt.line,
			Subject: "canonical",
			Message: fmt.Sprintf("第 %d 行 Match canonical 块按安全策略失败关闭未生效", stmt.line),
		}
	}
	for _, tok := range stmt.patterns {
		kw, _, _, _ := parseMatchKeyword(tok)
		if kw == "exec" {
			return StreamDiagnostic{
				Code:    "match_exec_ignored",
				Line:    stmt.line,
				Subject: "exec",
				Message: fmt.Sprintf("第 %d 行 Match exec 块按安全策略失败关闭且永不执行外部命令", stmt.line),
			}
		}
	}
	return StreamDiagnostic{}
}
