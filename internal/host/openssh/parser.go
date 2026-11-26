package openssh

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

type stmtKind uint8

const (
	stmtDirective stmtKind = iota + 1
	stmtHost
	stmtMatch
	stmtInclude
)

type configStmt struct {
	kind           stmtKind
	file           string
	line           int
	key            string
	rawVal         string
	parsed         option.ParsedOption
	hasParsed      bool
	patterns       []string
	included       []*parsedFile
	matchFinal     bool
	matchCanonical bool
}

type parsedFile struct {
	path     string
	stmts    []configStmt
	hasFinal bool
}

type loadState struct {
	source    *ConfigSource
	ancestors map[string]bool
	fileCount int
}

func (s *ConfigSource) loadRootDocument(ctx context.Context) (*parsedFile, bool, error) {
	st := &loadState{source: s, ancestors: make(map[string]bool)}
	doc, exists, err := st.loadFile(ctx, s.configPath, 0)
	return doc, exists, err
}

func (st *loadState) loadFile(ctx context.Context, filePath pathalg.LocalSourcePath, depth int) (*parsedFile, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if depth > st.source.maxIncludeDepth {
		return nil, false, fmt.Errorf("%w: %s (depth=%d)", ErrIncludeDepthExceeded, filePath.String(), depth)
	}
	canon := filePath.String()
	if st.ancestors[canon] {
		return nil, false, fmt.Errorf("%w: %s", ErrIncludeCycle, canon)
	}
	st.fileCount++
	if st.fileCount > st.source.maxIncludedFiles {
		return nil, false, fmt.Errorf("%w: Include 加载文件数超过上限 %d", ports.ErrLimitExceeded, st.source.maxIncludedFiles)
	}
	raw, exists, err := st.readFileBounded(ctx, filePath)
	if err != nil || !exists {
		return nil, exists, err
	}
	st.ancestors[canon] = true
	defer delete(st.ancestors, canon)
	return st.parseFileBytes(ctx, canon, raw, depth)
}

func (st *loadState) readFileBounded(ctx context.Context, filePath pathalg.LocalSourcePath) ([]byte, bool, error) {
	var data []byte
	err := st.source.reader.WithOperatorRead(ctx, filePath, st.source.symlinkPolicy, func(r ports.BoundedReadHandle, size int64) error {
		if size > st.source.maxFileBytes {
			return fmt.Errorf("%w: %s 大小 %d 超过上限 %d", ports.ErrLimitExceeded, filePath.String(), size, st.source.maxFileBytes)
		}
		buf, rErr := io.ReadAll(io.LimitReader(r, st.source.maxFileBytes+1))
		if rErr != nil {
			return rErr
		}
		if int64(len(buf)) > st.source.maxFileBytes {
			return fmt.Errorf("%w: %s 读取超出上限 %d", ports.ErrLimitExceeded, filePath.String(), st.source.maxFileBytes)
		}
		data = buf
		return nil
	})
	if errors.Is(err, ports.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (st *loadState) parseFileBytes(ctx context.Context, filePath string, raw []byte, depth int) (*parsedFile, bool, error) {
	doc := &parsedFile{path: filePath}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 4096), int(min(st.source.maxFileBytes+1, 1<<20)))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		stmt, ok, err := st.parseLine(ctx, filePath, lineNo, sc.Text(), depth)
		if err != nil {
			return nil, false, err
		}
		if ok {
			doc.stmts = append(doc.stmts, stmt)
			if stmt.matchFinal || anyIncludedHasFinal(stmt.included) {
				doc.hasFinal = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, false, fmt.Errorf("%w: 读取 %s 失败: %w", ErrInvalidConfig, filePath, err)
	}
	return doc, true, nil
}

func (st *loadState) parseLine(ctx context.Context, filePath string, lineNo int, rawLine string, depth int) (configStmt, bool, error) {
	trimmed := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
	if trimmed == "" || trimmed[0] == '#' {
		return configStmt{}, false, nil
	}
	key, val, err := splitConfigKeywordValue(trimmed)
	if err != nil {
		return configStmt{}, false, fmt.Errorf("%w: %s:%d: %w", ErrInvalidConfig, filePath, lineNo, err)
	}
	switch strings.ToLower(key) {
	case "host":
		return parseHostStmt(filePath, lineNo, key, val)
	case "match":
		return parseMatchStmt(filePath, lineNo, key, val)
	case "include":
		return st.parseIncludeStmt(ctx, filePath, lineNo, key, val, depth)
	default:
		return parseDirectiveStmt(filePath, lineNo, key, val)
	}
}

func parseHostStmt(filePath string, lineNo int, key, val string) (configStmt, bool, error) {
	pats, pErr := splitConfigTokens(val)
	if pErr != nil || len(pats) == 0 {
		return configStmt{}, false, fmt.Errorf("%w: %s:%d: host 模式列表非法", ErrInvalidConfig, filePath, lineNo)
	}
	return configStmt{kind: stmtHost, file: filePath, line: lineNo, key: key, rawVal: val, patterns: pats}, true, nil
}

func parseMatchStmt(filePath string, lineNo int, key, val string) (configStmt, bool, error) {
	toks, mErr := splitConfigTokens(val)
	if mErr != nil || len(toks) == 0 {
		return configStmt{}, false, fmt.Errorf("%w: %s:%d: match 条件非法", ErrInvalidConfig, filePath, lineNo)
	}
	isFinal, isCanonical, vErr := validateMatchTokens(toks)
	if vErr != nil {
		return configStmt{}, false, fmt.Errorf("%w: %s:%d: %w", ErrInvalidConfig, filePath, lineNo, vErr)
	}
	return configStmt{
		kind: stmtMatch, file: filePath, line: lineNo, key: key, rawVal: val,
		patterns: toks, matchFinal: isFinal, matchCanonical: isCanonical,
	}, true, nil
}

func parseDirectiveStmt(filePath string, lineNo int, key, val string) (configStmt, bool, error) {
	cleanedVal := val
	if !isWholeLineCommandKey(key) {
		cleanedVal = stripUnquotedInlineComment(val)
	}
	if cleanedVal == "" {
		return configStmt{}, false, fmt.Errorf("%w: %s:%d: 指令 %s 缺少参数值", ErrInvalidConfig, filePath, lineNo, key)
	}
	stmt := configStmt{kind: stmtDirective, file: filePath, line: lineNo, key: key, rawVal: cleanedVal}
	// 与真实 ssh -G 对齐：凡已注册核心选项均在解析期立即执行语法与值域校验（即便位于未命中的 Host/Match 块内），
	// 防止非法 Port / StrictHostKeyChecking / IdentityFile 在未命中块或无具体别名流中被静默忽略。
	if _, known := option.CanonicalOptionKey(key); known {
		parsed, err := option.ParseOptionKV(key, cleanedVal)
		if err != nil {
			return configStmt{}, false, fmt.Errorf("%w: %s:%d: %w", ErrInvalidConfig, filePath, lineNo, err)
		}
		stmt.parsed = parsed
		stmt.hasParsed = true
	}
	return stmt, true, nil
}

func anyIncludedHasFinal(files []*parsedFile) bool {
	for _, f := range files {
		if f != nil && f.hasFinal {
			return true
		}
	}
	return false
}

func isWholeLineCommandKey(key string) bool {
	canon, ok := option.CanonicalOptionKey(key)
	if !ok {
		return false
	}
	spec, ok := option.LookupOptionSpec(canon)
	return ok && spec.WholeLineCommand
}

// stripUnquotedInlineComment 按 ssh_config(5) 剥离空白词元边界处的未加引号行内 # 注释，
// 同时完整保留引号内的 # 与词元内部的 #（如 User alice#bob）。
func stripUnquotedInlineComment(val string) string {
	var inQuote byte
	prevSpace := true
	for i := 0; i < len(val); i++ {
		if inQuote != 0 {
			i, inQuote = advanceInsideQuote(val, i, inQuote)
			prevSpace = false
			continue
		}
		c := val[i]
		if c == '#' && prevSpace {
			return strings.TrimSpace(val[:i])
		}
		if c == '"' || c == '\'' {
			inQuote, prevSpace = c, false
			continue
		}
		prevSpace = c == ' ' || c == '\t'
	}
	return strings.TrimSpace(val)
}

func advanceInsideQuote(val string, i int, quote byte) (int, byte) {
	if quote == '"' && val[i] == '\\' && i+1 < len(val) {
		return i + 1, quote
	}
	if val[i] == quote {
		return i, 0
	}
	return i, quote
}

func (st *loadState) parseIncludeStmt(ctx context.Context, filePath string, lineNo int, key, val string, depth int) (configStmt, bool, error) {
	patterns, err := splitConfigTokens(val)
	if err != nil || len(patterns) == 0 {
		return configStmt{}, false, fmt.Errorf("%w: %s:%d: Include 路径非法", ErrInvalidConfig, filePath, lineNo)
	}
	stmt := configStmt{kind: stmtInclude, file: filePath, line: lineNo, key: key, rawVal: val, patterns: patterns}
	for _, pat := range patterns {
		targets, rErr := st.resolveIncludePattern(pat)
		if rErr != nil {
			return configStmt{}, false, fmt.Errorf("%w: %s:%d: %w", ErrInvalidConfig, filePath, lineNo, rErr)
		}
		for _, target := range targets {
			child, exists, lErr := st.loadFile(ctx, target, depth+1)
			if lErr != nil {
				return configStmt{}, false, lErr
			}
			if exists {
				stmt.included = append(stmt.included, child)
			}
		}
	}
	return stmt, true, nil
}

func splitConfigKeywordValue(line string) (key, val string, err error) {
	i := strings.IndexFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == '=' })
	if i <= 0 {
		return "", "", fmt.Errorf("缺少参数值 %q", line)
	}
	key = line[:i]
	rest := strings.TrimLeft(line[i:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	val = strings.TrimSpace(rest)
	if val == "" {
		return "", "", fmt.Errorf("指令 %s 缺少参数值", key)
	}
	return key, val, nil
}

func splitConfigTokens(raw string) ([]string, error) {
	var out []string
	for i := 0; i < len(raw); {
		if raw[i] == ' ' || raw[i] == '\t' {
			i++
			continue
		}
		// 空白词元边界处的未加引号 # 开启行内注释，后续内容全部忽略（不污染 Host/Match/Include 词元）。
		if raw[i] == '#' {
			break
		}
		tok, next, err := readConfigToken(raw, i)
		if err != nil {
			return nil, err
		}
		out, i = append(out, tok), next
	}
	return out, nil
}

func readConfigToken(raw string, start int) (string, int, error) {
	var b strings.Builder
	for i := start; i < len(raw); {
		if raw[i] == ' ' || raw[i] == '\t' {
			return b.String(), i, nil
		}
		if raw[i] == '"' || raw[i] == '\'' {
			seg, next, err := scanConfigQuote(raw, i)
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
	return b.String(), len(raw), nil
}

func scanConfigQuote(raw string, start int) (string, int, error) {
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
	return "", 0, fmt.Errorf("未闭合引号")
}
