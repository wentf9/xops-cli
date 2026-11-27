package sftpshell

import (
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// ParseLine 将单行交互 SFTP 命令按类 POSIX 引号与反斜杠转义规则切分为参数切片：
// 支持单引号 '...'、双引号 "..."、反斜杠转义及行内 # 注释；未闭合引号或悬空转义严格失败关闭返回 ErrSyntax。
func ParseLine(line string) ([]string, error) {
	var p lineTokenizer
	for _, r := range line {
		if p.step(r) {
			break
		}
	}
	return p.finish()
}

type lineTokenizer struct {
	tokens   []string
	cur      []rune
	inToken  bool
	inSingle bool
	inDouble bool
	escaped  bool
}

func (p *lineTokenizer) step(r rune) bool {
	switch {
	case p.escaped:
		p.cur = append(p.cur, r)
		p.escaped, p.inToken = false, true
		return false
	case p.inSingle:
		p.stepSingleQuote(r)
		return false
	case p.inDouble:
		p.stepDoubleQuote(r)
		return false
	default:
		return p.stepUnquoted(r)
	}
}

func (p *lineTokenizer) stepSingleQuote(r rune) {
	if r == '\'' {
		p.inSingle = false
	} else {
		p.cur = append(p.cur, r)
	}
	p.inToken = true
}

func (p *lineTokenizer) stepDoubleQuote(r rune) {
	switch r {
	case '"':
		p.inDouble = false
	case '\\':
		p.escaped = true
	default:
		p.cur = append(p.cur, r)
	}
	p.inToken = true
}

func (p *lineTokenizer) stepUnquoted(r rune) bool {
	switch {
	case r == '#' && !p.inToken:
		return true
	case unicode.IsSpace(r):
		if p.inToken {
			p.tokens = append(p.tokens, string(p.cur))
			p.cur = p.cur[:0]
			p.inToken = false
		}
	case r == '\'':
		p.inSingle, p.inToken = true, true
	case r == '"':
		p.inDouble, p.inToken = true, true
	case r == '\\':
		p.escaped, p.inToken = true, true
	default:
		p.cur = append(p.cur, r)
		p.inToken = true
	}
	return false
}

func (p *lineTokenizer) finish() ([]string, error) {
	if p.escaped || p.inSingle || p.inDouble {
		return nil, i18n.EF(ErrSyntax, i18n.KeySFTPUnclosedQuote)
	}
	if p.inToken {
		p.tokens = append(p.tokens, string(p.cur))
	}
	return p.tokens, nil
}

// resolveRemotePath 基于当前远端工作目录按 POSIX 语义解析绝对或相对远端路径（全程使用 pathalg.RemotePath）。
func resolveRemotePath(cwd pathalg.RemotePath, raw string) (pathalg.RemotePath, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return zeroVal[pathalg.RemotePath](), i18n.EF(ErrSyntax, i18n.KeySFTPEmptyRemotePath)
	}
	target, err := pathalg.ParseRemotePath(trimmed)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	if target.IsAbs() {
		return target, nil
	}
	return cwd.Resolve(target)
}

// rejectDisallowedLocalInput 在任何路径规范化之前严格拦截禁止的 UNC、设备命名空间、根相对反斜杠、
// 盘符相对路径（如 C:foo）以及混用反斜杠的 POSIX 绝对路径，保持与 core/domain/pathalg 失败关闭语义一致。
func rejectDisallowedLocalInput(raw string) error {
	if strings.HasPrefix(raw, `\`) || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/??/") || raw == "/??" {
		return i18n.EF(ErrSyntax, i18n.KeySFTPDisallowedLocalPrefix, i18n.BoundStr("path", raw))
	}
	if len(raw) >= 2 && isASCIIAlpha(raw[0]) && raw[1] == ':' {
		if len(raw) < 3 || (raw[2] != '/' && raw[2] != '\\') {
			return i18n.EF(ErrSyntax, i18n.KeySFTPDisallowedDriveRel, i18n.BoundStr("path", raw))
		}
	}
	if strings.HasPrefix(raw, "/") && strings.ContainsRune(raw, '\\') {
		return i18n.EF(ErrSyntax, i18n.KeySFTPDisallowedPOSIXBackslash, i18n.BoundStr("path", raw))
	}
	return nil
}

// resolveLocalDir 基于纯 pathalg.LocalDir 代数解析操作员模式下的本机目录切换（支持绝对路径、"."、".." 与多段相对路径），
// 绝不依赖 path/filepath 或 os.Getwd/os.Chdir。
func resolveLocalDir(cwd pathalg.LocalDir, raw string) (pathalg.LocalDir, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return zeroVal[pathalg.LocalDir](), i18n.EF(ErrSyntax, i18n.KeySFTPEmptyLocalPath)
	}
	if err := rejectDisallowedLocalInput(trimmed); err != nil {
		return zeroVal[pathalg.LocalDir](), err
	}
	if isAbsLocalInput(trimmed) {
		return pathalg.ParseLocalDir(trimmed)
	}
	norm := strings.ReplaceAll(trimmed, `\`, "/")
	segs := splitCleanLocalRel(cwd, norm)
	if segs == nil {
		return zeroVal[pathalg.LocalDir](), i18n.EF(ErrSyntax, i18n.KeySFTPLocalRelEscape, i18n.BoundStr("dir", cwd.String()))
	}
	return rebuildLocalDir(cwd, segs)
}

// resolveScopedLocalSegments 在 ScopedLocalOnly 模式下严格将输入解析为位于 sandboxRoot 之内的相对分量切片：
// 拒绝一切绝对路径、非法前缀、非法本地分量及向上穿越 sandboxRoot 的 ".."。
func resolveScopedLocalSegments(curSub []string, raw string) ([]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, i18n.EF(ErrSyntax, i18n.KeySFTPEmptyLocalPath)
	}
	if err := rejectDisallowedLocalInput(trimmed); err != nil {
		return nil, err
	}
	if isAbsLocalInput(trimmed) {
		return nil, i18n.EF(ErrSyntax, i18n.KeySFTPScopedAbsForbidden, i18n.BoundStr("path", raw))
	}
	return walkContainedRelSegments(curSub, strings.ReplaceAll(trimmed, `\`, "/"))
}

func walkContainedRelSegments(baseSub []string, norm string) ([]string, error) {
	segs := slices.Clone(baseSub)
	for part := range strings.SplitSeq(norm, "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(segs) == 0 {
				return nil, i18n.EF(ErrSyntax, i18n.KeySFTPScopedEscape)
			}
			segs = segs[:len(segs)-1]
		default:
			if err := pathalg.ValidateLocalComponent(part); err != nil {
				return nil, i18n.WrapS(ErrSyntax, err, i18n.KeySFTPInvalidLocalComponent, i18n.BoundStr("component", part))
			}
			segs = append(segs, part)
		}
	}
	return segs, nil
}

func joinLocalDirSegments(base pathalg.LocalDir, extra []string) (pathalg.LocalDir, error) {
	segs := append(localDirSegments(base), extra...)
	return rebuildLocalDir(base, segs)
}

func isAbsLocalInput(raw string) bool {
	if strings.HasPrefix(raw, "/") {
		return true
	}
	return len(raw) >= 3 && isASCIIAlpha(raw[0]) && raw[1] == ':' && (raw[2] == '/' || raw[2] == '\\')
}

func isDirInputHint(raw string) bool {
	return raw == "." || raw == "./" || raw == `.\` || strings.HasSuffix(raw, "/") || strings.HasSuffix(raw, `\`)
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func splitCleanLocalRel(cwd pathalg.LocalDir, norm string) []string {
	segs := localDirSegments(cwd)
	for part := range strings.SplitSeq(norm, "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(segs) == 0 {
				if cwd.IsAbs() {
					continue
				}
				return nil
			}
			segs = segs[:len(segs)-1]
		default:
			segs = append(segs, part)
		}
	}
	return segs
}

func localDirSegments(d pathalg.LocalDir) []string {
	s := d.String()
	switch d.Kind() {
	case pathalg.LocalPathPOSIXAbs:
		s = strings.TrimPrefix(s, "/")
	case pathalg.LocalPathWindowsDrive:
		if len(s) >= 3 {
			s = s[3:]
		}
	case pathalg.LocalPathRelative:
		if s == "." {
			return []string{}
		}
	}
	if s == "" {
		return []string{}
	}
	return strings.Split(s, "/")
}

func rebuildLocalDir(base pathalg.LocalDir, segs []string) (pathalg.LocalDir, error) {
	switch base.Kind() {
	case pathalg.LocalPathPOSIXAbs:
		if len(segs) == 0 {
			return pathalg.ParseLocalDir("/")
		}
		return pathalg.ParseLocalDir("/" + strings.Join(segs, "/"))
	case pathalg.LocalPathWindowsDrive:
		drive, _ := base.Drive()
		prefix := string([]byte{drive, ':', '/'})
		if len(segs) == 0 {
			return pathalg.ParseLocalDir(prefix)
		}
		return pathalg.ParseLocalDir(prefix + strings.Join(segs, "/"))
	default:
		if len(segs) == 0 {
			return pathalg.ParseLocalDir(".")
		}
		return pathalg.ParseLocalDir(strings.Join(segs, "/"))
	}
}

// resolveLocalUploadPath 解析操作员模式下 put 命令的本机源文件路径，支持相对当前 localDir 或显式绝对本地路径。
func resolveLocalUploadPath(cwd pathalg.LocalDir, raw string) (pathalg.LocalSourcePath, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return zeroVal[pathalg.LocalSourcePath](), i18n.EF(ErrSyntax, i18n.KeySFTPEmptyLocalPath)
	}
	if err := rejectDisallowedLocalInput(trimmed); err != nil {
		return zeroVal[pathalg.LocalSourcePath](), err
	}
	if isAbsLocalInput(trimmed) {
		return pathalg.ParseLocalSourcePath(trimmed)
	}
	dir, err := resolveLocalDir(cwd, trimmed)
	if err != nil {
		return zeroVal[pathalg.LocalSourcePath](), err
	}
	return pathalg.ParseLocalSourcePath(dir.String())
}

// resolveScopedUploadTarget 解析 ScopedLocalOnly 模式下相对 sandboxRoot 的上传源路径，严禁逃逸或指向空根 "."。
func resolveScopedUploadTarget(sandboxSub []string, raw string) (pathalg.LocalRootedDest, error) {
	segs, err := resolveScopedLocalSegments(sandboxSub, raw)
	if err != nil {
		return zeroVal[pathalg.LocalRootedDest](), err
	}
	if len(segs) == 0 {
		return zeroVal[pathalg.LocalRootedDest](), i18n.EF(ErrSyntax, i18n.KeySFTPScopedUploadRoot)
	}
	return pathalg.LocalRootedDestFromComponents(segs...)
}

// resolveLocalDownloadTarget 解析 get 命令的本地沙箱根与相对落盘目标，支持 "." 与尾斜杠目录写法；
// 当 scopedOnly 为 true 时强制锚定于不可变 sandboxRoot 并禁止任何绝对路径或越界穿越。
func resolveLocalDownloadTarget(
	cwd, sandboxRoot pathalg.LocalDir,
	sandboxSub []string,
	scopedOnly bool,
	remote pathalg.RemotePath,
	localArg string,
) (pathalg.LocalDir, pathalg.LocalRootedDest, error) {
	trimmed := strings.TrimSpace(localArg)
	if scopedOnly {
		return resolveScopedDownloadTarget(sandboxRoot, sandboxSub, remote, trimmed)
	}
	return resolveOperatorDownloadTarget(cwd, remote, trimmed)
}

func resolveScopedDownloadTarget(
	sandboxRoot pathalg.LocalDir,
	sandboxSub []string,
	remote pathalg.RemotePath,
	trimmed string,
) (pathalg.LocalDir, pathalg.LocalRootedDest, error) {
	var segs []string
	appendRemoteBase := trimmed == "" || isDirInputHint(trimmed)
	if trimmed == "" {
		segs = slices.Clone(sandboxSub)
	} else {
		var err error
		if segs, err = resolveScopedLocalSegments(sandboxSub, trimmed); err != nil {
			return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
		}
	}
	if appendRemoteBase {
		base, err := remoteBaseComponent(remote)
		if err != nil {
			return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
		}
		segs = append(segs, base)
	}
	if len(segs) == 0 {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), i18n.EF(ErrSyntax, i18n.KeySFTPInvalidDownloadDest)
	}
	dest, err := pathalg.LocalRootedDestFromComponents(segs...)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	return sandboxRoot, dest, nil
}

func resolveOperatorDownloadTarget(
	cwd pathalg.LocalDir,
	remote pathalg.RemotePath,
	trimmed string,
) (pathalg.LocalDir, pathalg.LocalRootedDest, error) {
	if trimmed == "" {
		return downloadIntoDir(cwd, remote)
	}
	if err := rejectDisallowedLocalInput(trimmed); err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	if isDirInputHint(trimmed) {
		dir, err := resolveLocalDir(cwd, trimmed)
		if err != nil {
			return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
		}
		return downloadIntoDir(dir, remote)
	}
	if isAbsLocalInput(trimmed) {
		return splitAbsLocalFileTarget(trimmed)
	}
	norm := strings.ReplaceAll(trimmed, `\`, "/")
	if segs, err := walkContainedRelSegments(nil, norm); err == nil && len(segs) > 0 {
		dest, dErr := pathalg.LocalRootedDestFromComponents(segs...)
		if dErr != nil {
			return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), dErr
		}
		return cwd, dest, nil
	}
	src, err := resolveLocalUploadPath(cwd, trimmed)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	dest, err := pathalg.ParseLocalRootedDest(src.Base())
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	return src.Dir(), dest, nil
}

func downloadIntoDir(dir pathalg.LocalDir, remote pathalg.RemotePath) (pathalg.LocalDir, pathalg.LocalRootedDest, error) {
	base, err := remoteBaseComponent(remote)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	dest, err := pathalg.ParseLocalRootedDest(base)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	return dir, dest, nil
}

func splitAbsLocalFileTarget(trimmed string) (pathalg.LocalDir, pathalg.LocalRootedDest, error) {
	src, err := pathalg.ParseLocalSourcePath(trimmed)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	dest, err := pathalg.ParseLocalRootedDest(src.Base())
	if err != nil {
		return zeroVal[pathalg.LocalDir](), zeroVal[pathalg.LocalRootedDest](), err
	}
	return src.Dir(), dest, nil
}

func remoteBaseComponent(remote pathalg.RemotePath) (string, error) {
	base, ok := remote.Base()
	if !ok {
		return "", i18n.EF(ErrSyntax, i18n.KeySFTPCannotInferLocalName, i18n.BoundStr("path", remote.String()))
	}
	return base.String(), nil
}

// parseOctalPerm 严格解析 POSIX 权限八进制数字（0o001..0o777，拒绝零值与越界特殊位）。
func parseOctalPerm(raw string) (fs.FileMode, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, i18n.EF(ErrSyntax, i18n.KeySFTPEmptyPerm)
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil || v == 0 || v > 0o777 {
		return 0, i18n.EF(ErrSyntax, i18n.KeySFTPInvalidPerm, i18n.BoundStr("value", raw))
	}
	return fs.FileMode(v), nil
}

// parseTimestamp 解析 RFC3339、本地 ISO 日期时间或 Unix 秒级时间戳并归一化至 UTC。
func parseTimestamp(raw string) (time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, i18n.EF(ErrSyntax, i18n.KeySFTPEmptyTimestamp)
	}
	if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
		return validateTimeRange(time.Unix(sec, 0).UTC(), raw)
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return validateTimeRange(t.UTC(), raw)
		}
	}
	return time.Time{}, i18n.EF(ErrSyntax, i18n.KeySFTPInvalidTimestamp, i18n.BoundStr("value", raw))
}

func validateTimeRange(t time.Time, raw string) (time.Time, error) {
	y := t.UTC().Year()
	if y < 1 || y > 9999 {
		return time.Time{}, i18n.EF(ErrSyntax, i18n.KeySFTPTimestampOutOfRange, i18n.BoundStr("value", raw))
	}
	return t.UTC(), nil
}
