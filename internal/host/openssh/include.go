package openssh

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// resolveIncludePattern 将单条 Include 模式展开为有序且去重的只读配置文件路径列表；
// 含通配符时严格经 ports.ScopedRootFS 安全枚举，ScopedFS 为 nil 时失败关闭。
func (st *loadState) resolveIncludePattern(rawPat string) ([]pathalg.LocalSourcePath, error) {
	expanded, err := st.expandIncludePath(rawPat)
	if err != nil {
		return nil, err
	}
	if !hasIncludeGlobMeta(expanded) {
		p, pErr := pathalg.ParseLocalSourcePath(expanded)
		if pErr != nil {
			return nil, pErr
		}
		return []pathalg.LocalSourcePath{p}, nil
	}
	return st.expandIncludeGlob(expanded)
}

func (st *loadState) expandIncludePath(rawPat string) (string, error) {
	norm := strings.ReplaceAll(rawPat, "\\", "/")
	if rest, ok := strings.CutPrefix(norm, "~/"); ok {
		if st.source.homeDir == "" {
			return "", fmt.Errorf("展开 include 路径 %q 需要有效 HomeDir", rawPat)
		}
		return joinSlashPath(strings.ReplaceAll(st.source.homeDir, "\\", "/"), rest), nil
	}
	if isAbsoluteSlashPath(norm) {
		return norm, nil
	}
	return joinSlashPath(st.source.includeBaseDir.String(), norm), nil
}

func (st *loadState) expandIncludeGlob(pattern string) ([]pathalg.LocalSourcePath, error) {
	if st.source.scopedFS == nil {
		return nil, fmt.Errorf("%w: 通配符 Include %q 需要提供 ScopedFS", ports.ErrInvalidArgument, pattern)
	}
	baseDir, globSegs, err := splitStaticBaseAndGlob(pattern)
	if err != nil {
		return nil, err
	}
	var matched []pathalg.LocalSourcePath
	err = st.source.scopedFS.WithRoot(baseDir, func(root ports.RootHandle) error {
		return walkGlobSegments(root, baseDir, algebraic.None[pathalg.LocalRootedDest](), globSegs, &matched)
	})
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	slices.SortFunc(matched, pathalg.LocalSourcePath.Compare)
	return slices.CompactFunc(matched, pathalg.LocalSourcePath.Equal), nil
}

func splitStaticBaseAndGlob(pattern string) (pathalg.LocalDir, []string, error) {
	prefix, segs := splitRootPrefixAndSegments(pattern)
	if slices.Contains(segs, "..") {
		return zeroVal[pathalg.LocalDir](), nil, fmt.Errorf("通配符 include 路径 %q 禁止包含 '..' 路径段", pattern)
	}
	firstGlob := slices.IndexFunc(segs, hasIncludeGlobMeta)
	if firstGlob < 0 {
		return zeroVal[pathalg.LocalDir](), nil, fmt.Errorf("内部错误：路径 %q 不含通配符", pattern)
	}
	for _, seg := range segs[firstGlob:] {
		if err := validateIncludeGlobSegment(seg); err != nil {
			return zeroVal[pathalg.LocalDir](), nil, err
		}
	}
	baseRaw := prefix + strings.Join(segs[:firstGlob], "/")
	if baseRaw == "" {
		baseRaw = "."
	}
	baseDir, err := pathalg.ParseLocalDir(baseRaw)
	if err != nil {
		return zeroVal[pathalg.LocalDir](), nil, err
	}
	return baseDir, segs[firstGlob:], nil
}

func splitRootPrefixAndSegments(p string) (string, []string) {
	var prefix, rest string
	switch {
	case len(p) >= 3 && isASCIIAlpha(p[0]) && p[1] == ':' && p[2] == '/':
		prefix, rest = p[:3], p[3:]
	case strings.HasPrefix(p, "/"):
		prefix, rest = "/", p[1:]
	default:
		prefix, rest = "", p
	}
	var segs []string
	for seg := range strings.SplitSeq(rest, "/") {
		if seg != "" && seg != "." {
			segs = append(segs, seg)
		}
	}
	return prefix, segs
}

func walkGlobSegments(root ports.RootHandle, baseDir pathalg.LocalDir, relDir algebraic.Option[pathalg.LocalRootedDest], segs []string, out *[]pathalg.LocalSourcePath) error {
	if len(segs) == 0 {
		return nil
	}
	entries, err := root.ReadDir(relDir)
	if errors.Is(err, ports.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return matchDirEntriesForGlob(root, baseDir, relDir, entries, segs, out)
}

func matchDirEntriesForGlob(root ports.RootHandle, baseDir pathalg.LocalDir, relDir algebraic.Option[pathalg.LocalRootedDest], entries []ports.LocalDirEntry, segs []string, out *[]pathalg.LocalSourcePath) error {
	for _, entry := range entries {
		if err := matchSingleGlobEntry(root, baseDir, relDir, entry, segs, out); err != nil {
			return err
		}
	}
	return nil
}

func matchSingleGlobEntry(root ports.RootHandle, baseDir pathalg.LocalDir, relDir algebraic.Option[pathalg.LocalRootedDest], entry ports.LocalDirEntry, segs []string, out *[]pathalg.LocalSourcePath) error {
	name, pat, rest := entry.Name(), segs[0], segs[1:]
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(pat, ".") {
		return nil
	}
	matched, err := matchIncludeGlobSegment(name, pat)
	if err != nil {
		return err
	}
	if !matched {
		return nil
	}
	nextRel, err := joinRelDest(relDir, name)
	if err != nil {
		return nil
	}
	if len(rest) == 0 {
		if !entry.IsDir() {
			appendMatchedSourcePath(baseDir, nextRel, out)
		}
		return nil
	}
	if !entry.IsDir() {
		return nil
	}
	return walkGlobSegments(root, baseDir, algebraic.Some(nextRel), rest, out)
}

func appendMatchedSourcePath(baseDir pathalg.LocalDir, rel pathalg.LocalRootedDest, out *[]pathalg.LocalSourcePath) {
	if srcPath, err := pathalg.ParseLocalSourcePath(joinSlashPath(baseDir.String(), rel.String())); err == nil {
		*out = append(*out, srcPath)
	}
}

func joinRelDest(parent algebraic.Option[pathalg.LocalRootedDest], name string) (pathalg.LocalRootedDest, error) {
	if p, ok := parent.Get(); ok {
		return p.JoinComponent(name)
	}
	return pathalg.ParseLocalRootedDest(name)
}

func hasGlobMeta(s string) bool        { return strings.ContainsAny(s, "*?") }
func hasIncludeGlobMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

// validateIncludeGlobSegment 校验单段 POSIX Include 通配符（*、? 与 [...] / [!...] 字符类），
// 严格拒绝未闭合 '[' 或空/倒置字符范围（如 [z-a]）。
func validateIncludeGlobSegment(pat string) error {
	for i := 0; i < len(pat); i++ {
		if pat[i] != '[' {
			continue
		}
		_, next, err := scanGlobCharClass(pat, i, 0, false)
		if err != nil {
			return err
		}
		i = next - 1
	}
	return nil
}

// matchIncludeGlobSegment 以 O(|P|*|S|) 非回溯双指针实现 POSIX glob(3) 单路径段匹配
// （支持 '*'、'?' 及 '[...]' / '[!...]' 字符类，供 OpenSSH Include 使用）。
func matchIncludeGlobSegment(name, pat string) (bool, error) {
	ti, pi, starPi, starTi := 0, 0, -1, 0
	for ti < len(name) {
		if pi < len(pat) && pat[pi] == '*' {
			starPi, starTi, pi = pi, ti, pi+1
			continue
		}
		ok, nextPi, err := matchIncludeGlobAtom(name[ti], pat, pi)
		if err != nil {
			return false, err
		}
		if ok {
			ti, pi = ti+1, nextPi
			continue
		}
		if starPi >= 0 {
			starTi++
			ti, pi = starTi, starPi+1
			continue
		}
		return false, nil
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat), nil
}

func matchIncludeGlobAtom(ch byte, pat string, pi int) (bool, int, error) {
	if pi >= len(pat) {
		return false, pi, nil
	}
	if pat[pi] == '?' {
		return true, pi + 1, nil
	}
	if pat[pi] == '[' {
		return scanGlobCharClass(pat, pi, ch, true)
	}
	return pat[pi] == ch, pi + 1, nil
}

func scanGlobCharClass(pat string, start int, target byte, eval bool) (bool, int, error) {
	i := start + 1
	if i >= len(pat) {
		return false, i, fmt.Errorf("通配符 %q 存在未闭合 '['", pat)
	}
	// 严格遵循 POSIX glob(3) 与 OpenSSH readconf.c 语义：仅 '[!...]' 取反，前导 '^' 按字面字符匹配。
	negated := pat[i] == '!'
	if negated {
		i++
	}
	matched, count := false, 0
	for i < len(pat) {
		if pat[i] == ']' && count > 0 {
			return eval && (matched != negated), i + 1, nil
		}
		hit, next, err := scanGlobClassItem(pat, i, target, eval)
		if err != nil {
			return false, next, err
		}
		matched = matched || hit
		i, count = next, count+1
	}
	return false, i, fmt.Errorf("通配符 %q 存在未闭合 '['", pat)
}

func scanGlobClassItem(pat string, i int, target byte, eval bool) (bool, int, error) {
	lo := pat[i]
	if i+2 < len(pat) && pat[i+1] == '-' && pat[i+2] != ']' {
		hi := pat[i+2]
		if lo > hi {
			return false, i, fmt.Errorf("通配符 %q 存在非法字符范围 [%c-%c]", pat, lo, hi)
		}
		return eval && target >= lo && target <= hi, i + 3, nil
	}
	return eval && target == lo, i + 1, nil
}

func isAbsoluteSlashPath(p string) bool {
	return strings.HasPrefix(p, "/") || (len(p) >= 3 && isASCIIAlpha(p[0]) && p[1] == ':' && p[2] == '/')
}

func isASCIIAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func joinSlashPath(base, rel string) string {
	switch {
	case base == "" || base == ".":
		return rel
	case strings.HasSuffix(base, "/"):
		return base + rel
	default:
		return base + "/" + rel
	}
}
