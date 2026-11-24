package pathalg

import (
	"encoding"
	"fmt"
	"slices"
	"strings"
)

var (
	_ encoding.TextAppender    = SymlinkPolicy(0)
	_ encoding.TextMarshaler   = SymlinkPolicy(0)
	_ encoding.TextUnmarshaler = (*SymlinkPolicy)(nil)
)

// SymlinkPolicy 定义 XOps v2 在本地文件读取（OperatorReadFS）与下载落盘（TransferService）中的软链接处置策略。
//
// 零值 SymlinkReject 严格为最严失败关闭策略（等同 O_NOFOLLOW，拒绝一切符号链接）：
//   - SymlinkReject：无条件拒绝所有符号链接；
//   - SymlinkContainedRelative：RFC 软链下载策略 (b)，仅允许解析后每一步深度均严格留在沙箱根目录内
//     （depth >= 0）、全分量满足 ValidateLocalComponent 且无跨 OS Unicode/大小写折叠碰撞的相对 POSIX 软链；
//   - SymlinkFollowOperatorSource：仅用于 OperatorReadFS 读取人工显式指定的只读源文件（如软链私钥），
//     绝不允许用于 ScopedRootFS 写路径或下载落盘。
//
//xops:opaque
//xops:failclosed
type SymlinkPolicy uint8

const (
	// SymlinkReject 是失败关闭零值策略：无条件拒绝任何符号链接（等同 O_NOFOLLOW）。
	SymlinkReject SymlinkPolicy = iota
	// SymlinkContainedRelative 是 RFC 策略 (b)：仅保留解析后严格留在根目录内的相对 POSIX 符号链接。
	SymlinkContainedRelative
	// SymlinkFollowOperatorSource 仅允许 OperatorReadFS 跟随人工显式指定的只读源文件软链接。
	SymlinkFollowOperatorSource
)

// ParseSymlinkPolicy 解析规范化软链接策略文本；空串或未知值一律失败关闭返回 SymlinkReject 与错误。
func ParseSymlinkPolicy(raw string) (SymlinkPolicy, error) {
	switch raw {
	case "reject":
		return SymlinkReject, nil
	case "contained_relative":
		return SymlinkContainedRelative, nil
	case "follow_operator_source":
		return SymlinkFollowOperatorSource, nil
	default:
		return SymlinkReject, fmt.Errorf("%w: 未知软链接策略 %q", ErrInvalidSymlinkPolicy, raw)
	}
}

// IsValid 报告 SymlinkPolicy 是否为已登记的合法策略枚举值。
func (p SymlinkPolicy) IsValid() bool {
	return p == SymlinkReject || p == SymlinkContainedRelative || p == SymlinkFollowOperatorSource
}

// AllowsContainedRelative 报告策略是否允许按 RFC 策略 (b) 保留/跟随根目录内受限相对软链接。
func (p SymlinkPolicy) AllowsContainedRelative() bool {
	return p == SymlinkContainedRelative
}

// AllowsOperatorFollow 报告策略是否允许 OperatorReadFS 跟随人工显式指定的只读源文件软链接。
func (p SymlinkPolicy) AllowsOperatorFollow() bool {
	return p == SymlinkFollowOperatorSource
}

// String 返回策略的规范文本表示；未识别枚举值返回 "invalid"。
func (p SymlinkPolicy) String() string {
	switch p {
	case SymlinkReject:
		return "reject"
	case SymlinkContainedRelative:
		return "contained_relative"
	case SymlinkFollowOperatorSource:
		return "follow_operator_source"
	default:
		return "invalid"
	}
}

// AppendText 实现 encoding.TextAppender（值接收者）；对非法枚举值失败关闭返回 ErrInvalidSymlinkPolicy。
func (p SymlinkPolicy) AppendText(b []byte) ([]byte, error) {
	if !p.IsValid() {
		return nil, ErrInvalidSymlinkPolicy
	}
	return append(b, p.String()...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (p SymlinkPolicy) MarshalText() ([]byte, error) { return p.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为最严零值 SymlinkReject 并返回错误。
func (p *SymlinkPolicy) UnmarshalText(text []byte) error {
	if p == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseSymlinkPolicy(string(text))
	if err != nil {
		*p = SymlinkReject
		return err
	}
	*p = parsed
	return nil
}

// ValidateSymlinkTarget 按指定 SymlinkPolicy 对单条符号链接目标执行纯数学准入校验。
//
// 行为契约：
//   - SymlinkReject 与任意无效枚举值：一律失败关闭返回错误；
//   - SymlinkContainedRelative：强制执行 RFC 策略 (b) 词法与深度不越界校验；
//   - SymlinkFollowOperatorSource：仅允许合法且不含控制/Bidi 字符的非空目标文本（不用于沙箱下载创建）。
func ValidateSymlinkTarget(policy SymlinkPolicy, target string, linkDirDepth int) error {
	switch policy {
	case SymlinkReject:
		return fmt.Errorf("%w: 当前策略 reject 禁止任何符号链接", ErrUnsafeSymlink)
	case SymlinkContainedRelative:
		return ValidateContainedSymlink(target, linkDirDepth)
	case SymlinkFollowOperatorSource:
		if target == "" || len(target) > MaxLocalPathBytes || hasForbiddenPathText(target) {
			return fmt.Errorf("%w: 操作员源软链接目标 %q 语法非法或含控制/Bidi 字符", ErrUnsafeSymlink, target)
		}
		return nil
	default:
		return fmt.Errorf("%w: 未知软链接策略 %d", ErrInvalidSymlinkPolicy, policy)
	}
}

// ValidateContainedSymlink 执行 RFC 软链下载策略 (b) 单跳词法与深度不越界校验。
//
// 仅允许满足以下全部条件的相对 POSIX 符号链接目标：
//   - 非空、长度 <= MaxRemotePathBytes、有效 UTF-8、无 NUL/控制/Bidi-Cf 字符；
//   - 相对 POSIX 路径：不以 '/' 开头、不含 '\'、不含 ':'（阻断 Windows 盘符与 NTFS ADS）；
//   - 除 "." 与 ".." 外，每一分量均通过 ValidateLocalComponent 校验；
//   - 从 linkDirDepth（>= 0，表示符号链接所在父目录相对根目录的深度）出发，
//     逐段解析过程中任意中间步深度均严格保持 >= 0（绝不允许先逃出根再折返）。
func ValidateContainedSymlink(target string, linkDirDepth int) error {
	if linkDirDepth < 0 {
		return fmt.Errorf("%w: 非法目录深度 %d", ErrUnsafeSymlink, linkDirDepth)
	}
	if err := validateContainedSymlinkSyntax(target); err != nil {
		return err
	}
	depth := linkDirDepth
	for seg := range strings.SplitSeq(target, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			depth--
			if depth < 0 {
				return fmt.Errorf("%w: 软链目标 %q 在解析过程中逃逸沙箱根目录", ErrUnsafeSymlink, target)
			}
		default:
			depth++
		}
	}
	return nil
}

func validateContainedSymlinkSyntax(target string) error {
	if target == "" {
		return fmt.Errorf("%w: 软链目标不能为空", ErrUnsafeSymlink)
	}
	if len(target) > MaxRemotePathBytes {
		return fmt.Errorf("%w: 软链目标长度 %d 超过上限 %d", ErrUnsafeSymlink, len(target), MaxRemotePathBytes)
	}
	if hasForbiddenPathText(target) {
		return fmt.Errorf("%w: 软链目标 %q 包含非法 UTF-8、控制或 Bidi/Cf 字符", ErrUnsafeSymlink, target)
	}
	if strings.HasPrefix(target, "/") || strings.ContainsAny(target, `\:`) {
		return fmt.Errorf("%w: 软链目标 %q 必须为不含反斜杠与冒号的相对 POSIX 路径", ErrUnsafeSymlink, target)
	}
	for seg := range strings.SplitSeq(target, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		if err := ValidateLocalComponent(seg); err != nil {
			return fmt.Errorf("%w: 软链目标 %q 含不安全分量: %w", ErrUnsafeSymlink, target, err)
		}
	}
	return nil
}

// SymlinkBinding 表示待下载树中已登记的一条沙箱内符号链接（位置 + 原始目标文本）。
//
//xops:opaque
//xops:failclosed
type SymlinkBinding struct {
	link   LocalRootedDest
	target string
}

// NewSymlinkBinding 构造经基础语法校验的沙箱符号链接绑定条目。
func NewSymlinkBinding(link LocalRootedDest, target string) (SymlinkBinding, error) {
	if !link.IsValid() {
		return SymlinkBinding{}, fmt.Errorf("%w: 软链位置无效", ErrUnsafeSymlink)
	}
	if target == "" || len(target) > MaxRemotePathBytes || hasForbiddenPathText(target) {
		return SymlinkBinding{}, fmt.Errorf("%w: 软链目标 %q 语法非法", ErrUnsafeSymlink, target)
	}
	return SymlinkBinding{link: link, target: target}, nil
}

// IsValid 报告 SymlinkBinding 是否有效。
func (b SymlinkBinding) IsValid() bool { return b.link.IsValid() && b.target != "" }

// Link 返回符号链接在沙箱根目录内的相对路径。
func (b SymlinkBinding) Link() LocalRootedDest { return b.link }

// Target 返回符号链接指向的目标文本。
func (b SymlinkBinding) Target() string { return b.target }

type foldedSymlinkIndex struct {
	exact  map[string]string
	folded map[string]foldedSymlinkRecord
}

type foldedSymlinkRecord struct {
	exactRel string
	target   string
}

// ValidateContainedSymlinkSet 在纯内存中对完整符号链接集合执行置换不变的策略 (b) 全图校验。
//
// 软链包含性属于整图全局不变量，与输入到达顺序无关，本函数强制校验：
//  1. 集合内所有软链均有效，且不存在任何精确重复或跨 OS Unicode/大小写折叠碰撞；
//  2. 集合内每条软链的所有祖先目录分量均不得命中集合内任何软链（精确或折叠匹配）；
//  3. 从集合内每条软链父目录出发，在完整全图索引上逐段展开所有命中的树内软链（含自环、增量互环与
//     逆序链式逃逸），受 MaxSymlinkHops（40 跳）与 MaxSymlinkSteps（4096 步）约束且任意中间步深度恒 >= 0。
func ValidateContainedSymlinkSet(bindings []SymlinkBinding) error {
	ordered := slices.Clone(bindings)
	slices.SortFunc(ordered, func(a, b SymlinkBinding) int { return a.link.Compare(b.link) })
	idx, err := buildFoldedSymlinkIndex(ordered)
	if err != nil {
		return err
	}
	for _, entry := range ordered {
		if err := validateBindingInGraph(idx, entry); err != nil {
			return err
		}
	}
	return nil
}

// ValidateContainedSymlinkChain 校验将 (link -> target) 加入 staged 后构成的完整软链图是否满足策略 (b)。
//
// 本函数将 (link, target) 与 staged 合并为完整图 G' 后委托 ValidateContainedSymlinkSet 执行全图校验，
// 严格阻断自环、增量互环、逆序链式逃逸、逆序祖先软链接管与重复路径覆写。
func ValidateContainedSymlinkChain(link LocalRootedDest, target string, staged []SymlinkBinding) error {
	added, err := NewSymlinkBinding(link, target)
	if err != nil {
		return err
	}
	combined := make([]SymlinkBinding, 0, len(staged)+1)
	combined = append(combined, staged...)
	combined = append(combined, added)
	return ValidateContainedSymlinkSet(combined)
}

func validateBindingInGraph(idx *foldedSymlinkIndex, entry SymlinkBinding) error {
	linkParts := entry.link.Segments()
	parentParts := linkParts[:len(linkParts)-1]
	if err := ValidateContainedSymlink(entry.target, len(parentParts)); err != nil {
		return err
	}
	if err := checkSymlinkParents(idx, parentParts); err != nil {
		return err
	}
	return walkContainedSymlinkChain(idx, entry.target, parentParts, splitRelPOSIXSegments(entry.target))
}

func buildFoldedSymlinkIndex(ordered []SymlinkBinding) (*foldedSymlinkIndex, error) {
	idx := &foldedSymlinkIndex{
		exact:  make(map[string]string, len(ordered)),
		folded: make(map[string]foldedSymlinkRecord, len(ordered)),
	}
	for _, entry := range ordered {
		if !entry.IsValid() {
			return nil, fmt.Errorf("%w: 软链集合包含无效 SymlinkBinding", ErrUnsafeSymlink)
		}
		rel := entry.link.rel
		folded, err := foldSlashPath(rel)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnsafeSymlink, err)
		}
		if prev, dup := idx.folded[folded]; dup {
			if prev.exactRel == rel {
				return nil, fmt.Errorf("%w: %w: 重复符号链接路径 %q", ErrUnsafeSymlink, ErrNameCollision, rel)
			}
			return nil, fmt.Errorf("%w: %w: 软链 %q 与 %q 折叠碰撞", ErrUnsafeSymlink, ErrNameCollision, prev.exactRel, rel)
		}
		idx.exact[rel] = entry.target
		idx.folded[folded] = foldedSymlinkRecord{exactRel: rel, target: entry.target}
	}
	return idx, nil
}

func checkSymlinkParents(idx *foldedSymlinkIndex, parentParts []string) error {
	for i := range parentParts {
		prefix := strings.Join(parentParts[:i+1], "/")
		if _, found, err := lookupFoldedSymlink(idx, prefix); err != nil {
			return err
		} else if found {
			return fmt.Errorf("%w: 祖先目录分量 %q 命中已有符号链接", ErrUnsafeSymlink, prefix)
		}
	}
	return nil
}

func lookupFoldedSymlink(idx *foldedSymlinkIndex, rel string) (string, bool, error) {
	if target, ok := idx.exact[rel]; ok {
		return target, true, nil
	}
	folded, err := foldSlashPath(rel)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", ErrUnsafeSymlink, err)
	}
	if rec, ok := idx.folded[folded]; ok {
		return rec.target, true, nil
	}
	return "", false, nil
}

func walkContainedSymlinkChain(idx *foldedSymlinkIndex, origTarget string, startDir, initialQueue []string) error {
	cur := slices.Clone(startDir)
	queue := slices.Clone(initialQueue)
	hops, steps := 0, 0
	for len(queue) > 0 {
		steps++
		if steps > MaxSymlinkSteps {
			return fmt.Errorf("%w: 软链 %q 超过最大解析步数上限 (%d)", ErrUnsafeSymlink, origTarget, MaxSymlinkSteps)
		}
		var err error
		cur, queue, hops, err = stepContainedSymlink(idx, origTarget, cur, queue, hops)
		if err != nil {
			return err
		}
	}
	return nil
}

func stepContainedSymlink(idx *foldedSymlinkIndex, origTarget string, cur, queue []string, hops int) ([]string, []string, int, error) {
	seg := queue[0]
	queue = queue[1:]
	if seg == ".." {
		if len(cur) == 0 {
			return nil, nil, hops, fmt.Errorf("%w: 软链 %q 经链式展开后逃逸沙箱根目录", ErrUnsafeSymlink, origTarget)
		}
		return cur[:len(cur)-1], queue, hops, nil
	}
	candRel := strings.Join(append(slices.Clip(cur), seg), "/")
	symTarget, found, err := lookupFoldedSymlink(idx, candRel)
	if err != nil {
		return nil, nil, hops, err
	}
	if !found {
		return append(cur, seg), queue, hops, nil
	}
	hops++
	if hops > MaxSymlinkHops {
		return nil, nil, hops, fmt.Errorf("%w: 软链 %q 超过最大展开跳数上限 (%d)（疑似环路）", ErrUnsafeSymlink, origTarget, MaxSymlinkHops)
	}
	if err := ValidateContainedSymlink(symTarget, len(cur)); err != nil {
		return nil, nil, hops, err
	}
	return cur, append(splitRelPOSIXSegments(symTarget), queue...), hops, nil
}

func splitRelPOSIXSegments(target string) []string {
	var out []string
	for seg := range strings.SplitSeq(target, "/") {
		if seg == "" || seg == "." {
			continue
		}
		out = append(out, seg)
	}
	return out
}
