package sftpshell

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// hasWildcard 检测路径是否包含未转义的通配符元字符 (* ? [)
// 支持反斜杠转义：\* 视为字面量星号，与 path.Match 语义一致
func hasWildcard(p string) bool {
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			i++ // 跳过被转义的下一个字符
		case '*', '?', '[':
			return true
		}
	}
	return false
}

// expandLocal 在本地文件系统上展开通配符模式
// 无通配符时直接返回 [resolved]，避免无谓 Glob 调用并保持原错误信息
// 展开结果为空时返回 sftp_shell_glob_no_match 错误
func (s *Shell) expandLocal(pattern string) ([]string, error) {
	resolved := s.resolveLocalPath(pattern)
	if !hasWildcard(pattern) {
		return []string{resolved}, nil
	}
	matches, err := filepath.Glob(resolved)
	if err != nil {
		return nil, fmt.Errorf("expand local pattern %q failed: %w", pattern, err)
	}
	if len(matches) == 0 {
		return nil, errors.New(i18n.Tf("sftp_shell_glob_no_match", map[string]any{"Pattern": pattern}))
	}
	return matches, nil
}

// expandRemote 在远程 SFTP 服务器上展开通配符模式
// sftp.Client.Glob 基于绝对路径，相对模式先用 s.resolvePath 解析
// 无通配符时直接返回 [resolved]
// 展开结果为空时返回 sftp_shell_glob_no_match 错误
func (s *Shell) expandRemote(ctx context.Context, pattern string) ([]string, error) {
	resolved := s.resolvePath(pattern)
	if !hasWildcard(pattern) {
		return []string{resolved}, nil
	}
	cli, release, err := s.acquireClient(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	var matches []string
	err = cli.Do(ctx, func(c *pkgsftp.Client) error {
		var globErr error
		matches, globErr = c.Glob(resolved)
		return globErr
	})
	if err != nil {
		// sftp.Glob 仅返回 ErrBadPattern
		return nil, fmt.Errorf("expand remote pattern %q failed: %w", pattern, err)
	}
	if len(matches) == 0 {
		return nil, errors.New(i18n.Tf("sftp_shell_glob_no_match", map[string]any{"Pattern": pattern}))
	}
	return matches, nil
}

// classifyGlobResult 根据"是否期望单个结果"对展开结果进行策略校验
//
//	expectSingle=true  (cd/lcd):  必须恰好 1 个，否则报 sftp_shell_glob_multiple_cd
//	expectSingle=false (ls/cp/rm/get/put): 多个允许
//
// 空切片视为 no-match（防御性，expand* 已保证非空）
func classifyGlobResult(pattern string, matches []string, expectSingle bool) ([]string, error) {
	if len(matches) == 0 {
		return nil, errors.New(i18n.Tf("sftp_shell_glob_no_match", map[string]any{"Pattern": pattern}))
	}
	if expectSingle && len(matches) > 1 {
		return nil, errors.New(i18n.Tf("sftp_shell_glob_multiple_cd",
			map[string]any{"Pattern": pattern, "Count": len(matches)}))
	}
	return matches, nil
}

// resolveMultiSrc 远程多源到单一 dst 的目标路径解析（用 path.Join，SFTP 强制 /）
//
//	单源 + dst 非目录 → [dst]
//	单源 + dst 是目录 → [dst/base(src)]
//	多源 + dst 非目录 → sftp_shell_dest_must_be_dir 错误
//	多源 + dst 是目录 → [dst/base(src) for each src]
func resolveMultiSrc(srcs []string, dst string, dstIsDir bool) ([]string, error) {
	if len(srcs) == 0 {
		return nil, errors.New(i18n.T("sftp_shell_glob_no_match"))
	}
	if len(srcs) == 1 {
		if dstIsDir {
			return []string{path.Join(dst, path.Base(srcs[0]))}, nil
		}
		return []string{dst}, nil
	}
	if !dstIsDir {
		return nil, errors.New(i18n.T("sftp_shell_dest_must_be_dir"))
	}
	out := make([]string, 0, len(srcs))
	for _, src := range srcs {
		out = append(out, path.Join(dst, path.Base(src)))
	}
	return out, nil
}

// resolveMultiSrcLocal 本地变体，使用 filepath.Join
func resolveMultiSrcLocal(srcs []string, dst string, dstIsDir bool) ([]string, error) {
	if len(srcs) == 0 {
		return nil, errors.New(i18n.T("sftp_shell_glob_no_match"))
	}
	if len(srcs) == 1 {
		if dstIsDir {
			return []string{filepath.Join(dst, filepath.Base(srcs[0]))}, nil
		}
		return []string{dst}, nil
	}
	if !dstIsDir {
		return nil, errors.New(i18n.T("sftp_shell_dest_must_be_dir"))
	}
	out := make([]string, 0, len(srcs))
	for _, src := range srcs {
		out = append(out, filepath.Join(dst, filepath.Base(src)))
	}
	return out, nil
}
