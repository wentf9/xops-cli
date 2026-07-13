package sftp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/peterh/liner"
	"github.com/schollz/progressbar/v3"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"golang.org/x/term"
)

// Shell 定义交互式 SFTP 环境
type Shell struct {
	client      *Client
	cwd         string
	localCwd    string
	line        *liner.State
	historyFile string // 用于退出时保存历史
	stdout      io.Writer
	stderr      io.Writer
}

// NewShell 创建一个新的交互式 Shell
func (c *Client) NewShell(stdin io.Reader, stdout, stderr io.Writer) (*Shell, error) {
	cwd, err := c.sftpClient.Getwd()
	if err != nil {
		cwd = "."
	}
	localCwd, err := os.Getwd()
	if err != nil {
		localCwd = "."
	}

	// 初始化 liner
	line := liner.NewLiner()
	line.SetCtrlCAborts(true) // 允许 Ctrl+C 中断提示

	// 读取历史记录
	homeDir, _ := os.UserHomeDir()
	historyFile := ""
	if homeDir != "" {
		historyFile = filepath.Join(homeDir, ".xops_sftp_history")
		if f, err := os.Open(historyFile); err == nil {
			_, _ = line.ReadHistory(f)
			_ = f.Close()
		}
	}

	shell := &Shell{
		client:      c,
		cwd:         cwd,
		localCwd:    localCwd,
		line:        line,
		historyFile: historyFile,
		stdout:      stdout,
		stderr:      stderr,
	}

	// 绑定自动补全：TabPrints 模式 — 第一次 Tab 补全公共前缀，第二次 Tab 列出所有候选（bash 行为）
	line.SetTabCompletionStyle(liner.TabPrints)
	line.SetWordCompleter(shell.wordCompleter)

	return shell, nil
}

// Run 启动交互式循环 (REPL)
func (s *Shell) Run(ctx context.Context) error {
	defer func() {
		// 退出时保存历史记录
		if s.historyFile != "" {
			if f, err := os.Create(s.historyFile); err == nil {
				_, _ = s.line.WriteHistory(f)
				_ = f.Close()
			}
		}
		_ = s.line.Close()
	}()

	for {
		prompt := fmt.Sprintf("sftp:%s> ", s.cwd)
		input, err := s.line.Prompt(prompt)
		if err != nil {
			if errors.Is(err, liner.ErrPromptAborted) {
				continue // 对应 Ctrl+C 拦截
			}
			return nil // EOF 对应 Ctrl+D 或其他错误退出
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		s.line.AppendHistory(input) // 动态加入历史

		// ! 前缀：本地执行快捷方式（如 `!ls` 或 `! ls -la`）
		if strings.HasPrefix(input, "!") {
			localCmd := strings.TrimSpace(input[1:])
			if localCmd != "" {
				s.handleLexec(ctx, localCmd)
			}
			continue
		}

		args := strings.Fields(input)
		cmd := args[0]
		params := args[1:]

		exit, err := s.dispatchCommand(ctx, cmd, params)
		if exit {
			return err
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (s *Shell) dispatchCommand(ctx context.Context, cmd string, params []string) (bool, error) {
	switch cmd {
	case "exit", "quit", "bye":
		return true, nil
	case "help", "?":
		s.printHelp()
	case "pwd", "lpwd":
		s.handlePwd(cmd)
	case "ls", "ll", "lls", "lll":
		s.handleLsGroup(cmd, params)
	case "cd", "lcd":
		s.handleCdGroup(cmd, params)
	case "mkdir", "lmkdir":
		s.handleMkdirGroup(cmd, params)
	case "rm", "lrm":
		s.handleRmGroup(cmd, params)
	default:
		s.dispatchTransferCmd(ctx, cmd, params)
	}
	return false, nil
}

func (s *Shell) dispatchTransferCmd(ctx context.Context, cmd string, params []string) {
	switch cmd {
	case "cp", "lcp":
		s.handleCpGroup(cmd, params)
	case "mv", "lmv":
		s.handleMvGroup(cmd, params)
	case "shell":
		s.handleShell(ctx)
	case "lshell":
		s.handleLshell(ctx)
	case "exec":
		s.handleExec(ctx, params)
	case "lexec":
		s.handleLexec(ctx, strings.Join(params, " "))
	case "get":
		s.handleGet(ctx, params)
	case "put":
		s.handlePut(ctx, params)
	default:
		_, _ = fmt.Fprintf(s.stderr, "%s\n", i18n.Tf("sftp_shell_unknown_cmd", map[string]any{"Cmd": cmd}))
	}
}

func (s *Shell) handlePwd(cmd string) {
	if cmd == "pwd" {
		_, _ = fmt.Fprintln(s.stdout, s.cwd)
	} else {
		_, _ = fmt.Fprintln(s.stdout, s.localCwd)
	}
}

func (s *Shell) handleLsGroup(cmd string, params []string) {
	switch cmd {
	case "ls":
		s.handleLs(params, false)
	case "ll":
		s.handleLs(params, true)
	case "lls":
		s.handleLocalLs(params, false)
	case "lll":
		s.handleLocalLs(params, true)
	}
}

func (s *Shell) handleCdGroup(cmd string, params []string) {
	if cmd == "cd" {
		s.handleCd(params)
	} else {
		s.handleLocalCd(params)
	}
}

func (s *Shell) handleMkdirGroup(cmd string, params []string) {
	if cmd == "mkdir" {
		s.handleMkdir(params)
	} else {
		s.handleLocalMkdir(params)
	}
}

func (s *Shell) handleRmGroup(cmd string, params []string) {
	if cmd == "rm" {
		s.handleRm(params)
	} else {
		s.handleLocalRm(params)
	}
}

func (s *Shell) handleCpGroup(cmd string, params []string) {
	if cmd == "cp" {
		s.handleCp(params)
	} else {
		s.handleLocalCp(params)
	}
}

func (s *Shell) handleMvGroup(cmd string, params []string) {
	if cmd == "mv" {
		s.handleMv(params)
	} else {
		s.handleLocalMv(params)
	}
}

// ================= 命令处理逻辑 =================

func (s *Shell) resolvePath(p string) string {
	// SFTP 协议强制使用 / 作为路径分隔符
	// 使用 strings.HasPrefix 判断绝对路径，而非 filepath.IsAbs
	// 因为 filepath.IsAbs 依赖本地操作系统规则（Windows 会认为 /home 是相对路径）
	if strings.HasPrefix(p, "/") {
		return p
	}
	return s.client.JoinPath(s.cwd, p)
}

func (s *Shell) resolveLocalPath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.localCwd, p)
}

func (s *Shell) handleCd(args []string) {
	if len(args) == 0 {
		return
	}
	var target string
	if hasWildcard(args[0]) {
		matches, err := s.expandRemote(args[0])
		if err != nil {
			_, _ = fmt.Fprintf(s.stderr, "cd: %v\n", err)
			return
		}
		single, err := classifyGlobResult(args[0], matches, true)
		if err != nil {
			_, _ = fmt.Fprintf(s.stderr, "cd: %v\n", err)
			return
		}
		target = single[0]
	} else {
		target = s.resolvePath(args[0])
	}

	// 检查目录是否存在
	info, err := s.client.sftpClient.Stat(target)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "cd: %v\n", err)
		return
	}
	if !info.IsDir() {
		_, _ = fmt.Fprintf(s.stderr, "%s\n", i18n.Tf("sftp_shell_cd_not_dir", map[string]any{"Path": args[0]}))
		return
	}
	s.cwd = target
}

func (s *Shell) handleLocalCd(args []string) {
	if len(args) == 0 {
		return
	}
	var target string
	if hasWildcard(args[0]) {
		matches, err := s.expandLocal(args[0])
		if err != nil {
			_, _ = fmt.Fprintf(s.stderr, "lcd: %v\n", err)
			return
		}
		single, err := classifyGlobResult(args[0], matches, true)
		if err != nil {
			_, _ = fmt.Fprintf(s.stderr, "lcd: %v\n", err)
			return
		}
		target = single[0]
	} else {
		target = s.resolveLocalPath(args[0])
	}
	if err := os.Chdir(target); err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lcd: %v\n", err)
		return
	}
	// 更新本地当前目录
	s.localCwd, _ = os.Getwd()
}

func (s *Shell) handleLs(args []string, long bool) {
	if len(args) > 0 && hasWildcard(args[0]) {
		matches, err := s.expandRemote(args[0])
		if err != nil {
			_, _ = fmt.Fprintf(s.stderr, "ls: %v\n", err)
			return
		}
		multi := len(matches) > 1
		for _, m := range matches {
			if multi {
				_, _ = fmt.Fprintf(s.stdout, "\n%s:\n", m)
			}
			s.listRemoteOne(m, long)
		}
		return
	}
	path := s.cwd
	if len(args) > 0 {
		path = s.resolvePath(args[0])
	}
	s.listRemoteOne(path, long)
}

// listRemoteOne 列出单个远程路径的内容
// path 为文件时直接显示该文件信息，为目录时列出其内容（与 bash ls 行为一致）
func (s *Shell) listRemoteOne(path string, long bool) {
	info, err := s.client.sftpClient.Stat(path)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "ls: %v\n", err)
		return
	}
	var files []os.FileInfo
	if info.IsDir() {
		files, err = s.client.sftpClient.ReadDir(path)
		if err != nil {
			_, _ = fmt.Fprintf(s.stderr, "ls: %v\n", err)
			return
		}
	} else {
		// path 是文件，直接显示该文件自身
		files = []os.FileInfo{info}
	}

	if long {
		// 详细列表模式 (类似 ls -l)
		w := tabwriter.NewWriter(s.stdout, 0, 0, 1, ' ', 0)
		for _, f := range files {
			modTime := f.ModTime().Format("Jan 02 15:04")
			size := formatBytes(f.Size())
			name := f.Name()
			if f.IsDir() {
				name += "/"
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Mode(), size, modTime, name)
		}
		_ = w.Flush()
	} else {
		// 简单列表模式 (多列输出)
		names := make([]string, 0, len(files))
		for _, f := range files {
			name := f.Name()
			if f.IsDir() {
				name += "/"
			}
			names = append(names, name)
		}
		s.printColumns(names)
	}
}

func (s *Shell) handleLocalLs(args []string, long bool) {
	if len(args) > 0 && hasWildcard(args[0]) {
		matches, err := s.expandLocal(args[0])
		if err != nil {
			_, _ = fmt.Fprintf(s.stderr, "lls: %v\n", err)
			return
		}
		multi := len(matches) > 1
		for _, m := range matches {
			if multi {
				_, _ = fmt.Fprintf(s.stdout, "\n%s:\n", m)
			}
			s.listLocalOne(m, long)
		}
		return
	}
	path := s.localCwd
	if len(args) > 0 {
		path = s.resolveLocalPath(args[0])
	}
	s.listLocalOne(path, long)
}

// listLocalOne 列出单个本地路径的内容
// path 为文件时直接显示该文件信息，为目录时列出其内容（与 bash ls 行为一致）
func (s *Shell) listLocalOne(path string, long bool) {
	info, err := os.Stat(path)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lls: %v\n", err)
		return
	}
	var infos []os.FileInfo
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			_, _ = fmt.Fprintf(s.stderr, "lls: %v\n", err)
			return
		}
		for _, e := range entries {
			ei, err := e.Info()
			if err != nil {
				continue
			}
			infos = append(infos, ei)
		}
	} else {
		// path 是文件，直接显示该文件自身
		infos = []os.FileInfo{info}
	}

	if long {
		// 详细列表模式
		w := tabwriter.NewWriter(s.stdout, 0, 0, 1, ' ', 0)
		for _, fi := range infos {
			modTime := fi.ModTime().Format("Jan 02 15:04")
			size := formatBytes(fi.Size())
			name := fi.Name()
			if fi.IsDir() {
				name += string(filepath.Separator)
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", fi.Mode(), size, modTime, name)
		}
		_ = w.Flush()
	} else {
		// 简单列表模式 (多列输出)
		names := make([]string, 0, len(infos))
		for _, fi := range infos {
			name := fi.Name()
			if fi.IsDir() {
				name += string(filepath.Separator)
			}
			names = append(names, name)
		}
		s.printColumns(names)
	}
}

func (s *Shell) handleGet(ctx context.Context, args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_get_usage"))
		return
	}
	remotes, err := s.expandRemote(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "get: %v\n", err)
		return
	}

	// 多源时：本地 dst 必须是已存在的目录或省略
	if len(remotes) > 1 {
		var localDir string
		if len(args) > 1 {
			localDir = s.resolveLocalPath(args[1])
			info, statErr := os.Stat(localDir)
			if statErr != nil || !info.IsDir() {
				_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_dest_must_be_dir"))
				return
			}
		} else {
			localDir = s.localCwd
		}
		for _, remote := range remotes {
			localTarget := filepath.Join(localDir, filepath.Base(remote))
			s.getSingle(ctx, remote, localTarget)
		}
		return
	}

	// 单源：保持原行为
	remote := remotes[0]
	local := filepath.Base(remote)
	if len(args) > 1 {
		local = s.resolveLocalPath(args[1])
	}
	s.getSingle(ctx, remote, local)
}

// getSingle 下载单个远程文件/目录到本地，含覆盖确认与进度条
func (s *Shell) getSingle(ctx context.Context, remote, local string) {
	// 检查目标文件是否已存在
	if lStat, err := os.Stat(local); err == nil {
		localDest := local
		if lStat.IsDir() {
			localDest = filepath.Join(local, filepath.Base(remote))
		}
		if _, err := os.Stat(localDest); err == nil {
			if s.client.config.NoOverwrite {
				return
			}
			if !s.client.config.Force {
				if !s.askConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": localDest})) {
					return
				}
				origForce := s.client.config.Force
				s.client.SetForce(true)
				defer s.client.SetForce(origForce)
			}
		}
	}

	_, _ = fmt.Fprintln(s.stdout, i18n.Tf("sftp_shell_downloading", map[string]any{"Remote": remote, "Local": local}))

	// 计算远程文件/目录总大小以显示准确的进度条
	info, statErr := s.client.sftpClient.Stat(remote)
	var totalSize int64
	description := "Downloading"
	if statErr == nil {
		if info.IsDir() {
			description = "Downloading (Dir)"
			walker := s.client.sftpClient.Walk(remote)
			for walker.Step() {
				if walker.Err() != nil {
					continue
				}
				if fi := walker.Stat(); !fi.IsDir() {
					totalSize += fi.Size()
				}
			}
		} else {
			totalSize = info.Size()
		}
	}

	bar := progressbar.NewOptions64(
		totalSize,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(s.stdout),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionOnCompletion(func() {
			_, _ = fmt.Fprint(s.stdout, "\n")
		}),
	)
	callback := func(n int64) { _ = bar.Add64(n) }

	err := s.client.Download(ctx, remote, local, callback)
	_ = bar.Finish()
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "%s\n", i18n.Tf("sftp_shell_download_failed", map[string]any{"Error": err}))
	} else {
		_, _ = fmt.Fprintln(s.stdout, i18n.T("sftp_shell_download_done"))
	}
}

func (s *Shell) handlePut(ctx context.Context, args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_put_usage"))
		return
	}
	locals, err := s.expandLocal(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "put: %v\n", err)
		return
	}

	// 检查本地文件/目录是否存在（expandLocal 已展开，但单源无通配符时短路返回原路径，
	// 此处保留 os.Stat 检查以维持原错误信息）
	if _, err := os.Stat(locals[0]); err != nil {
		errMsg := i18n.Tf("sftp_shell_upload_failed", map[string]any{"Error": err})
		_, _ = fmt.Fprintf(s.stderr, "%s\n", strings.TrimPrefix(errMsg, "\n"))
		return
	}

	// 多源时：远程 dst 必须是已存在的目录或省略
	if len(locals) > 1 {
		var remoteDir string
		if len(args) > 1 {
			remoteDir = s.resolvePath(args[1])
			info, statErr := s.client.sftpClient.Stat(remoteDir)
			if statErr != nil || !info.IsDir() {
				_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_dest_must_be_dir"))
				return
			}
		} else {
			remoteDir = s.cwd
		}
		for _, local := range locals {
			remoteTarget := s.client.JoinPath(remoteDir, filepath.Base(local))
			s.putSingle(ctx, local, remoteTarget)
		}
		return
	}

	// 单源：保持原行为
	local := locals[0]
	var remote string
	if len(args) > 1 {
		remote = s.resolvePath(args[1])
	} else {
		remote = s.client.JoinPath(s.cwd, filepath.Base(local))
	}
	s.putSingle(ctx, local, remote)
}

// putSingle 上传单个本地文件/目录到远程，含覆盖确认与进度条
func (s *Shell) putSingle(ctx context.Context, local, remote string) {
	// 检查目标文件是否已存在
	remoteStat, err := s.client.sftpClient.Stat(remote)
	if err == nil && remoteStat.IsDir() {
		remote = s.client.JoinPath(remote, filepath.Base(local))
	}
	if _, err := s.client.sftpClient.Stat(remote); err == nil {
		if s.client.config.NoOverwrite {
			return
		}
		if !s.client.config.Force {
			if !s.askConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": remote})) {
				return
			}
			origForce := s.client.config.Force
			s.client.SetForce(true)
			defer s.client.SetForce(origForce)
		}
	}

	_, _ = fmt.Fprintln(s.stdout, i18n.Tf("sftp_shell_uploading", map[string]any{"Local": local, "Remote": remote}))

	// 计算本地文件大小以显示准确的进度条
	var totalSize int64
	walkErr := filepath.Walk(local, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info != nil && !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	if walkErr != nil {
		_, _ = fmt.Fprintf(s.stderr, "%s\n", i18n.Tf("sftp_shell_upload_failed", map[string]any{"Error": walkErr}))
		return
	}

	bar := progressbar.NewOptions64(
		totalSize,
		progressbar.OptionSetDescription("Uploading"),
		progressbar.OptionSetWriter(s.stdout), // 关键：使用 readline 的 stdout
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionOnCompletion(func() {
			_, _ = fmt.Fprint(s.stdout, "\n")
		}),
	)
	callback := func(n int64) { _ = bar.Add64(n) }

	err = s.client.Upload(ctx, local, remote, callback)
	_ = bar.Finish()
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "%s\n", i18n.Tf("sftp_shell_upload_failed", map[string]any{"Error": err}))
	} else {
		_, _ = fmt.Fprintln(s.stdout, i18n.T("sftp_shell_upload_done"))
	}
}

func (s *Shell) handleMkdir(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_mkdir_usage"))
		return
	}
	path := s.resolvePath(args[0])
	if err := s.client.sftpClient.Mkdir(path); err != nil {
		_, _ = fmt.Fprintf(s.stderr, "mkdir: %v\n", err)
	}
}

func (s *Shell) handleLocalMkdir(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_lmkdir_usage"))
		return
	}
	path := s.resolveLocalPath(args[0])
	if err := os.Mkdir(path, 0755); err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lmkdir: %v\n", err)
	}
}

func (s *Shell) handleRm(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_rm_usage"))
		return
	}
	paths, err := s.expandRemote(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "rm: %v\n", err)
		return
	}
	// 含通配符时跳过 sshClient.Run 快捷路径，避免远程 shell 二次展开导致误删
	useShellShortcut := !hasWildcard(args[0])
	for _, p := range paths {
		s.removeOne(p, useShellShortcut)
	}
}

// removeOne 删除单个远程路径
// useShellShortcut 为 true 时优先尝试远程 shell 命令 (rm -rf)，
// 失败回退到 SFTP 协议操作；为 false 时直接走 SFTP 协议
func (s *Shell) removeOne(p string, useShellShortcut bool) {
	if useShellShortcut {
		cmd := fmt.Sprintf("rm -rf '%s'", strings.ReplaceAll(p, "'", "'\\''"))
		_, err := s.client.sshClient.Run(context.Background(), cmd)
		if err == nil {
			return
		}
	}

	// 回退到 SFTP 协议操作
	if err := s.client.sftpClient.Remove(p); err != nil {
		// 尝试作为目录删除
		if err2 := s.client.sftpClient.RemoveDirectory(p); err2 != nil {
			_, _ = fmt.Fprintf(s.stderr, "rm: %v\n", err)
		}
	}
}

func (s *Shell) handleLocalRm(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_lrm_usage"))
		return
	}
	paths, err := s.expandLocal(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lrm: %v\n", err)
		return
	}
	for _, p := range paths {
		// 为了方便，lrm 直接支持递归删除
		if err := os.RemoveAll(p); err != nil {
			_, _ = fmt.Fprintf(s.stderr, "lrm: %v\n", err)
		}
	}
}

func (s *Shell) handleCp(args []string) {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_cp_usage"))
		return
	}
	srcs, err := s.expandRemote(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "cp: %v\n", err)
		return
	}
	dst := s.resolvePath(args[1])

	// 含通配符时跳过 sshClient.Run 快捷路径，避免远程 shell 二次展开
	if !hasWildcard(args[0]) && len(srcs) == 1 {
		// 优先尝试使用远程命令以实现高性能服务器端复制
		cmd := fmt.Sprintf("cp -r '%s' '%s'", strings.ReplaceAll(srcs[0], "'", "'\\''"), strings.ReplaceAll(dst, "'", "'\\''"))
		if _, err := s.client.sshClient.Run(context.Background(), cmd); err == nil {
			return
		}
		// 失败回退到 SFTP 协议流式复制
	}

	// 多源或快捷路径失败时走 SFTP 协议
	dstInfo, errStat := s.client.sftpClient.Stat(dst)
	dstIsDir := errStat == nil && dstInfo.IsDir()
	finalDsts, err := resolveMultiSrc(srcs, dst, dstIsDir)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "cp: %v\n", err)
		return
	}
	for i, src := range srcs {
		if err := s.remoteCopySFTP(src, finalDsts[i]); err != nil {
			_, _ = fmt.Fprintf(s.stderr, "cp: %v\n", err)
		}
	}
}

func (s *Shell) remoteCopySFTP(src, dst string) error {
	srcFile, err := s.client.sftpClient.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	srcStat, err := srcFile.Stat()
	if err != nil {
		return err
	}

	if srcStat.IsDir() {
		if err := s.client.sftpClient.MkdirAll(dst); err != nil {
			return err
		}
		entries, err := s.client.sftpClient.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			subSrc := s.client.JoinPath(src, entry.Name())
			subDst := s.client.JoinPath(dst, entry.Name())
			if err := s.remoteCopySFTP(subSrc, subDst); err != nil {
				return err
			}
		}
		return nil
	}

	dstFile, err := s.client.sftpClient.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = dstFile.Close() }()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func (s *Shell) handleMv(args []string) {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_mv_usage"))
		return
	}
	srcs, err := s.expandRemote(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "mv: %v\n", err)
		return
	}
	dst := s.resolvePath(args[1])

	// 含通配符时跳过 sshClient.Run 快捷路径，避免远程 shell 二次展开
	if !hasWildcard(args[0]) && len(srcs) == 1 {
		// 优先尝试使用远程命令
		cmd := fmt.Sprintf("mv '%s' '%s'", strings.ReplaceAll(srcs[0], "'", "'\\''"), strings.ReplaceAll(dst, "'", "'\\''"))
		if _, err := s.client.sshClient.Run(context.Background(), cmd); err == nil {
			return
		}
	}

	// 回退到 SFTP Rename (注意：SFTP Rename 通常不支持跨文件系统)
	dstInfo, errStat := s.client.sftpClient.Stat(dst)
	dstIsDir := errStat == nil && dstInfo.IsDir()
	finalDsts, err := resolveMultiSrc(srcs, dst, dstIsDir)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "mv: %v\n", err)
		return
	}
	for i, src := range srcs {
		if err := s.client.sftpClient.Rename(src, finalDsts[i]); err != nil {
			_, _ = fmt.Fprintf(s.stderr, "mv: %v\n", err)
		}
	}
}

func (s *Shell) handleLocalCp(args []string) {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_lcp_usage"))
		return
	}
	srcs, err := s.expandLocal(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lcp: %v\n", err)
		return
	}
	dst := s.resolveLocalPath(args[1])

	// 检查目标是否是目录
	dstInfo, errStat := os.Stat(dst)
	dstIsDir := errStat == nil && dstInfo.IsDir()
	finalDsts, err := resolveMultiSrcLocal(srcs, dst, dstIsDir)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lcp: %v\n", err)
		return
	}
	for i, src := range srcs {
		if err := s.localCopy(src, finalDsts[i]); err != nil {
			_, _ = fmt.Fprintf(s.stderr, "lcp: %v\n", err)
		}
	}
}

func (s *Shell) localCopy(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if srcInfo.IsDir() {
		if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			subSrc := filepath.Join(src, entry.Name())
			subDst := filepath.Join(dst, entry.Name())
			if err := s.localCopy(subSrc, subDst); err != nil {
				return err
			}
		}
		return nil
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = dstFile.Close() }()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}
	return os.Chmod(dst, srcInfo.Mode())
}

func (s *Shell) handleLocalMv(args []string) {
	if len(args) < 2 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_lmv_usage"))
		return
	}
	srcs, err := s.expandLocal(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lmv: %v\n", err)
		return
	}
	dst := s.resolveLocalPath(args[1])

	// 检查目标是否是目录
	dstInfo, errStat := os.Stat(dst)
	dstIsDir := errStat == nil && dstInfo.IsDir()
	finalDsts, err := resolveMultiSrcLocal(srcs, dst, dstIsDir)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lmv: %v\n", err)
		return
	}
	for i, src := range srcs {
		if err := os.Rename(src, finalDsts[i]); err != nil {
			_, _ = fmt.Fprintf(s.stderr, "lmv: %v\n", err)
		}
	}
}

func (s *Shell) printHelp() {
	_, _ = fmt.Fprintln(s.stdout, i18n.T("sftp_shell_help"))
}

func (s *Shell) askConfirmation(prompt string) bool {
	_, _ = fmt.Fprint(s.stdout, "\n")
	input, err := s.line.Prompt(fmt.Sprintf("%s [y/N]: ", prompt))
	if err != nil {
		return false
	}
	response := strings.ToLower(strings.TrimSpace(input))
	return response == "y" || response == "yes"
}

// handleShell 进入远程交互式 shell（SSH PTY）
func (s *Shell) handleShell(ctx context.Context) {
	_ = s.line.Close()
	if err := s.client.sshClient.Shell(ctx); err != nil {
		_, _ = fmt.Fprintf(s.stderr, "shell: %v\n", err)
	}
	s.resetLiner()
	_, _ = fmt.Fprintln(s.stdout, "")
}

// handleLshell 进入本地交互式 shell
func (s *Shell) handleLshell(ctx context.Context) {
	shellBin := os.Getenv("SHELL")
	if shellBin == "" {
		shellBin = "sh"
	}
	if runtime.GOOS == "windows" {
		shellBin = "powershell.exe"
	}
	c := exec.CommandContext(ctx, shellBin)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Dir = s.localCwd
	if err := c.Run(); err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lshell: %v\n", err)
	}
	_, _ = fmt.Fprintln(s.stdout, "")
}

// handleExec 在远程主机上执行命令，分配 PTY 以支持 vim/top 等交互式程序
func (s *Shell) handleExec(ctx context.Context, args []string) {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_exec_usage"))
		return
	}
	escapedCwd := strings.ReplaceAll(s.cwd, "'", "'\\''")
	cmdStr := fmt.Sprintf("cd '%s' && %s", escapedCwd, strings.Join(args, " "))
	if err := s.client.sshClient.RunInteractiveCmd(ctx, cmdStr); err != nil {
		_, _ = fmt.Fprintf(s.stderr, "exec: %v\n", err)
	}
	_, _ = fmt.Fprintln(s.stdout, "")
}

// handleLexec 在本地执行命令，接管终端 I/O 以支持 vim 等交互式程序
func (s *Shell) handleLexec(ctx context.Context, cmdStr string) {
	if cmdStr == "" {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_lexec_usage"))
		return
	}
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command", cmdStr)
	} else {
		c = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}
	// 直接绑定终端，确保 vim/less 等交互式程序能正常读写
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Dir = s.localCwd

	// liner 持有终端原始状态，运行前先将终端还原为普通模式，
	// 退出后重新接管，避免 vim 退出后终端状态混乱
	_ = s.line.Close()
	err := c.Run()
	s.resetLiner()

	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lexec: %v\n", err)
	}
}

func (s *Shell) resetLiner() {
	s.line = liner.NewLiner()
	s.line.SetCtrlCAborts(true)
	s.line.SetTabCompletionStyle(liner.TabPrints)
	s.line.SetWordCompleter(s.wordCompleter)
	if s.historyFile != "" {
		if f, err := os.Open(s.historyFile); err == nil {
			_, _ = s.line.ReadHistory(f)
			_ = f.Close()
		}
	}
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// printColumns 多列格式输出，类似 Linux ls 命令
func (s *Shell) printColumns(names []string) {
	if len(names) == 0 {
		return
	}

	// 获取终端宽度
	width := 80 // 默认宽度
	if fd := int(os.Stdout.Fd()); term.IsTerminal(fd) {
		if w, _, err := term.GetSize(fd); err == nil && w > 0 {
			width = w
		}
	}

	// 找出最长名称
	maxLen := 0
	for _, name := range names {
		if len(name) > maxLen {
			maxLen = len(name)
		}
	}

	// 每列宽度 = 最大名称 + 2 (间距)
	colWidth := maxLen + 2
	if colWidth < 4 {
		colWidth = 4
	}

	// 计算列数
	cols := width / colWidth
	if cols < 1 {
		cols = 1
	}

	// 计算行数
	rows := (len(names) + cols - 1) / cols

	// 按列优先顺序输出
	for row := range rows {
		for col := 0; col < cols; col++ {
			idx := col*rows + row
			if idx >= len(names) {
				break
			}
			name := names[idx]
			// 使用固定宽度格式化，左对齐
			_, _ = fmt.Fprintf(s.stdout, "%-*s", colWidth, name)
		}
		_, _ = fmt.Fprintln(s.stdout)
	}
}
