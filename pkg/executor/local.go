package executor

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// LocalExecutor 本地执行器
type LocalExecutor struct {
	password string
}

func NewLocalExecutor(password string) *LocalExecutor {
	return &LocalExecutor{password: password}
}

func (e *LocalExecutor) Run(ctx context.Context, cmd string) (string, error) {
	// 使用 bash -c 执行以支持复杂的 shell 语法
	c := exec.CommandContext(ctx, "bash", "-c", cmd)
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("command failed: %w, output: %s", err, string(out))
	}
	return string(out), nil
}

func (e *LocalExecutor) RunWithSudo(ctx context.Context, cmd string) (string, error) {
	if os.Getuid() == 0 {
		return e.Run(ctx, cmd)
	}
	if e.password == "" {
		// 如果没密码，尝试无交互 sudo
		if !strings.HasPrefix(cmd, "sudo") {
			cmd = "sudo " + cmd
		}
		return e.Run(ctx, cmd)
	}

	// 使用 sudo -S 从 stdin 读取密码
	// -p '' 隐藏提示符
	sudoCmd := fmt.Sprintf("sudo -S -p '' %s", cmd)
	c := exec.CommandContext(ctx, "bash", "-c", sudoCmd)

	stdin, err := c.StdinPipe()
	if err != nil {
		return "", err
	}

	go func() {
		defer func() { _ = stdin.Close() }()
		_, _ = io.WriteString(stdin, e.password+"\n")
	}()

	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("sudo command failed: %w, output: %s", err, string(out))
	}
	return string(out), nil
}

func (e *LocalExecutor) InteractiveWithSudo(ctx context.Context, args []string) error {
	if os.Getuid() == 0 {
		c := exec.CommandContext(ctx, "bash", args...)
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	}

	// 如果有密码，先使用 sudo -v (validate) 注入密码到缓存中
	if e.password != "" {
		// sudo -v -S 从 stdin 读取密码并更新 sudo 缓存
		vCmd := exec.CommandContext(ctx, "sudo", "-v", "-S", "-p", "")
		vStdin, err := vCmd.StdinPipe()
		if err != nil {
			return err
		}
		if err := vCmd.Start(); err != nil {
			return err
		}
		_, _ = vStdin.Write([]byte(e.password + "\n"))
		_ = vStdin.Close()
		_ = vCmd.Wait()
		// 无论 sudo -v 是否成功（可能密码错），我们都继续下一步，让原生 sudo 处理
	}

	// 现在密码已经在缓存里（或者由用户手动输入），直接运行 sudo -s 并接管 TTY
	// 这样可以获得完美的 shell 体验，不会有 stdin 转发导致的报错
	sudoArgs := []string{"-s"}
	sudoArgs = append(sudoArgs, args...)
	c := exec.CommandContext(ctx, "sudo", sudoArgs...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
