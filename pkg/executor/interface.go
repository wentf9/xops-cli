package executor

import (
	"context"

	"github.com/wentf9/xops-cli/pkg/ssh"
)

// Executor 定义命令执行接口
type Executor interface {
	// Run 执行命令并返回标准输出内容
	Run(ctx context.Context, cmd string, opts ...ssh.RunOption) (string, error)
	// RunWithSudo 提权执行命令
	RunWithSudo(ctx context.Context, cmd string, opts ...ssh.RunOption) (string, error)
	// InteractiveWithSudo 开启交互式提权会话 (如 sudo -s)
	InteractiveWithSudo(ctx context.Context, args []string) error
}

// Transfer 定义文件传输接口
type Transfer interface {
	// Copy 复制文件 (为了统一 SCP 和 本地复制)
	Copy(ctx context.Context, src, dst string) error
}
