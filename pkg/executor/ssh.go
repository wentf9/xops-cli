package executor

import (
	"context"

	"github.com/wentf9/xops-cli/pkg/ssh"
)

// SSHExecutor 包装 ssh.Client 以满足 Executor 接口
type SSHExecutor struct {
	client *ssh.Client
}

func NewSSHExecutor(client *ssh.Client) *SSHExecutor {
	return &SSHExecutor{client: client}
}

func (e *SSHExecutor) Run(ctx context.Context, cmd string, opts ...ssh.RunOption) (string, error) {
	return e.client.Run(ctx, cmd, opts...)
}

func (e *SSHExecutor) RunWithSudo(ctx context.Context, cmd string, opts ...ssh.RunOption) (string, error) {
	return e.client.RunWithSudo(ctx, cmd, opts...)
}

func (e *SSHExecutor) InteractiveWithSudo(ctx context.Context, args []string) error {
	// 远程交互式 Shell 暂不处理 args，直接进入 ShellWithSudo
	return e.client.ShellWithSudo(ctx)
}
