package executor

import (
	"context"

	"github.com/wentf9/xops-cli/pkg/ssh"
)

// SSHExecutor 包装 ssh.Client 以满足 Executor 接口
type SSHExecutor struct {
	client      *ssh.Client
	defaultOpts []ssh.RunOption
}

func NewSSHExecutor(client *ssh.Client, opts ...ssh.RunOption) *SSHExecutor {
	return &SSHExecutor{client: client, defaultOpts: opts}
}

func (e *SSHExecutor) Run(ctx context.Context, cmd string, opts ...ssh.RunOption) (string, error) {
	finalOpts := append(e.defaultOpts, opts...)
	return e.client.Run(ctx, cmd, finalOpts...)
}

func (e *SSHExecutor) RunWithSudo(ctx context.Context, cmd string, opts ...ssh.RunOption) (string, error) {
	finalOpts := append(e.defaultOpts, opts...)
	return e.client.RunWithSudo(ctx, cmd, finalOpts...)
}

func (e *SSHExecutor) InteractiveWithSudo(ctx context.Context, args []string) error {
	// 远程交互式 Shell 暂不处理 args，直接进入 ShellWithSudo
	return e.client.ShellWithSudo(ctx)
}
