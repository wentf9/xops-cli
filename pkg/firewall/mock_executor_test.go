package firewall

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/pkg/ssh"
)

// mockExecutor 记录接收到的命令并返回预设结果
type mockExecutor struct {
	lastCmd string
	// responses 映射命令前缀到预设输出
	responses map[string]string
	// errors 映射命令前缀到预设错误
	errors map[string]error
}

func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		responses: make(map[string]string),
		errors:    make(map[string]error),
	}
}

func (m *mockExecutor) Run(ctx context.Context, cmd string, opts ...ssh.RunOption) (string, error) {
	m.lastCmd = cmd
	if err, ok := m.errors[cmd]; ok {
		return "", err
	}
	if resp, ok := m.responses[cmd]; ok {
		return resp, nil
	}
	return "", fmt.Errorf("command not found: %s", cmd)
}

func (m *mockExecutor) RunWithSudo(ctx context.Context, cmd string, opts ...ssh.RunOption) (string, error) {
	return m.Run(ctx, cmd, opts...)
}

func (m *mockExecutor) InteractiveWithSudo(ctx context.Context, args []string) error {
	return nil
}
