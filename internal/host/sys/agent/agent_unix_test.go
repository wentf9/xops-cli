//go:build unix

package agent_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys/agent"
	"go.uber.org/goleak"
	sshagent "golang.org/x/crypto/ssh/agent"
)

const agentHelperSockEnv = "XOPS_AGENT_TEST_SOCK"

// TestAgentHelperProcess 在独立测试子进程中运行真实 SSH Agent Unix 套接字服务，
// 既可跨进程检验 SO_PEERCRED / LOCAL_PEERCRED 对端认证，又保证父测试进程零后台协程泄漏。
func TestAgentHelperProcess(t *testing.T) {
	sock := os.Getenv(agentHelperSockEnv)
	if sock == "" {
		return
	}
	ring, err := buildTestKeyring()
	if err != nil {
		os.Exit(2)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		os.Exit(3)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		os.Exit(4)
	}
	n, err := conc.NewNursery(context.Background())
	if err != nil {
		_ = ln.Close()
		os.Exit(5)
	}
	if err := n.Go(func(context.Context) error {
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return nil
			}
			_ = n.Go(func(context.Context) error {
				defer func() { _ = conn.Close() }()
				_ = sshagent.ServeAgent(ring, conn)
				return nil
			})
		}
	}); err != nil {
		_ = ln.Close()
		_ = n.Close()
		os.Exit(6)
	}
	_, _ = io.WriteString(os.Stdout, "READY\n")
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = ln.Close()
	_ = n.Close()
	os.Exit(0)
}

func startUnixAgentHelper(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable 失败: %v", err)
	}
	// 使用短路径临时目录避免在非 /tmp TMPDIR 或 macOS 104B / Linux 108B AF_UNIX sun_path 上限下溢出。
	shortDir, err := os.MkdirTemp("", "xops-ag-*")
	if err != nil {
		t.Fatalf("os.MkdirTemp 失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortDir) })
	baseDir, err := filepath.EvalSymlinks(shortDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) 失败: %v", shortDir, err)
	}
	sock := filepath.Join(baseDir, "a.sock")
	cmd := exec.Command(exe, "-test.run=^TestAgentHelperProcess$")
	cmd.Env = append(os.Environ(), agentHelperSockEnv+"="+sock)
	stdinW, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe 失败: %v", err)
	}
	stdoutR, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdinW.Close()
		t.Fatalf("StdoutPipe 失败: %v", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		t.Fatalf("启动 SSH Agent 子进程桩失败: %v", err)
	}
	line, rErr := bufio.NewReader(stdoutR).ReadString('\n')
	if rErr != nil || strings.TrimSpace(line) != "READY" {
		_ = stdinW.Close()
		_ = cmd.Wait()
		t.Fatalf("SSH Agent 子进程桩未就绪: line=%q err=%v", line, rErr)
	}
	t.Cleanup(func() {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = cmd.Wait()
	})
	return sock
}

// TestTCKSSHAgent_Unix 验证真实 Unix SSH Agent 适配器完整通过 core/ports/tck.RunSSHAgentSuite 与 RSA-SHA256 验签。
func TestTCKSSHAgent_Unix(t *testing.T) {
	defer goleak.VerifyNone(t)
	sock := startUnixAgentHelper(t)
	missingSock := filepath.Join(t.TempDir(), "missing.sock")

	t.Run("EnvSSHAuthSock", func(t *testing.T) {
		tck.RunSSHAgentSuite(t, tck.SSHAgentFixture{
			NewAgent: func(*testing.T) ports.SSHAgentPort {
				return agent.NewSystemAgent(agent.Spec{Env: staticEnv{vals: map[string]string{"SSH_AUTH_SOCK": sock}}})
			},
			NewUnavailableAgent: func(*testing.T) ports.SSHAgentPort {
				return agent.NewSystemAgent(agent.Spec{Env: staticEnv{vals: map[string]string{"SSH_AUTH_SOCK": missingSock}}})
			},
			Spec: algebraic.None[inventory.AgentSpec](),
		})
	})

	t.Run("ExplicitSpecAndRSASHA256", func(t *testing.T) {
		sp, err := inventory.ParseAgentSpec(sock)
		if err != nil {
			t.Fatalf("ParseAgentSpec(%q) 失败: %v", sock, err)
		}
		ag := agent.NewSystemAgent(agent.Spec{Env: staticEnv{}})
		verifyAgentRSASHA256Sign(t, ag, algebraic.Some(sp))
	})
}
