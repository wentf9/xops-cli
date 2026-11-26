//go:build windows

package agent_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys/agent"
	"go.uber.org/goleak"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

const agentHelperPipeEnv = "XOPS_AGENT_TEST_PIPE"

// TestAgentHelperProcess 在独立测试子进程中创建带属主 DACL 的 Windows 命名管道 SSH Agent 服务。
func TestAgentHelperProcess(t *testing.T) {
	pipeName := os.Getenv(agentHelperPipeEnv)
	if pipeName == "" {
		return
	}
	ring, err := buildTestKeyring()
	if err != nil {
		os.Exit(2)
	}
	namePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		os.Exit(3)
	}
	sd, err := buildOwnerPipeSD()
	if err != nil {
		os.Exit(4)
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	h, err := createTestPipeInstance(namePtr, sa)
	if err != nil {
		os.Exit(5)
	}
	_, _ = io.WriteString(os.Stdout, "READY\n")
	serveWindowsPipeLoop(h, namePtr, sa, ring)
	runtime.KeepAlive(sd)
	runtime.KeepAlive(sa)
	os.Exit(0)
}

func buildOwnerPipeSD() (*windows.SECURITY_DESCRIPTOR, error) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sddl := fmt.Sprintf("O:%sD:P(A;;GA;;;%s)", tu.User.Sid.String(), tu.User.Sid.String())
	return windows.SecurityDescriptorFromString(sddl)
}

func createTestPipeInstance(namePtr *uint16, sa *windows.SecurityAttributes) (windows.Handle, error) {
	return windows.CreateNamedPipe(
		namePtr,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES,
		4096,
		4096,
		0,
		sa,
	)
}

func serveWindowsPipeLoop(h windows.Handle, namePtr *uint16, sa *windows.SecurityAttributes, ring sshagent.Agent) {
	for {
		err := windows.ConnectNamedPipe(h, nil)
		if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			_ = windows.CloseHandle(h)
			return
		}
		// 立即预先创建下一个监听实例再处理并关闭当前连接，防止连续拨号之间出现 0 实例窗口触发 ERROR_FILE_NOT_FOUND。
		next, cErr := createTestPipeInstance(namePtr, sa)
		f := os.NewFile(uintptr(h), "agent-pipe")
		_ = sshagent.ServeAgent(ring, f)
		_ = f.Close()
		if cErr != nil {
			return
		}
		h = next
	}
}

func startWindowsAgentHelper(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable 失败: %v", err)
	}
	pipeName := fmt.Sprintf(`\\.\pipe\xops-tck-agent-%d-%d`, os.Getpid(), time.Now().UnixNano())
	cmd := exec.Command(exe, "-test.run=^TestAgentHelperProcess$")
	cmd.Env = append(os.Environ(), agentHelperPipeEnv+"="+pipeName)
	stdoutR, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe 失败: %v", err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdoutR.Close()
		t.Fatalf("启动 Windows SSH Agent 子进程桩失败: %v", err)
	}
	line, rErr := bufio.NewReader(stdoutR).ReadString('\n')
	if rErr != nil || strings.TrimSpace(line) != "READY" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("Windows SSH Agent 子进程桩未就绪: line=%q err=%v", line, rErr)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = stdoutR.Close()
		_ = cmd.Wait()
	})
	return pipeName
}

// TestTCKSSHAgent_Windows 验证 Windows 命名管道 SSH Agent 适配器完整通过 core/ports/tck.RunSSHAgentSuite。
func TestTCKSSHAgent_Windows(t *testing.T) {
	defer goleak.VerifyNone(t)
	pipeName := startWindowsAgentHelper(t)
	missingPipe := fmt.Sprintf(`\\.\pipe\xops-tck-missing-%d`, os.Getpid())

	tck.RunSSHAgentSuite(t, tck.SSHAgentFixture{
		NewAgent: func(*testing.T) ports.SSHAgentPort {
			return agent.NewSystemAgent(agent.Spec{Env: staticEnv{vals: map[string]string{"SSH_AUTH_SOCK": pipeName}}})
		},
		NewUnavailableAgent: func(*testing.T) ports.SSHAgentPort {
			return agent.NewSystemAgent(agent.Spec{Env: staticEnv{vals: map[string]string{"SSH_AUTH_SOCK": missingPipe}}})
		},
		Spec: algebraic.None[inventory.AgentSpec](),
	})

	sp, err := inventory.ParseAgentSpec(pipeName)
	if err != nil {
		t.Fatalf("ParseAgentSpec(%q) 失败: %v", pipeName, err)
	}
	ag := agent.NewSystemAgent(agent.Spec{Env: staticEnv{}})
	verifyAgentRSASHA256Sign(t, ag, algebraic.Some(sp))
}
