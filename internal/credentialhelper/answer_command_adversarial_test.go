//go:build !windows

package credentialhelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestAdversarialAnswerHelperProcess 提供对抗性子进程桩。
func TestAdversarialAnswerHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_ADVERSARIAL_HELPER") != "1" {
		return
	}

	mode := os.Getenv("ADV_HELPER_MODE")
	if handleHelperOutputModes(mode) {
		return
	}
	if handleHelperProcessModes(mode) {
		return
	}
	if handleHelperEnvModes(mode) {
		return
	}
	if handleHelperStderrModes(mode) {
		return
	}

	_, _ = fmt.Fprintf(os.Stderr, "unknown adversarial mode: %s\n", mode)
	os.Exit(1)
}

func handleHelperOutputModes(mode string) bool {
	switch mode {
	case "flood_1mb":
		chunk := bytes.Repeat([]byte("B"), 64*1024)
		for i := 0; i < 16; i++ {
			if _, err := os.Stdout.Write(chunk); err != nil {
				os.Exit(1)
			}
		}
		os.Exit(0)
	case "boundary_4096_with_newline":
		data := append(bytes.Repeat([]byte("X"), 4095), '\n')
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	case "boundary_4096_no_newline":
		data := bytes.Repeat([]byte("Y"), 4096)
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	case "boundary_4097_with_newline":
		data := append(bytes.Repeat([]byte("Z"), 4096), '\n')
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	default:
		return false
	}
	return true
}

func handleHelperProcessModes(mode string) bool {
	switch mode {
	case "spawn_grandchild":
		pidFile := os.Getenv("ADV_GRANDCHILD_PID_FILE")
		child := exec.Command("sleep", "60")
		if err := child.Start(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to start child: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "failed to write pid file: %v\n", err)
			os.Exit(3)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "ignore_sigterm":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "continuous_stdin_read":
		buf := make([]byte, 1024)
		for i := 0; i < 50; i++ {
			n, err := os.Stdin.Read(buf)
			if err != io.EOF && n != 0 {
				_, _ = fmt.Fprintf(os.Stderr, "stdin read unexpected: n=%d err=%v\n", n, err)
				os.Exit(4)
			}
		}
		fmt.Print("stdin-exhausted-eof\n")
		os.Exit(0)
	case "orphan_grandchild_holds_stdout":
		fmt.Print("immediate-token\n")
		child := exec.Command("sleep", "10")
		child.Stdout = os.Stdout
		_ = child.Start()
		os.Exit(0)
	default:
		return false
	}
	return true
}

func handleHelperEnvModes(mode string) bool {
	switch mode {
	case "verify_env_poisoning":
		verifyEnvPoisoning()
		fmt.Print("env-isolation-verified\n")
		os.Exit(0)
	case "verify_complex_ansi":
		verifyComplexANSI()
		fmt.Print("ansi-sanitized-ok\n")
		os.Exit(0)
	default:
		return false
	}
	return true
}

func verifyEnvPoisoning() {
	forbiddenKeys := []string{"XOPS_POISON", "XOPS_INJECTION", "XOPS_MALICIOUS"}
	for _, k := range forbiddenKeys {
		if v, exists := os.LookupEnv(k); exists {
			_, _ = fmt.Fprintf(os.Stderr, "forbidden env %s exists with value %q\n", k, v)
			os.Exit(5)
		}
	}
	if os.Getenv("XOPS_NODE") != "legit-node" {
		_, _ = fmt.Fprintf(os.Stderr, "XOPS_NODE poisoned: %q\n", os.Getenv("XOPS_NODE"))
		os.Exit(6)
	}
	if os.Getenv("XOPS_HOST") != "legit-host" {
		_, _ = fmt.Fprintf(os.Stderr, "XOPS_HOST poisoned: %q\n", os.Getenv("XOPS_HOST"))
		os.Exit(7)
	}
	if os.Getenv("XOPS_USER") != "legit-user" {
		_, _ = fmt.Fprintf(os.Stderr, "XOPS_USER poisoned: %q\n", os.Getenv("XOPS_USER"))
		os.Exit(8)
	}
	if os.Getenv("XOPS_NON_INTERACTIVE") != "1" {
		_, _ = fmt.Fprintf(os.Stderr, "XOPS_NON_INTERACTIVE unexpected: %q\n", os.Getenv("XOPS_NON_INTERACTIVE"))
		os.Exit(9)
	}
}

func verifyComplexANSI() {
	prompt := os.Getenv("XOPS_PROMPT")
	instruction := os.Getenv("XOPS_INSTRUCTION")

	if strings.Contains(prompt, "\x1b") || strings.Contains(instruction, "\x1b") {
		_, _ = fmt.Fprintf(os.Stderr, "ESC byte leaked in prompt/instruction\n")
		os.Exit(10)
	}
	for _, b := range []byte{0x00, 0x07, 0x08, 0x0b, 0x0c, 0x1b, 0x7f, '\r'} {
		if bytes.Contains([]byte(prompt), []byte{b}) || bytes.Contains([]byte(instruction), []byte{b}) {
			_, _ = fmt.Fprintf(os.Stderr, "control byte 0x%02x leaked\n", b)
			os.Exit(11)
		}
	}
	if !strings.Contains(prompt, "Please Enter OTP:") || !strings.Contains(prompt, "\nLine2\tTabbed") {
		_, _ = fmt.Fprintf(os.Stderr, "prompt content mismatch: %q\n", prompt)
		os.Exit(12)
	}
	if !strings.Contains(instruction, "Safe Instruction Banner") {
		_, _ = fmt.Fprintf(os.Stderr, "instruction content mismatch: %q\n", instruction)
		os.Exit(13)
	}
}

func handleHelperStderrModes(mode string) bool {
	if mode != "stderr_flood_secrets" {
		return false
	}
	junk := strings.Repeat("system log diagnostic noise line\n", 2000)
	secret := "critical secret: dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY3ODkw\n"
	_, _ = os.Stderr.WriteString(secret + junk)
	os.Exit(99)
	return true
}

func adversarialOptions(mode string, env ...string) AnswerCommandOptions {
	allEnv := append([]string{
		"GO_WANT_ADVERSARIAL_HELPER=1",
		"ADV_HELPER_MODE=" + mode,
	}, env...)
	return AnswerCommandOptions{
		Command: os.Args[0],
		Args:    []string{"-test.run=^TestAdversarialAnswerHelperProcess$", "--"},
		Env:     allEnv,
		Timeout: 5 * time.Second,
	}
}

// TestAdversarial_OutputFlooding_1MB 测试 1MB 大输出管道排空防死锁与 4096 字节截断
func TestAdversarial_OutputFlooding_1MB(t *testing.T) {
	ctx := context.Background()
	opts := adversarialOptions("flood_1mb")

	start := time.Now()
	ans, err := RunAnswerCommand(ctx, opts)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("RunAnswerCommand failed on 1MB output: %v", err)
	}
	if len(ans) != MaxAnswerStdoutBytes {
		t.Fatalf("expected bounded output length %d, got %d", MaxAnswerStdoutBytes, len(ans))
	}
	expected := bytes.Repeat([]byte("B"), MaxAnswerStdoutBytes)
	if !bytes.Equal(ans, expected) {
		t.Fatalf("output content does not match expected prefix")
	}
	t.Logf("1MB flooding successfully drained and bounded in %v", duration)
}

// TestAdversarial_OutputBoundaries 测试 4095、4096、4097 字节边界及换行符剥离行为
func TestAdversarial_OutputBoundaries(t *testing.T) {
	ctx := context.Background()

	// 1. 4095 字节 + '\n' -> 剥离后恰好 4095 字节
	opts1 := adversarialOptions("boundary_4096_with_newline")
	ans1, err := RunAnswerCommand(ctx, opts1)
	if err != nil {
		t.Fatalf("boundary 4095+newline failed: %v", err)
	}
	if len(ans1) != 4095 {
		t.Fatalf("expected 4095 bytes after newline trim, got %d", len(ans1))
	}

	// 2. 4096 字节无换行符 -> 返回 4096 字节
	opts2 := adversarialOptions("boundary_4096_no_newline")
	ans2, err := RunAnswerCommand(ctx, opts2)
	if err != nil {
		t.Fatalf("boundary 4096 no newline failed: %v", err)
	}
	if len(ans2) != 4096 {
		t.Fatalf("expected 4096 bytes, got %d", len(ans2))
	}

	// 3. 4096 字节 + '\n' (总计 4097 字节) -> LimitReader 读前 4096 字节，末尾 '\n' 未落入缓冲
	opts3 := adversarialOptions("boundary_4097_with_newline")
	ans3, err := RunAnswerCommand(ctx, opts3)
	if err != nil {
		t.Fatalf("boundary 4097 failed: %v", err)
	}
	if len(ans3) != 4096 {
		t.Fatalf("expected 4096 bytes, got %d", len(ans3))
	}
	if bytes.HasSuffix(ans3, []byte("\n")) {
		t.Fatalf("output should not contain newline")
	}
}

// TestAdversarial_ProcessTreeKilling_WithGrandchildren 验证 KillTree 终止包括孙进程在内的整个进程树
func TestAdversarial_ProcessTreeKilling_WithGrandchildren(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := tmpDir + "/grandchild.pid"

	opts := adversarialOptions("spawn_grandchild", "ADV_GRANDCHILD_PID_FILE="+pidFile)
	opts.Timeout = 150 * time.Millisecond

	start := time.Now()
	_, err := RunAnswerCommand(context.Background(), opts)
	duration := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out after") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 读取孙进程 PID
	pidData, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("failed to read grandchild PID file: %v", readErr)
	}
	grandchildPid, parseErr := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if parseErr != nil || grandchildPid <= 0 {
		t.Fatalf("invalid grandchild PID: %q", string(pidData))
	}

	// 轮询检查孙进程是否已被 SIGKILL 终止
	dead := false
	for i := 0; i < 20; i++ {
		// syscall.Kill(pid, 0) 返回 ESRCH 表示进程已彻底死亡
		err := syscall.Kill(grandchildPid, 0)
		if errors.Is(err, syscall.ESRCH) {
			dead = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !dead {
		// 兜底清理孤儿孙进程
		_ = syscall.Kill(grandchildPid, syscall.SIGKILL)
		t.Fatalf("grandchild process %d was NOT terminated by KillTree!", grandchildPid)
	}
	t.Logf("grandchild process %d successfully terminated by KillTree within %v", grandchildPid, duration)
}

// TestAdversarial_ProcessTreeKilling_StubbornSIGKILL 验证无法捕获 SIGKILL 的顽固进程被直接杀死
func TestAdversarial_ProcessTreeKilling_StubbornSIGKILL(t *testing.T) {
	opts := adversarialOptions("ignore_sigterm")
	opts.Timeout = 100 * time.Millisecond

	_, err := RunAnswerCommand(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "timed out after") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

// TestAdversarial_AlreadyCanceledContext 验证传入已取消的 Context 能够立即安全退出而不发生死锁
func TestAdversarial_AlreadyCanceledContext(t *testing.T) {
	opts := adversarialOptions("flood_1mb")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 预先取消

	_, err := RunAnswerCommand(ctx, opts)
	if err == nil {
		t.Fatalf("expected canceled error")
	}
	if !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestAdversarial_StdinDevNull_ContinuousRead 验证 stdin 连续读取立即返回 EOF 而不阻塞挂起
func TestAdversarial_StdinDevNull_ContinuousRead(t *testing.T) {
	ctx := context.Background()
	opts := adversarialOptions("continuous_stdin_read")

	ans, err := RunAnswerCommand(ctx, opts)
	if err != nil {
		t.Fatalf("continuous stdin read failed: %v", err)
	}
	if string(ans) != "stdin-exhausted-eof" {
		t.Fatalf("unexpected answer: %q", string(ans))
	}
}

// TestAdversarial_EnvironmentPoisoning_CallerIsolation 验证调用方环境及 opts.Env 中注入的恶意 XOPS_* 变量被完全隔离
func TestAdversarial_EnvironmentPoisoning_CallerIsolation(t *testing.T) {
	// 设置当前进程宿主环境中的恶意 XOPS_* 变量
	t.Setenv("XOPS_POISON", "attacker-payload")
	t.Setenv("XOPS_NODE", "poisoned-node")
	t.Setenv("XOPS_HOST", "poisoned-host")
	t.Setenv("XOPS_INJECTION", "injected-secret")

	opts := adversarialOptions("verify_env_poisoning")
	// 在 opts.Env 中追加恶意覆盖
	opts.Env = append(opts.Env, "XOPS_MALICIOUS=malicious", "XOPS_USER=attacker-user")

	// 设置合法的上下文参数
	opts.Node = "legit-node"
	opts.Host = "legit-host"
	opts.User = "legit-user"
	opts.NonInteractive = true

	ans, err := RunAnswerCommand(context.Background(), opts)
	if err != nil {
		t.Fatalf("environment poisoning test failed: %v", err)
	}
	if string(ans) != "env-isolation-verified" {
		t.Fatalf("unexpected answer: %q", string(ans))
	}
}

// TestAdversarial_ANSISanitization_Exhaustive 穷举测试复杂 ANSI 转义序列与控制字符清洗
func TestAdversarial_ANSISanitization_Exhaustive(t *testing.T) {
	opts := adversarialOptions("verify_complex_ansi")

	// 构造包含多种复杂 CSI、OSC、ESC 与控制字符的 prompt 和 instruction
	opts.Prompt = "\x1b[38;2;255;0;0m\x1b[48;2;0;0;255m\x1b[?1049h\x00\x07Please Enter OTP:\x08\x1b[0m\r\nLine2\tTabbed\x1b[2K\x7f"
	opts.Instruction = "\x1b]0;Evil Window Title\x07\x1b]2;Another OSC Title\x1b\\\x1bM\x0bSafe Instruction Banner\x0c"

	ans, err := RunAnswerCommand(context.Background(), opts)
	if err != nil {
		t.Fatalf("ansi sanitization test failed: %v", err)
	}
	if string(ans) != "ansi-sanitized-ok" {
		t.Fatalf("unexpected answer: %q", string(ans))
	}
}

// TestAdversarial_StderrFloodingAndRedaction 测试 100KB Stderr 洪水输出下限流至 4096 字节且敏感凭据被脱敏
func TestAdversarial_StderrFloodingAndRedaction(t *testing.T) {
	opts := adversarialOptions("stderr_flood_secrets")
	_, err := RunAnswerCommand(context.Background(), opts)
	if err == nil {
		t.Fatalf("expected error on nonzero exit")
	}
	errMsg := err.Error()

	// 1. 验证敏感 Base64 凭据被脱敏为 [REDACTED]
	if strings.Contains(errMsg, "dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY3ODkw") {
		t.Fatalf("sensitive Base64 token leaked in error message: %s", errMsg)
	}
	if !strings.Contains(errMsg, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in error message: %s", errMsg)
	}

	// 2. 验证错误信息长度受到 SanitizeDiagnostic (256 字符上限 + "...") 严格控制，未被 100KB 撑爆
	if len(errMsg) > 500 {
		t.Fatalf("error message exceeds safe bounded diagnostic limit: length=%d", len(errMsg))
	}
	if !strings.Contains(errMsg, "...") {
		t.Fatalf("expected truncated diagnostic with '...', got: %s", errMsg)
	}
}

// TestAdversarial_Concurrency_RaceStress 并发压测 30 个协程混合执行不同场景，确保零死锁零竞态
func TestAdversarial_Concurrency_RaceStress(t *testing.T) {
	const workers = 30
	var wg sync.WaitGroup
	wg.Add(workers)

	modes := []string{
		"flood_1mb",
		"boundary_4096_with_newline",
		"continuous_stdin_read",
		"verify_complex_ansi",
	}

	errChan := make(chan error, workers)

	for i := 0; i < workers; i++ {
		mode := modes[i%len(modes)]
		go func(m string, id int) {
			defer wg.Done()
			opts := adversarialOptions(m)
			if m == "verify_complex_ansi" {
				opts.Prompt = fmt.Sprintf("\x1b[31mWorker-%d\x1b[0m Please Enter OTP:\r\nLine2\tTabbed", id)
				opts.Instruction = "\x1b]0;Title\x07Safe Instruction Banner"
			}
			_, err := RunAnswerCommand(context.Background(), opts)
			if err != nil {
				errChan <- fmt.Errorf("worker %d (%s) failed: %w", id, m, err)
			}
		}(mode, i)
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		t.Fatalf("concurrent stress test had %d failures: %v", len(errs), errs[0])
	}
}

// TestAdversarial_OrphanGrandchild_WaitDelayUnblocks 验证孙进程继承 stdout 保持打开时，cmd.WaitDelay 能够安全解除等待而非永久阻塞
func TestAdversarial_OrphanGrandchild_WaitDelayUnblocks(t *testing.T) {
	opts := adversarialOptions("orphan_grandchild_holds_stdout")
	opts.Timeout = 5 * time.Second

	start := time.Now()
	ans, err := RunAnswerCommand(context.Background(), opts)
	elapsed := time.Since(start)

	if err != nil {
		t.Logf("errors.Is(err, os.ErrClosed) = %v", errors.Is(err, os.ErrClosed))
		t.Fatalf("expected success with WaitDelay unblocking, got error: %v", err)
	}
	if string(ans) != "immediate-token" {
		t.Fatalf("got unexpected token %q", string(ans))
	}
	// 验证在 1 秒内完成（WaitDelay 为 50ms），未等待 10 秒
	if elapsed > 2*time.Second {
		t.Fatalf("command took too long (%v), WaitDelay did not unblock in time", elapsed)
	}
	t.Logf("command successfully unblocked via WaitDelay in %v", elapsed)
}
