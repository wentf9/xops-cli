package credentialhelper

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestAnswerCommandHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_ANSWER_COMMAND_HELPER") != "1" {
		return
	}

	mode := os.Getenv("ANSWER_HELPER_MODE")
	switch mode {
	case "success":
		fmt.Print("token-123456\n")
		os.Exit(0)
	case "crlf":
		fmt.Print("crlf-token\r\n")
		os.Exit(0)
	case "cr":
		fmt.Print("cr-token\r")
		os.Exit(0)
	case "verify_stdin":
		// 读取 Stdin，预期因为绑定到 os.DevNull 而立即返回 EOF
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "read stdin error: %v\n", err)
			os.Exit(2)
		}
		if len(b) > 0 {
			_, _ = fmt.Fprintf(os.Stderr, "expected empty stdin, got %d bytes\n", len(b))
			os.Exit(3)
		}
		fmt.Print("stdin-is-eof\n")
		os.Exit(0)
	case "verify_env":
		expected := map[string]string{
			"XOPS_NODE":            "node-alpha",
			"XOPS_HOST":            "10.0.0.1",
			"XOPS_USER":            "devops",
			"XOPS_IDENTITY":        "jumpbox",
			"XOPS_PROMPT":          "Verification Code:",
			"XOPS_INSTRUCTION":     "Enter TOTP",
			"XOPS_ECHO":            "true",
			"XOPS_NON_INTERACTIVE": "1",
		}
		for k, v := range expected {
			got := os.Getenv(k)
			if got != v {
				_, _ = fmt.Fprintf(os.Stderr, "env %s: got %q, want %q\n", k, got, v)
				os.Exit(4)
			}
		}
		fmt.Print("env-ok\n")
		os.Exit(0)
	case "huge_output":
		// 输出大于 4096 字节的数据 (例如 10000 字节)
		data := bytes.Repeat([]byte("A"), 10000)
		data = append(data, '\n')
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	case "hang":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "crash":
		_, _ = fmt.Fprintf(os.Stderr, "failed with base64 secret dXNlcm5hbWU6cGFzc3dvcmQxMjM= details")
		os.Exit(42)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown mode: %s\n", mode)
		os.Exit(1)
	}
}

func fakeAnswerCommandOptions(mode string, env ...string) AnswerCommandOptions {
	allEnv := append([]string{
		"GO_WANT_ANSWER_COMMAND_HELPER=1",
		"ANSWER_HELPER_MODE=" + mode,
	}, env...)
	return AnswerCommandOptions{
		Command: os.Args[0],
		Args:    []string{"-test.run=^TestAnswerCommandHelperProcess$", "--"},
		Env:     allEnv,
		Timeout: 5 * time.Second,
	}
}

func TestRunAnswerCommand_SuccessAndNewlineTrim(t *testing.T) {
	ctx := context.Background()

	// 1. 单个 \n 换行符剥离
	opts := fakeAnswerCommandOptions("success")
	ans, err := RunAnswerCommand(ctx, opts)
	if err != nil {
		t.Fatalf("RunAnswerCommand failed: %v", err)
	}
	if string(ans) != "token-123456" {
		t.Fatalf("got %q, want %q", string(ans), "token-123456")
	}

	// 2. \r\n 换行符剥离
	optsCRLF := fakeAnswerCommandOptions("crlf")
	ansCRLF, err := RunAnswerCommand(ctx, optsCRLF)
	if err != nil {
		t.Fatalf("RunAnswerCommand crlf failed: %v", err)
	}
	if string(ansCRLF) != "crlf-token" {
		t.Fatalf("got %q, want %q", string(ansCRLF), "crlf-token")
	}

	// 3. \r 换行符剥离
	optsCR := fakeAnswerCommandOptions("cr")
	ansCR, err := RunAnswerCommand(ctx, optsCR)
	if err != nil {
		t.Fatalf("RunAnswerCommand cr failed: %v", err)
	}
	if string(ansCR) != "cr-token" {
		t.Fatalf("got %q, want %q", string(ansCR), "cr-token")
	}
}

func TestRunAnswerCommand_StdinDevNull(t *testing.T) {
	ctx := context.Background()
	opts := fakeAnswerCommandOptions("verify_stdin")
	ans, err := RunAnswerCommand(ctx, opts)
	if err != nil {
		t.Fatalf("RunAnswerCommand verify_stdin failed: %v", err)
	}
	if string(ans) != "stdin-is-eof" {
		t.Fatalf("got %q, want %q", string(ans), "stdin-is-eof")
	}
}

func TestRunAnswerCommand_EnvironmentVariables(t *testing.T) {
	opts := fakeAnswerCommandOptions("verify_env")
	opts.Node = "node-alpha"
	opts.Host = "10.0.0.1"
	opts.User = "devops"
	opts.Identity = "jumpbox"
	// 测试 ANSI 转义清洗：\x1b[31m 与 \r 应当被清洗
	opts.Prompt = "\x1b[31mVerification Code:\x1b[0m\r"
	opts.Instruction = "\x1b[1mEnter TOTP\x1b[0m"
	opts.Echo = true
	opts.NonInteractive = true

	ans, err := RunAnswerCommand(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunAnswerCommand verify_env failed: %v", err)
	}
	if string(ans) != "env-ok" {
		t.Fatalf("got %q, want %q", string(ans), "env-ok")
	}

	// 测试 credential.WithoutInteraction(ctx) 自动使 XOPS_NON_INTERACTIVE 变为 "1"
	opts.NonInteractive = false
	ctxNoInteraction := credential.WithoutInteraction(context.Background())
	ans2, err := RunAnswerCommand(ctxNoInteraction, opts)
	if err != nil {
		t.Fatalf("RunAnswerCommand with context interaction disabled failed: %v", err)
	}
	if string(ans2) != "env-ok" {
		t.Fatalf("got %q, want %q", string(ans2), "env-ok")
	}
}

func TestRunAnswerCommand_TimeoutAndCancel(t *testing.T) {
	// 1. 超时终止进程树
	opts := fakeAnswerCommandOptions("hang")
	opts.Timeout = 100 * time.Millisecond
	_, err := RunAnswerCommand(context.Background(), opts)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out after") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 2. 外部 Context 取消
	opts.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err = RunAnswerCommand(ctx, opts)
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("expected canceled error, got: %v", err)
	}
}

func TestRunAnswerCommand_OutputTruncation(t *testing.T) {
	ctx := context.Background()
	opts := fakeAnswerCommandOptions("huge_output")
	ans, err := RunAnswerCommand(ctx, opts)
	if err != nil {
		t.Fatalf("RunAnswerCommand huge_output failed: %v", err)
	}
	if len(ans) != MaxAnswerStdoutBytes {
		t.Fatalf("expected output length %d, got %d", MaxAnswerStdoutBytes, len(ans))
	}
	if !bytes.Equal(ans, bytes.Repeat([]byte("A"), MaxAnswerStdoutBytes)) {
		t.Fatalf("unexpected truncated output content")
	}
}

func TestRunAnswerCommand_CrashAndStderrSanitization(t *testing.T) {
	ctx := context.Background()
	opts := fakeAnswerCommandOptions("crash")
	_, err := RunAnswerCommand(ctx, opts)
	if err == nil {
		t.Fatalf("expected error on crash")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "[REDACTED]") {
		t.Fatalf("expected sensitive Base64 to be redacted in stderr, got: %s", errMsg)
	}
	if strings.Contains(errMsg, "dXNlcm5hbWU6cGFzc3dvcmQxMjM=") {
		t.Fatalf("sensitive token leaked in error message: %s", errMsg)
	}
}

func TestRunAnswerCommand_Validation(t *testing.T) {
	// 空命令
	_, err := RunAnswerCommand(context.Background(), AnswerCommandOptions{})
	if err == nil || !strings.Contains(err.Error(), "command is empty") {
		t.Fatalf("expected empty command error, got: %v", err)
	}

	// 不存在的可执行文件
	_, err = RunAnswerCommand(context.Background(), AnswerCommandOptions{
		Command: "non_existent_executable_12345",
	})
	if err == nil || !strings.Contains(err.Error(), "executable not found") {
		t.Fatalf("expected executable not found error, got: %v", err)
	}
}
