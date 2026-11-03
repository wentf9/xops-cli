package adapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/credentialhelper"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

// TestAdversarialAdapterCommandHelperProcess 提供对抗性子进程桩。
func TestAdversarialAdapterCommandHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_ADVERSARIAL_ADAPTER_HELPER") != "1" {
		return
	}
	mode := os.Getenv("ADV_ADAPTER_HELPER_MODE")
	switch mode {
	case "timeout_hang":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "exit_error":
		_, _ = fmt.Fprintln(os.Stderr, "command execution failed with status 42")
		os.Exit(42)
	case "long_output":
		// 输出 10000 字节数据
		data := append(bytes.Repeat([]byte("Z"), 10000), '\n')
		_, _ = os.Stdout.Write(data)
		os.Exit(0)
	case "verify_isolation":
		// 校验外部污染的 XOPS_INJECTED_LEAK 变量已被清除
		if val, exists := os.LookupEnv("XOPS_INJECTED_LEAK"); exists {
			_, _ = fmt.Fprintf(os.Stderr, "leaked env var detected: XOPS_INJECTED_LEAK=%q\n", val)
			os.Exit(1)
		}
		// 校验预期的受控注入变量
		expected := map[string]string{
			"XOPS_NODE":            "node-adv",
			"XOPS_HOST":            "127.0.0.1",
			"XOPS_USER":            "adv-user",
			"XOPS_IDENTITY":        "id1",
			"XOPS_PROMPT":          "Enter OTP Token:",
			"XOPS_INSTRUCTION":     "MFA Protected",
			"XOPS_ECHO":            "false",
			"XOPS_NON_INTERACTIVE": "0",
		}
		for k, want := range expected {
			got := os.Getenv(k)
			if got != want {
				_, _ = fmt.Fprintf(os.Stderr, "env %s: got %q, want %q\n", k, got, want)
				os.Exit(2)
			}
		}
		fmt.Println("isolation-verified")
		os.Exit(0)
	default:
		os.Exit(99)
	}
}

func fakeAdversarialCommandOptions(mode string, timeout time.Duration) (string, []string, time.Duration) {
	return os.Args[0], []string{"-test.run=^TestAdversarialAdapterCommandHelperProcess$", "--"}, timeout
}

// TestAdversarial_Adapter_AntiLoopStress 测试 Attempt = 2, 3, 5, 100 对抗性防循环逻辑
func TestAdversarial_Adapter_AntiLoopStress(t *testing.T) {
	ctx := context.Background()

	// 1. SecretKindOTP 防循环
	t.Run("OTP_AntiLoop_Attempts", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User:     "ops",
			AuthType: "otp",
			OTP: &models.OTPConfig{
				TOTPSecretRef: &credential.Ref{StoreID: "default", ItemID: "totp-seed"},
			},
		})
		store := &adapterCredentialStore{data: map[string]credential.Secret{
			"totp-seed": credential.NewSecret([]byte("JBSWY3DPEHPK3PXP")),
		}}
		reg := credential.NewRegistry()
		_ = reg.Register("default", store)
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg),
			WithCredentialSource(reg),
			WithSessionAuthOverride("node1", SessionAuth{OTP: "123456"}),
		)

		for _, attempt := range []int{2, 3, 5, 10, 100} {
			_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
				Kind:    ssh.SecretKindOTP,
				NodeID:  "node1",
				Attempt: attempt,
			})
			if !errors.Is(err, ssh.ErrInteractionRequired) {
				t.Fatalf("attempt %d: expected ErrInteractionRequired, got %v", attempt, err)
			}
		}
	})

	// 2. SecretKindKeyboardInteractive 各类来源防循环
	t.Run("KeyboardInteractive_AntiLoop_AllSources", func(t *testing.T) {
		sources := []struct {
			name   string
			source models.ChallengeAnswerSource
		}{
			{"LoginPassword", models.ChallengeSourceLoginPassword},
			{"OTP", models.ChallengeSourceOTP},
			{"Secret", models.ChallengeSourceSecret},
			{"Command", models.ChallengeSourceCommand},
		}

		for _, s := range sources {
			t.Run(s.name, func(t *testing.T) {
				cfg := newTestAdapterConfig("node1", models.Identity{
					User:     "ops",
					Password: "login-pass",
					OTP: &models.OTPConfig{
						TOTPSecretRef: &credential.Ref{StoreID: "default", ItemID: "seed"},
					},
					KeyboardInteractive: &models.KeyboardInteractiveConfig{
						Rules: []models.ChallengeRule{
							{
								Name:          "rule-" + s.name,
								PromptPattern: ".*",
								Source:        s.source,
								SecretRef:     &credential.Ref{StoreID: "default", ItemID: "item"},
								Command:       "echo",
							},
						},
					},
				})
				store := &adapterCredentialStore{data: map[string]credential.Secret{
					"seed": credential.NewSecret([]byte("JBSWY3DPEHPK3PXP")),
					"item": credential.NewSecret([]byte("secret-ans")),
				}}
				reg := credential.NewRegistry()
				_ = reg.Register("default", store)
				adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg), WithCredentialSource(reg))

				for _, attempt := range []int{2, 3, 5, 20} {
					_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
						Kind:    ssh.SecretKindKeyboardInteractive,
						NodeID:  "node1",
						Prompt:  "Enter token:",
						Attempt: attempt,
					})
					if !errors.Is(err, ssh.ErrInteractionRequired) {
						t.Fatalf("source %s attempt %d: expected ErrInteractionRequired, got %v", s.name, attempt, err)
					}
				}
			})
		}
	})
}

// TestAdversarial_Adapter_RegexEdgeCases 测试正则编译错误、空 prompt、规则穿透等极端边界
func TestAdversarial_Adapter_RegexEdgeCases(t *testing.T) {
	ctx := context.Background()

	// 1. 畸形 PromptPattern
	t.Run("MalformedPromptPattern_ReturnsError", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:          "bad-regex",
						PromptPattern: "[unclosed-bracket(",
						Source:        models.ChallengeSourceLoginPassword,
					},
				},
			},
			Password: "pass",
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "test prompt",
			Attempt: 1,
		})
		if err == nil || !strings.Contains(err.Error(), "invalid prompt pattern") {
			t.Fatalf("expected invalid prompt pattern error, got: %v", err)
		}
	})

	// 2. 畸形 InstructionPattern
	t.Run("MalformedInstructionPattern_ReturnsError", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:               "bad-instruction-regex",
						PromptPattern:      ".*",
						InstructionPattern: "*illegal-start-re*",
						Source:             models.ChallengeSourceLoginPassword,
					},
				},
			},
			Password: "pass",
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:        ssh.SecretKindKeyboardInteractive,
			NodeID:      "node1",
			Prompt:      "test prompt",
			Instruction: "test instruction",
			Attempt:     1,
		})
		if err == nil || !strings.Contains(err.Error(), "invalid instruction pattern") {
			t.Fatalf("expected invalid instruction pattern error, got: %v", err)
		}
	})

	// 3. 畸形 OTP PromptPattern
	t.Run("MalformedOTPPromptPattern_ReturnsError", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			OTP: &models.OTPConfig{
				PromptPattern: "(?P<incomplete",
			},
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "test prompt",
			Attempt: 1,
		})
		if err == nil || !strings.Contains(err.Error(), "invalid otp prompt pattern") {
			t.Fatalf("expected invalid otp prompt pattern error, got: %v", err)
		}
	})

	// 4. 空 Prompt 匹配边界
	t.Run("EmptyPrompt_Handling", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:          "match-empty-prompt",
						PromptPattern: "^$",
						Source:        models.ChallengeSourceLoginPassword,
					},
				},
			},
			Password: "empty-prompt-pass",
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))

		// 空 Prompt 应当匹配 ^$
		ans, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "",
			Attempt: 1,
		})
		if err != nil || string(ans) != "empty-prompt-pass" {
			t.Fatalf("expected 'empty-prompt-pass', got ans=%q, err=%v", string(ans), err)
		}

		// 非空 Prompt 不匹配 ^$ -> 降级为 ErrInteractionRequired
		_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "not-empty",
			Attempt: 1,
		})
		if !errors.Is(err, ssh.ErrInteractionRequired) {
			t.Fatalf("expected ErrInteractionRequired for non-empty prompt against ^$, got: %v", err)
		}
	})

	// 5. 不匹配规则穿透至 Explicit OTP Fallback
	t.Run("RuleMiss_FallsThroughToExplicitOTP", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			OTP: &models.OTPConfig{
				TOTPSecretRef: &credential.Ref{StoreID: "default", ItemID: "seed"},
				PromptPattern: "(?i)otp",
			},
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:          "strict-password-rule",
						PromptPattern: "^Password:",
						Source:        models.ChallengeSourceLoginPassword,
					},
				},
			},
		})
		store := &adapterCredentialStore{data: map[string]credential.Secret{
			"seed": credential.NewSecret([]byte("JBSWY3DPEHPK3PXP")),
		}}
		reg := credential.NewRegistry()
		_ = reg.Register("default", store)
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg), WithCredentialSource(reg))

		// 匹配第一个规则 -> 不穿透
		// 不匹配第一个规则但匹配 OTP PromptPattern -> 成功穿透至 OTP
		ans, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "Enter OTP code:",
			Attempt: 1,
		})
		if err != nil {
			t.Fatalf("expected successful OTP fallback, got %v", err)
		}
		if len(ans) != 6 {
			t.Fatalf("expected 6-digit OTP from fallback, got %q", string(ans))
		}

		// 两者都不匹配 -> ErrInteractionRequired
		_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "Random challenge:",
			Attempt: 1,
		})
		if !errors.Is(err, ssh.ErrInteractionRequired) {
			t.Fatalf("expected ErrInteractionRequired on full miss, got %v", err)
		}
	})

	// 6. 未知 / 非法 Challenge Answer Source
	t.Run("UnknownChallengeAnswerSource_FailsCleanly", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:          "unknown-source-rule",
						PromptPattern: ".*",
						Source:        models.ChallengeAnswerSource("telepathy"),
					},
				},
			},
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "Think your answer:",
			Attempt: 1,
		})
		if err == nil || !strings.Contains(err.Error(), "unsupported challenge answer source") {
			t.Fatalf("expected unsupported source error, got: %v", err)
		}
	})

	// 7. Secret 来源但 SecretRef 为 nil 或空
	t.Run("SourceSecret_NilRef_ReturnsError", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:          "empty-secret-ref-rule",
						PromptPattern: ".*",
						Source:        models.ChallengeSourceSecret,
						SecretRef:     nil,
					},
				},
			},
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "Enter token:",
			Attempt: 1,
		})
		if err == nil || !strings.Contains(err.Error(), "secret_ref is empty") {
			t.Fatalf("expected secret_ref is empty error, got: %v", err)
		}
	})

	// 8. Command 来源但 Command 为空字符串
	t.Run("SourceCommand_EmptyCommand_ReturnsError", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:          "empty-command-rule",
						PromptPattern: ".*",
						Source:        models.ChallengeSourceCommand,
						Command:       "   ",
					},
				},
			},
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "Enter token:",
			Attempt: 1,
		})
		if err == nil || !strings.Contains(err.Error(), "command is empty") {
			t.Fatalf("expected command is empty error, got: %v", err)
		}
	})
}

// TestAdversarial_Adapter_OTPCommandExecution 测试 OTP 外部命令执行：超时、非零退出、长输出截断与环境隔离
func TestAdversarial_Adapter_OTPCommandExecution(t *testing.T) {
	ctx := context.Background()

	// 1. 命令超时
	t.Run("Timeout_KillsProcessTree", func(t *testing.T) {
		t.Setenv("GO_WANT_ADVERSARIAL_ADAPTER_HELPER", "1")
		t.Setenv("ADV_ADAPTER_HELPER_MODE", "timeout_hang")

		cmd, args, _ := fakeAdversarialCommandOptions("timeout_hang", 100*time.Millisecond)
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			OTP: &models.OTPConfig{
				Command: cmd,
				Args:    args,
				Timeout: 100 * time.Millisecond,
			},
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:   ssh.SecretKindOTP,
			NodeID: "node1",
		})
		if err == nil || !strings.Contains(err.Error(), "timed out after") {
			t.Fatalf("expected timed out after error, got: %v", err)
		}
	})

	// 2. 非零退出码与诊断信息脱敏
	t.Run("NonZeroExit_ReturnsSanitizedError", func(t *testing.T) {
		t.Setenv("GO_WANT_ADVERSARIAL_ADAPTER_HELPER", "1")
		t.Setenv("ADV_ADAPTER_HELPER_MODE", "exit_error")

		cmd, args, _ := fakeAdversarialCommandOptions("exit_error", 5*time.Second)
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			OTP: &models.OTPConfig{
				Command: cmd,
				Args:    args,
				Timeout: 5 * time.Second,
			},
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		_, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:   ssh.SecretKindOTP,
			NodeID: "node1",
		})
		if err == nil || !strings.Contains(err.Error(), "command execution failed with status 42") {
			t.Fatalf("expected error with stderr message, got: %v", err)
		}
	})

	// 3. 超长输出（10000 字节）被上限截断为 4096 字节
	t.Run("LongOutput_TruncatedTo4096Bytes", func(t *testing.T) {
		t.Setenv("GO_WANT_ADVERSARIAL_ADAPTER_HELPER", "1")
		t.Setenv("ADV_ADAPTER_HELPER_MODE", "long_output")

		cmd, args, _ := fakeAdversarialCommandOptions("long_output", 5*time.Second)
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			OTP: &models.OTPConfig{
				Command: cmd,
				Args:    args,
				Timeout: 5 * time.Second,
			},
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		ans, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:   ssh.SecretKindOTP,
			NodeID: "node1",
		})
		if err != nil {
			t.Fatalf("expected success with truncated output, got: %v", err)
		}
		if len(ans) != credentialhelper.MaxAnswerStdoutBytes {
			t.Fatalf("expected exactly %d bytes, got %d", credentialhelper.MaxAnswerStdoutBytes, len(ans))
		}
		if !bytes.Equal(ans, bytes.Repeat([]byte("Z"), credentialhelper.MaxAnswerStdoutBytes)) {
			t.Fatalf("unexpected truncated output contents")
		}
	})

	// 4. 环境变量隔离：父进程注入的 XOPS_* 变量被剔除，只有合法的 XOPS_* 上下文注入
	t.Run("EnvironmentVariable_Isolation", func(t *testing.T) {
		t.Setenv("GO_WANT_ADVERSARIAL_ADAPTER_HELPER", "1")
		t.Setenv("ADV_ADAPTER_HELPER_MODE", "verify_isolation")
		// 模拟父进程受污染的非法 XOPS_* 变量
		t.Setenv("XOPS_INJECTED_LEAK", "malicious_injected_secret")

		cmd, args, _ := fakeAdversarialCommandOptions("verify_isolation", 5*time.Second)
		cfg := newTestAdapterConfig("node-adv", models.Identity{
			User: "adv-user",
			OTP: &models.OTPConfig{
				Command: cmd,
				Args:    args,
				Timeout: 5 * time.Second,
			},
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg))
		ans, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:        ssh.SecretKindOTP,
			NodeID:      "node-adv",
			Prompt:      "Enter OTP Token:",
			Instruction: "MFA Protected",
			Echo:        false,
		})
		if err != nil {
			t.Fatalf("expected successful isolated execution, got: %v", err)
		}
		if string(ans) != "isolation-verified" {
			t.Fatalf("got %q, want 'isolation-verified'", string(ans))
		}
	})
}

// TestAdversarial_Adapter_SessionOverridePriority 测试 --otp 会话级覆盖始终优先于持久化配置 (TOTPSecretRef 与 Command)
func TestAdversarial_Adapter_SessionOverridePriority(t *testing.T) {
	ctx := context.Background()

	// 1. 节点覆盖优先于配置的 TOTPSecretRef
	t.Run("Override_Precedes_TOTPSecretRef", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User:     "ops",
			AuthType: "otp",
			OTP: &models.OTPConfig{
				TOTPSecretRef: &credential.Ref{StoreID: "default", ItemID: "seed"},
			},
		})
		store := &adapterCredentialStore{data: map[string]credential.Secret{
			"seed": credential.NewSecret([]byte("JBSWY3DPEHPK3PXP")),
		}}
		reg := credential.NewRegistry()
		_ = reg.Register("default", store)

		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg),
			WithCredentialSource(reg),
			WithSessionAuthOverride("node1", SessionAuth{OTP: "override-otp-111"}),
		)

		otp, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:   ssh.SecretKindOTP,
			NodeID: "node1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(otp) != "override-otp-111" {
			t.Fatalf("expected override OTP 'override-otp-111', got %q", string(otp))
		}
	})

	// 2. 节点覆盖优先于配置的 Command
	t.Run("Override_Precedes_ExternalCommand", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User:     "ops",
			AuthType: "otp",
			OTP: &models.OTPConfig{
				Command: "/non/existent/failing/command/path",
			},
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg),
			WithSessionAuthOverride("node1", SessionAuth{OTP: "override-otp-222"}),
		)

		otp, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:   ssh.SecretKindOTP,
			NodeID: "node1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(otp) != "override-otp-222" {
			t.Fatalf("expected override OTP 'override-otp-222', got %q", string(otp))
		}
	})

	// 3. 节点特定覆盖优先于全局覆盖 (GlobalSessionAuth)
	t.Run("NodeOverride_Precedes_GlobalOverride", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{User: "ops", AuthType: "otp"})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg),
			WithGlobalSessionAuth(SessionAuth{OTP: "global-otp-888"}),
			WithSessionAuthOverride("node1", SessionAuth{OTP: "node-specific-otp-999"}),
		)

		otp, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:   ssh.SecretKindOTP,
			NodeID: "node1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(otp) != "node-specific-otp-999" {
			t.Fatalf("expected node-specific override, got %q", string(otp))
		}
	})

	// 4. KeyboardInteractive 中 Rule Source 为 OTP 时，Override 优先于配置的 TOTP
	t.Run("KeyboardInteractive_RuleSourceOTP_RespectsOverride", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			OTP: &models.OTPConfig{
				TOTPSecretRef: &credential.Ref{StoreID: "default", ItemID: "seed"},
			},
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:          "rule-otp",
						PromptPattern: ".*",
						Source:        models.ChallengeSourceOTP,
					},
				},
			},
		})
		store := &adapterCredentialStore{data: map[string]credential.Secret{
			"seed": credential.NewSecret([]byte("JBSWY3DPEHPK3PXP")),
		}}
		reg := credential.NewRegistry()
		_ = reg.Register("default", store)

		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg),
			WithCredentialSource(reg),
			WithSessionAuthOverride("node1", SessionAuth{OTP: "ki-override-otp-777"}),
		)

		ans, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "Enter OTP:",
			Attempt: 1,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(ans) != "ki-override-otp-777" {
			t.Fatalf("expected 'ki-override-otp-777', got %q", string(ans))
		}
	})

	// 5. KeyboardInteractive 中没有任何规则匹配时，Override 兜底成功
	t.Run("KeyboardInteractive_NoRuleMatched_FallbackToOverride", func(t *testing.T) {
		cfg := newTestAdapterConfig("node1", models.Identity{
			User: "ops",
			KeyboardInteractive: &models.KeyboardInteractiveConfig{
				Rules: []models.ChallengeRule{
					{
						Name:          "strict-rule",
						PromptPattern: "^PIN:",
						Source:        models.ChallengeSourceLoginPassword,
					},
				},
			},
			Password: "pass",
		})
		adp := NewSSHAdapter(config.NewProviderWithoutOpenSSH(cfg),
			WithSessionAuthOverride("node1", SessionAuth{OTP: "ki-fallback-override-555"}),
		)

		ans, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
			Kind:    ssh.SecretKindKeyboardInteractive,
			NodeID:  "node1",
			Prompt:  "Server MFA Challenge:",
			Attempt: 1,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(ans) != "ki-fallback-override-555" {
			t.Fatalf("expected 'ki-fallback-override-555', got %q", string(ans))
		}
	})
}
