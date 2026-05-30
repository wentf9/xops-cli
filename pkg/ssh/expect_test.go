package ssh

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestExpect_PasswordPrompt_English(t *testing.T) {
	var stdin bytes.Buffer
	expect := NewExpect(&stdin, ExpectRule{
		Pattern: regexp.MustCompile(DefaultPasswordPromptPattern),
		Respond: StaticRespond("mysecret"),
	})

	_, err := expect.Write([]byte("Password: "))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if !strings.Contains(stdin.String(), "mysecret\n") {
		t.Errorf("expected password to be sent, got: %q", stdin.String())
	}
}

func TestExpect_PasswordPrompt_Chinese(t *testing.T) {
	var stdin bytes.Buffer
	expect := NewExpect(&stdin, ExpectRule{
		Pattern: regexp.MustCompile(DefaultPasswordPromptPattern),
		Respond: StaticRespond("mysecret"),
	})

	_, _ = expect.Write([]byte("请输入密码："))

	if !strings.Contains(stdin.String(), "mysecret\n") {
		t.Errorf("expected password to be sent, got: %q", stdin.String())
	}
}

func TestExpect_PasswordPrompt_French(t *testing.T) {
	var stdin bytes.Buffer
	expect := NewExpect(&stdin, ExpectRule{
		Pattern: regexp.MustCompile(DefaultPasswordPromptPattern),
		Respond: StaticRespond("frenchpass"),
	})

	_, _ = expect.Write([]byte("Mot de passe : "))

	if !strings.Contains(stdin.String(), "frenchpass\n") {
		t.Errorf("expected password to be sent, got: %q", stdin.String())
	}
}

func TestExpect_PasswordPrompt_SplitRead(t *testing.T) {
	var stdin bytes.Buffer
	expect := NewExpect(&stdin, ExpectRule{
		Pattern: regexp.MustCompile(DefaultPasswordPromptPattern),
		Respond: StaticRespond("splitpass"),
	})

	// 分两次写入，模拟 TCP 拆包
	_, _ = expect.Write([]byte("Pass"))
	_, _ = expect.Write([]byte("word: "))

	if !strings.Contains(stdin.String(), "splitpass\n") {
		t.Errorf("accumulated buffer should match split prompt, got: %q", stdin.String())
	}
}

func TestExpect_Timeout(t *testing.T) {
	var stdin bytes.Buffer
	expect := NewExpect(&stdin, ExpectRule{
		Pattern: regexp.MustCompile(DefaultPasswordPromptPattern),
		Respond: StaticRespond("irrelevant"),
	})

	_, _ = expect.Write([]byte("some output without prompt"))

	// 此时不会匹配，调用 Wait 应该超时
	err := expect.Wait(context.Background(), 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestExpect_ContextCancel(t *testing.T) {
	var stdin bytes.Buffer
	expect := NewExpect(&stdin, ExpectRule{
		Pattern: regexp.MustCompile(DefaultPasswordPromptPattern),
		Respond: StaticRespond("irrelevant"),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	err := expect.Wait(ctx, 5*time.Second)
	if err == nil {
		t.Fatal("expected context cancel error, got nil")
	}
}

func TestExpect_CustomPattern(t *testing.T) {
	var stdin bytes.Buffer
	customPattern := regexp.MustCompile(`^>>> `)
	expect := NewExpect(&stdin, ExpectRule{
		Pattern: customPattern,
		Respond: StaticRespond("customresp"),
	})

	_, _ = expect.Write([]byte(">>> "))

	if !strings.Contains(stdin.String(), "customresp\n") {
		t.Errorf("expected custom response, got: %q", stdin.String())
	}
}

func TestExpect_MultiStage(t *testing.T) {
	var stdin bytes.Buffer
	expect := NewExpect(&stdin,
		ExpectRule{
			Pattern: regexp.MustCompile(`(?i)password\s*:`),
			Respond: StaticRespond("stage1"),
		},
		ExpectRule{
			Pattern: regexp.MustCompile(`(?i)confirm\s*:`),
			Respond: StaticRespond("stage2"),
		},
	)

	_, _ = expect.Write([]byte("Password: done\nConfirm: "))

	out := stdin.String()
	if !strings.Contains(out, "stage1\n") {
		t.Errorf("expected stage1 response, got: %q", out)
	}
	if !strings.Contains(out, "stage2\n") {
		t.Errorf("expected stage2 response, got: %q", out)
	}
}

func TestExpect_CleanOutput(t *testing.T) {
	var stdin bytes.Buffer
	promptRe := regexp.MustCompile(DefaultPasswordPromptPattern)
	expect := NewExpect(&stdin, ExpectRule{
		Pattern: promptRe,
		Respond: StaticRespond("pass"),
	})
	expect.SetAccumulate(true) // 开启缓冲以便后续调用 CleanOutput

	_, _ = expect.Write([]byte("Password: \nsome real output\n"))

	cleaned := expect.CleanOutput(promptRe)

	if strings.Contains(cleaned, "Password:") {
		t.Errorf("CleanOutput should remove prompt line, got: %q", cleaned)
	}
	if !strings.Contains(cleaned, "some real output") {
		t.Errorf("CleanOutput should preserve real output, got: %q", cleaned)
	}
}

func TestExpect_NoRules(t *testing.T) {
	var stdin bytes.Buffer
	expect := NewExpect(&stdin) // 无规则
	_, _ = expect.Write([]byte("any output"))

	err := expect.Wait(context.Background(), 2*time.Second)
	if err != nil {
		t.Fatalf("expected nil for no-rule Expect, got: %v", err)
	}
}

func TestStaticRespond(t *testing.T) {
	fn := StaticRespond("hello")
	got, err := fn()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello" {
		t.Errorf("expected 'hello', got: %q", got)
	}
}
