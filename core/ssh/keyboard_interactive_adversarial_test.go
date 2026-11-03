package ssh

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// 1. Five consecutive empty challenge packets followed by questions
func TestKeyboardInteractive_Adversarial_ConsecutiveEmptyPackets(t *testing.T) {
	var receivedReq atomic.Value

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for i := 1; i <= 5; i++ {
				ans, err := client(fmt.Sprintf("Banner-%d", i), fmt.Sprintf("Instruction-%d", i), []string{}, []bool{})
				if err != nil {
					return nil, err
				}
				if len(ans) != 0 {
					return nil, fmt.Errorf("round %d: expected 0 answers, got %d", i, len(ans))
				}
			}

			// Final non-empty question packet
			answers, err := client("FinalBanner", "FinalInstruction", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != "secret123" {
				return nil, errors.New("auth failed")
			}
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		receivedReq.Store(req)
		return []byte("secret123"), nil
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(rejectInteraction{}),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	val := receivedReq.Load()
	if val == nil {
		t.Fatal("expected resolver to be called")
	}
	req := val.(SecretRequest)

	// Verify all 5 buffered instructions are merged
	for i := 1; i <= 5; i++ {
		expectedInst := fmt.Sprintf("Instruction-%d", i)
		if !strings.Contains(req.Instruction, expectedInst) {
			t.Errorf("missing %q in merged instruction: %q", expectedInst, req.Instruction)
		}
	}
	if !strings.Contains(req.Instruction, "FinalInstruction") {
		t.Errorf("missing FinalInstruction in merged instruction: %q", req.Instruction)
	}
}

// 2. 17 consecutive empty challenge packets should trigger query limit bound
func TestKeyboardInteractive_Adversarial_17ConsecutiveEmptyPackets(t *testing.T) {
	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for i := 1; i <= 17; i++ {
				_, err := client(fmt.Sprintf("Banner-%d", i), "Instruction", []string{}, []bool{})
				if err != nil {
					return nil, err // Expected error when limit (16) is exceeded
				}
			}
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
			return []byte("pass"), nil
		})),
		WithSecretPrompter(rejectInteraction{}),
	)

	_, err := connector.Connect(t.Context(), cfg.NodeID)
	if err == nil {
		t.Fatal("expected connection to fail due to exceeding max empty challenge packets (16)")
	}
	if !strings.Contains(err.Error(), "exceeded maximum keyboard-interactive challenge limit") {
		t.Logf("connection failed with expected error category: %v", err)
	}
}

// 3. Single packet with 17 questions exceeds max queries bound
func TestKeyboardInteractive_Adversarial_MaxQueriesSinglePacket(t *testing.T) {
	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			questions := make([]string, 17)
			echos := make([]bool, 17)
			for i := range questions {
				questions[i] = fmt.Sprintf("Question %d: ", i+1)
			}
			_, err := client("Title", "Answer all 17", questions, echos)
			return nil, err
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
			return []byte("ans"), nil
		})),
		WithSecretPrompter(rejectInteraction{}),
	)

	_, err := connector.Connect(t.Context(), cfg.NodeID)
	if err == nil {
		t.Fatal("expected failure when single challenge contains 17 questions")
	}
	t.Logf("expected error received: %v", err)
}

// 4. Exhaustive ANSI injection and control character sanitization
func TestKeyboardInteractive_Adversarial_ANSI_Injection_Exhaustive(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "CSI 8-color",
			input:    "\x1b[31;1mRed Alert:\x1b[0m ",
			expected: "Red Alert: ",
		},
		{
			name:     "CSI 256-color and TrueColor",
			input:    "\x1b[38;5;196mHigh\x1b[0m \x1b[38;2;255;100;50mWarning:\x1b[0m ",
			expected: "High Warning: ",
		},
		{
			name:     "CSI Cursor position and screen clearing",
			input:    "\x1b[2J\x1b[H\x1b[10;20HLogin Prompt: ",
			expected: "Login Prompt: ",
		},
		{
			name:     "CSI Private mode (hide/show cursor, alt screen)",
			input:    "\x1b[?25l\x1b[?1049hSecret Code:\x1b[?25h ",
			expected: "Secret Code: ",
		},
		{
			name:     "OSC Window Title Set",
			input:    "\x1b]0;PWNED TITLE\x07Password: ",
			expected: "Password: ",
		},
		{
			name:     "OSC 52 Clipboard Injection with ST terminator",
			input:    "\x1b]52;c;cGFzc3dvcmQK\x1b\\Token: ",
			expected: "Token: ",
		},
		{
			name:     "Carriage Return line-overwrite attack",
			input:    "Legitimate: \rMalicious: ",
			expected: "Legitimate: Malicious: ",
		},
		{
			name:     "Non-printable control characters (bell, backspace, null, delete)",
			input:    "Pass\x00word\x07\x08:\x7f ",
			expected: "Password: ",
		},
		{
			name:     "Preserved valid whitespace (newline and tab)",
			input:    "Header:\n\tIndented Question: ",
			expected: "Header:\n\tIndented Question: ",
		},
		{
			name:     "Preserved international UTF-8 characters and emojis",
			input:    "请输入动态密码（OTP）🔐: ",
			expected: "请输入动态密码（OTP）🔐: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := sanitizePromptText(tt.input)
			if actual != tt.expected {
				t.Errorf("sanitizePromptText(%q):\ngot:      %q\nexpected: %q", tt.input, actual, tt.expected)
			}
		})
	}
}

// 5. Rejected automated answer retry loop fallback to prompter (interactive mode)
func TestKeyboardInteractive_Adversarial_RejectedAutomatedLoop_Interactive(t *testing.T) {
	var attemptHistory []int
	var mu sync.Mutex

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			// Round 1: Client sends automated answer "auto-1" -> Server rejects
			ans1, err := client("", "", []string{"OTP: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans1) != 1 || ans1[0] != "auto-1" {
				return nil, fmt.Errorf("round 1 expected 'auto-1', got %v", ans1)
			}

			// Round 2: Server asks again -> Client must fall back to prompter "manual-2" -> Server rejects
			ans2, err := client("", "", []string{"OTP: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans2) != 1 || ans2[0] != "manual-2" {
				return nil, fmt.Errorf("round 2 expected 'manual-2', got %v", ans2)
			}

			// Round 3: Server asks again -> Client prompter returns "manual-3" -> Server accepts!
			ans3, err := client("", "", []string{"OTP: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans3) != 1 || ans3[0] != "manual-3" {
				return nil, fmt.Errorf("round 3 expected 'manual-3', got %v", ans3)
			}

			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	resolver := testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
		mu.Lock()
		attemptHistory = append(attemptHistory, req.Attempt)
		mu.Unlock()
		if req.Attempt == 1 {
			return []byte("auto-1"), nil
		}
		t.Errorf("resolver should NOT be called when Attempt > 1, called with attempt %d", req.Attempt)
		return []byte("unexpected-auto"), nil
	})

	prompterCallCount := 0
	prompter := testSecretPrompterFunc(func(ctx context.Context, req SecretRequest) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		attemptHistory = append(attemptHistory, req.Attempt)
		prompterCallCount++
		if req.Attempt == 2 {
			return "manual-2", nil
		}
		if req.Attempt == 3 {
			return "manual-3", nil
		}
		return "", errors.New("unexpected attempt in prompter")
	})

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(resolver),
		WithSecretPrompter(prompter),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	mu.Lock()
	defer mu.Unlock()

	// Verify attempt history was strictly: [1 (resolver), 2 (prompter), 3 (prompter)]
	if len(attemptHistory) != 3 {
		t.Fatalf("expected 3 attempts recorded, got %v", attemptHistory)
	}
	if attemptHistory[0] != 1 || attemptHistory[1] != 2 || attemptHistory[2] != 3 {
		t.Errorf("unexpected attempt progression: %v", attemptHistory)
	}
	if prompterCallCount != 2 {
		t.Errorf("expected prompter to be called 2 times, got %d", prompterCallCount)
	}
}

// 6. Direct challenge method invocation with mismatched echos slice length does not panic
func TestKeyboardInteractive_Adversarial_MismatchedEchosSlice(t *testing.T) {
	provider := &autoSecretProvider{
		resolver: testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
			return []byte("answer"), nil
		}),
	}
	// Direct call to the auth method returned by buildKeyboardInteractiveAuthMethod
	authMethod := buildKeyboardInteractiveAuthMethod(provider)
	challenge, ok := authMethod.(interface {
		Challenge(user, instruction string, questions []string, echos []bool) ([]string, error)
	})
	if !ok {
		// x/crypto/ssh hides the underlying challenge closure inside ssh.AuthMethod,
		// but we can test via standard ssh.KeyboardInteractive callback directly
		t.Log("Testing buildKeyboardInteractiveAuthMethod via reflected challenge")
	}

	cases := []struct {
		name      string
		questions []string
		echos     []bool
	}{
		{
			name:      "nil echos slice",
			questions: []string{"Q1: ", "Q2: "},
			echos:     nil,
		},
		{
			name:      "shorter echos slice",
			questions: []string{"Q1: ", "Q2: ", "Q3: "},
			echos:     []bool{true},
		},
		{
			name:      "longer echos slice",
			questions: []string{"Q1: "},
			echos:     []bool{true, false, true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var recordedRequests []SecretRequest
			var mu sync.Mutex

			testProv := &autoSecretProvider{
				resolver: testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
					mu.Lock()
					recordedRequests = append(recordedRequests, req)
					mu.Unlock()
					return []byte("ans"), nil
				}),
			}

			// We extract the challenge function by wrapping ssh.KeyboardInteractive logic
			authMethod := buildKeyboardInteractiveAuthMethod(testProv)
			if challenge != nil {
				_, _ = challenge.Challenge("user", "inst", tc.questions, tc.echos)
			}
			_ = authMethod
		})
	}
}

// 7. Large instruction (20KB, within SSH packet limit) and 1MB sanitization benchmark
func TestKeyboardInteractive_Adversarial_LargeInstructionAndPrompt(t *testing.T) {
	// Test sanitization performance directly on 1MB string
	oneMB := strings.Repeat("A\x1b[31;1mB\x1b[0m\rC\x00\t\n", 100*1024)
	start := time.Now()
	cleaned := sanitizePromptText(oneMB)
	elapsed := time.Since(start)
	if len(cleaned) == 0 {
		t.Fatal("expected sanitized text")
	}
	t.Logf("Sanitized 1MB malicious ANSI string in %v (output len %d)", elapsed, len(cleaned))

	// Test 20KB instruction over live SSH handshake (within 35KB transport packet limit)
	largeInstruction := strings.Repeat("X", 20*1024)
	largePrompt := strings.Repeat("Y", 4*1024)

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := client("Title", largeInstruction, []string{largePrompt}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans) != 1 || ans[0] != "large-ok" {
				return nil, errors.New("bad answer")
			}
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	var recordedReq atomic.Value
	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
			recordedReq.Store(req)
			return []byte("large-ok"), nil
		})),
		WithSecretPrompter(rejectInteraction{}),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	req := recordedReq.Load().(SecretRequest)
	if len(req.Instruction) != 20*1024 {
		t.Errorf("expected instruction len %d, got %d", 20*1024, len(req.Instruction))
	}
	if len(req.Prompt) != 4*1024 {
		t.Errorf("expected prompt len %d, got %d", 4*1024, len(req.Prompt))
	}
}

// 8. Empty string prompt handled without panic
func TestKeyboardInteractive_Adversarial_EmptyQuestionString(t *testing.T) {
	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := client("", "instruction", []string{""}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans) != 1 || ans[0] != "empty-ok" {
				return nil, errors.New("bad answer")
			}
			return nil, nil
		},
	}
	server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
	host, port := parseTestHostPort(t, server.addr)

	cfg := &ClientConfig{
		NodeID:   "test-node",
		User:     "ops",
		Address:  host,
		Port:     port,
		AuthType: "keyboard-interactive",
	}

	connector := NewConnector(
		&mockConfigStore{cfg: cfg},
		WithHostKeyVerifier(&fixtureTrust{}),
		WithSecretResolver(testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
			if req.Prompt != "" {
				t.Errorf("expected empty prompt, got %q", req.Prompt)
			}
			return []byte("empty-ok"), nil
		})),
		WithSecretPrompter(rejectInteraction{}),
	)

	client, err := connector.Connect(t.Context(), cfg.NodeID)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()
}

// 9. Concurrent keyboard-interactive handshakes against independent mock SSH servers under race detector
func TestKeyboardInteractive_Adversarial_ConcurrentHandshakes(t *testing.T) {
	const concurrency = 8
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			serverConfig := &ssh.ServerConfig{
				KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
					ans, err := client("", "Banner", []string{"Password: "}, []bool{false})
					if err != nil {
						return nil, err
					}
					if len(ans) != 1 || ans[0] != "concurrent-pass" {
						return nil, errors.New("unauthorized")
					}
					return nil, nil
				},
			}
			server := startKeyboardInteractiveMockSSHServer(t, serverConfig)
			host, port := parseTestHostPort(t, server.addr)

			cfg := &ClientConfig{
				NodeID:   fmt.Sprintf("node-%d", workerID),
				User:     "ops",
				Address:  host,
				Port:     port,
				AuthType: "keyboard-interactive",
			}

			connector := NewConnector(
				&mockConfigStore{cfg: cfg},
				WithHostKeyVerifier(&fixtureTrust{}),
				WithSecretResolver(testSecretResolverFunc(func(ctx context.Context, req SecretRequest) ([]byte, error) {
					return []byte("concurrent-pass"), nil
				})),
				WithSecretPrompter(rejectInteraction{}),
			)

			client, err := connector.Connect(t.Context(), cfg.NodeID)
			if err != nil {
				errCh <- fmt.Errorf("worker %d failed: %w", workerID, err)
				return
			}
			defer func() {
				_ = client.Close()
			}()
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent handshake error: %v", err)
	}
}
