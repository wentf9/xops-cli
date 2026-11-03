package ssh

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// defaultMaxKeyboardInteractiveQueries defines the upper bound of challenge queries allowed in a handshake.
const defaultMaxKeyboardInteractiveQueries = 16

// KeyboardInteractiveOptions allows customizing keyboard-interactive behavior.
type KeyboardInteractiveOptions struct {
	MaxQueries int
}

var (
	ansiCSIRegex = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	ansiOSCRegex = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)
	ansiEscRegex = regexp.MustCompile(`\x1b[@-Z\\-_]`)
)

// sanitizePromptText strips ANSI escape sequences and non-printable control characters,
// while preserving normal whitespace (spaces, tabs, newlines).
func sanitizePromptText(raw string) string {
	if raw == "" {
		return ""
	}
	// Strip ANSI escape codes (CSI, OSC, and other 2-byte escape sequences)
	cleaned := ansiCSIRegex.ReplaceAllString(raw, "")
	cleaned = ansiOSCRegex.ReplaceAllString(cleaned, "")
	cleaned = ansiEscRegex.ReplaceAllString(cleaned, "")

	var b strings.Builder
	b.Grow(len(cleaned))
	for _, r := range cleaned {
		if r == '\r' {
			continue
		}
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// buildKeyboardInteractiveAuthMethod wraps ssh.KeyboardInteractiveChallenge.
// It enforces:
// 1. Zero keyword guessing (never heuristically inspect questions).
// 2. Buffering of empty challenge packets (RFC 4256 len(questions) == 0).
// 3. Anti-loop prevention (when server asks same question with Attempt > 1, skip automated resolver).
// 4. In non-interactive mode, rejected automated answer returns ErrInteractionRequired immediately.
// 5. Bounded query iterations (max 16 queries per handshake).
// 6. Interactive answers never trigger PasswordCallback or persist credentials.
func buildKeyboardInteractiveAuthMethod(secProvider *autoSecretProvider, opts ...KeyboardInteractiveOptions) ssh.AuthMethod {
	maxQueries := defaultMaxKeyboardInteractiveQueries
	if len(opts) > 0 && opts[0].MaxQueries > 0 {
		maxQueries = opts[0].MaxQueries
	}

	var (
		mu                  sync.Mutex
		bufferedInstruction string
		attempts            = make(map[string]int)
		totalQueries        int
		rounds              int
	)

	return ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()

		if secProvider != nil {
			if err := secProvider.terminalError(); err != nil {
				return nil, err
			}
		}

		rounds++
		if rounds > maxQueries {
			return nil, fmt.Errorf("server exceeded maximum keyboard-interactive challenge limit (%d)", maxQueries)
		}

		// RFC 4256: Server may send informational challenge packets with no questions.
		// Buffer instruction/name and return nil, nil without prompting user or failing.
		if len(questions) == 0 {
			sanitizedInst := sanitizePromptText(instruction)
			sanitizedName := sanitizePromptText(name)
			text := sanitizedInst
			if text == "" {
				text = sanitizedName
			} else if sanitizedName != "" && !strings.Contains(sanitizedInst, sanitizedName) {
				text = sanitizedName + "\n" + sanitizedInst
			}
			if text != "" {
				if bufferedInstruction == "" {
					bufferedInstruction = text
				} else {
					bufferedInstruction += "\n" + text
				}
			}
			return nil, nil
		}

		totalQueries += len(questions)
		if totalQueries > maxQueries {
			return nil, fmt.Errorf("server exceeded maximum keyboard-interactive challenge limit (%d)", maxQueries)
		}

		// Merge buffered instruction text into current non-empty request.
		sanitizedInst := sanitizePromptText(instruction)
		effectiveInstruction := sanitizedInst
		if bufferedInstruction != "" {
			if effectiveInstruction != "" {
				effectiveInstruction = bufferedInstruction + "\n" + effectiveInstruction
			} else {
				effectiveInstruction = bufferedInstruction
			}
			bufferedInstruction = ""
		}

		answers := make([]string, len(questions))
		for i, q := range questions {
			sanitizedQ := sanitizePromptText(q)
			attempts[sanitizedQ]++
			attempt := attempts[sanitizedQ]

			req := SecretRequest{
				Kind:        SecretKindKeyboardInteractive,
				Instruction: effectiveInstruction,
				Prompt:      sanitizedQ,
				Echo:        i < len(echos) && echos[i],
				Attempt:     attempt,
				NumPrompts:  len(questions),
			}

			if secProvider == nil {
				return nil, ErrInteractionRequired
			}

			// Anti-loop prevention on Attempt > 1:
			// When server repeats a question prompt, skip automated resolution (retry = true)
			// and fall back directly to interactive prompter.
			// In non-interactive mode, immediately return ErrInteractionRequired.
			retry := attempt > 1
			ans, err := secProvider.resolveOrPromptAttempt(req, retry)
			if err != nil {
				if errors.Is(err, ErrInteractionRequired) {
					return nil, ErrInteractionRequired
				}
				return nil, err
			}
			answers[i] = ans
		}

		return answers, nil
	})
}
