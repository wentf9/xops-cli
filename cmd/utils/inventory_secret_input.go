package utils

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// InventorySecretInput reads explicit credential replacements without putting
// their values in command arguments. An omitted flag leaves the secret unchanged.
type InventorySecretInput struct {
	passwordStdin   bool
	passphraseStdin bool
	askPass         bool
	askPassphrase   bool
}

func (s *InventorySecretInput) RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&s.passwordStdin, "password-stdin", false, i18n.T("flag_password_stdin"))
	cmd.Flags().BoolVar(&s.passphraseStdin, "passphrase-stdin", false, i18n.T("flag_passphrase_stdin"))
	cmd.Flags().BoolVar(&s.askPass, "ask-pass", false, i18n.T("flag_ask_pass"))
	cmd.Flags().BoolVar(&s.askPassphrase, "ask-passphrase", false, i18n.T("flag_ask_passphrase"))
	cmd.MarkFlagsMutuallyExclusive("password-stdin", "passphrase-stdin", "ask-pass", "ask-passphrase")
	cmd.MarkFlagsMutuallyExclusive("password-stdin", "key")
	cmd.MarkFlagsMutuallyExclusive("ask-pass", "key")
}

// UsesStdin reports whether standard input is reserved for reading a secret.
func (s *InventorySecretInput) UsesStdin() bool {
	return s != nil && (s.passwordStdin || s.passphraseStdin)
}

func (s *InventorySecretInput) Read(cmd *cobra.Command) (password, passphrase string, err error) {
	if s.passwordStdin || s.passphraseStdin {
		secret, err := ReadSecretFromReader(cmd.InOrStdin())
		if err != nil {
			return "", "", fmt.Errorf("read inventory credential from stdin: %w", err)
		}
		if s.passwordStdin {
			return secret, "", nil
		}
		return "", secret, nil
	}
	if s.askPass {
		secret, err := ReadPasswordFromTerminal(i18n.T("prompt_enter_password"))
		if err != nil {
			return "", "", fmt.Errorf("read inventory password from terminal: %w", err)
		}
		if secret == "" {
			return "", "", errors.New("password from terminal is empty")
		}
		return secret, "", nil
	}
	if s.askPassphrase {
		prompt := i18n.T("prompt_enter_key_passphrase")
		if keyPath, _ := cmd.Flags().GetString("key"); keyPath != "" {
			prompt = i18n.Tf("prompt_enter_passphrase", map[string]any{"Path": ToAbsolutePath(keyPath)})
		}
		secret, err := ReadPasswordFromTerminal(prompt)
		if err != nil {
			return "", "", fmt.Errorf("read inventory passphrase from terminal: %w", err)
		}
		if secret == "" {
			return "", "", errors.New("passphrase from terminal is empty")
		}
		return "", secret, nil
	}
	return "", "", nil
}
