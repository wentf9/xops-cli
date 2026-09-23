package utils

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// InventorySecretInput reads explicit credential replacements without putting
// their values in command arguments. An omitted flag leaves the secret unchanged.
type InventorySecretInput struct {
	passwordStdin   bool
	passphraseStdin bool
}

func (s *InventorySecretInput) RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&s.passwordStdin, "password-stdin", false, i18n.T("flag_password_stdin"))
	cmd.Flags().BoolVar(&s.passphraseStdin, "passphrase-stdin", false, i18n.T("flag_passphrase_stdin"))
	cmd.MarkFlagsMutuallyExclusive("password-stdin", "passphrase-stdin")
	cmd.MarkFlagsMutuallyExclusive("password-stdin", "key")
}

func (s *InventorySecretInput) Read(cmd *cobra.Command) (password, passphrase string, err error) {
	if !s.passwordStdin && !s.passphraseStdin {
		return "", "", nil
	}
	secret, err := ReadSecretFromReader(cmd.InOrStdin())
	if err != nil {
		return "", "", fmt.Errorf("read inventory credential from stdin: %w", err)
	}
	if s.passwordStdin {
		return secret, "", nil
	}
	return "", secret, nil
}
