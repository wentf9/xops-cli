package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/pflag"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func validateExplicitZeroPort(flags *pflag.FlagSet) error {
	if flags == nil || !flags.Changed("port") {
		return nil
	}
	if portVal, err := flags.GetUint16("port"); err == nil && portVal == 0 {
		return errors.New(i18n.T("scp_err_port_zero"))
	}
	return nil
}

func readCLISecretsFromStdin(o *SshOptions) (bool, error) {
	if o == nil {
		return false, nil
	}
	hadCredentialStdin := o.OTPStdin || o.PasswordStdin || o.PassphraseStdin
	if o.OTP != "" && o.OTPStdin {
		return false, errors.New(i18n.T("err_otp_mutually_exclusive"))
	}
	if o.OTPStdin {
		otp, err := utils.ReadSecretLineFromStdin()
		if err != nil {
			return false, fmt.Errorf("read otp from stdin: %w", err)
		}
		o.OTP = otp
		o.OTPStdin = false
	}
	if o.PasswordStdin {
		pwd, err := utils.ReadSecretFromStdin()
		if err != nil {
			return false, fmt.Errorf("read password from stdin: %w", err)
		}
		o.Password = pwd
	}
	if o.PassphraseStdin {
		pass, err := utils.ReadSecretFromStdin()
		if err != nil {
			return false, fmt.Errorf("read passphrase from stdin: %w", err)
		}
		o.Passphrase = pass
	}
	return hadCredentialStdin, nil
}

func validateCommonSSHBaseOptions(o *SshOptions) error {
	if o == nil {
		return nil
	}
	if o.OTP != "" && o.OTPStdin {
		return errors.New(i18n.T("err_otp_mutually_exclusive"))
	}
	if err := utils.ValidateRememberPolicy(o.Remember); err != nil {
		return err
	}
	return config.ValidateNodeAlias(o.Alias)
}
