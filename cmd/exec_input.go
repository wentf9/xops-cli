package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/terminal"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// completeInput establishes one owner for stdin before consuming any bytes.
func (o *ExecOptions) completeInput(ctx context.Context) error {
	if !o.Interactive && o.Command == "" && o.ShellFile == "" && (o.PasswordStdin || o.PassphraseStdin) {
		return fmt.Errorf("stdin cannot supply both credentials and a script; use --cmd or --shell")
	}
	if o.PasswordStdin {
		pwd, err := utils.ReadSecretFromStdin()
		if err != nil {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		o.Password = pwd
	}
	if o.PassphraseStdin {
		pass, err := utils.ReadSecretFromStdin()
		if err != nil {
			return fmt.Errorf("read passphrase from stdin: %w", err)
		}
		o.Passphrase = pass
	}
	if err := o.readStdinIfRequired(ctx); err != nil {
		return err
	}
	if o.execution.enabled() && o.Command == "" && o.ShellFile == "" {
		return fmt.Errorf("%s", i18n.T("exec_err_no_cmd"))
	}
	return o.prepareCommandPlan()
}

// readExecScriptInput borrows source and owns only an interruptible duplicate.
// The calling goroutine does the bounded read; cancellation interrupts the owned
// input, and cleanup joins that interruption before releasing the duplicate.
// Kernel filesystem reads already in progress still have to finish first.
func readExecScriptInput(ctx context.Context, source *os.File, limit int64) (content []byte, retErr error) {
	work, cancel := context.WithTimeout(ctx, ssh.DefaultCommandTimeout)
	defer cancel()
	if err := work.Err(); err != nil {
		return nil, err
	}
	if limit > 0 {
		info, err := source.Stat()
		if err != nil {
			return nil, err
		}
		if info.Mode().IsRegular() && info.Size() > limit {
			return nil, fmt.Errorf("script exceeds %d bytes", limit)
		}
	}
	input, err := terminal.DuplicatePromptInput(source)
	if err != nil {
		return nil, fmt.Errorf("duplicate script input: %w", err)
	}
	interrupted := make(chan error, 1)
	stop := context.AfterFunc(work, func() { interrupted <- input.Interrupt() })
	defer func() {
		var interruptErr error
		if !stop() {
			interruptErr = <-interrupted
		}
		retErr = errors.Join(retErr, interruptErr, input.Close())
	}()
	var reader io.Reader = input
	if limit > 0 {
		reader = io.LimitReader(reader, limit+1)
	}
	content, err = io.ReadAll(reader)
	if err := errors.Join(err, work.Err()); err != nil {
		return nil, err
	}
	if limit > 0 && int64(len(content)) > limit {
		return nil, fmt.Errorf("script exceeds %d bytes", limit)
	}
	return content, nil
}

func readExecScriptFile(ctx context.Context, path string, limit int64) (content []byte, retErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// Opening a FIFO can block before cancellation is installed. Pipe scripts
	// through stdin instead; --shell denotes a local regular script file.
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("script path must be a regular file; use stdin for piped scripts")
	}
	if limit > 0 && info.Size() > limit {
		return nil, fmt.Errorf("script exceeds %d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { retErr = errors.Join(retErr, file.Close()) }()
	return readExecScriptInput(ctx, file, limit)
}
