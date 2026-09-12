package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
)

// confirmPrivilege runs only after the corresponding remote operation succeeds
// and the password exchange is observed. Acquiring material alone never saves it.
func (c *Client) confirmPrivilege(ctx context.Context, material *PrivilegeMaterial) error {
	if material == nil || material.confirmedSave == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	save := material.confirmedSave
	material.confirmedSave = nil
	if err := save(ctx, material.Password); err != nil {
		if !reportCredentialFailure(ctx, c.prompter, "save", err) {
			return err
		}
		c.cfgMu.Lock()
		c.connCfg.AuthUpdateToken, c.connCfg.SudoUpdateToken = "", ""
		c.cfgMu.Unlock()
	}
	return nil
}

// privilegePromptWriter removes only the random sudo prompt, preserving all
// other bytes, including split markers and partial matches at process exit.
// The session joins its stderr copier before callers inspect or flush it.
type privilegePromptWriter struct {
	marker, pending []byte
	target          io.Writer
	observed        bool
}

func (w *privilegePromptWriter) Write(data []byte) (int, error) {
	n := len(data)
	if len(w.marker) == 0 || w.target == nil {
		return 0, errors.New("invalid privilege prompt writer")
	}
	w.pending = append(w.pending, data...)
	for {
		at := bytes.Index(w.pending, w.marker)
		if at < 0 {
			break
		}
		if err := w.writeOutput(w.pending[:at]); err != nil {
			return 0, err
		}
		w.pending = w.pending[at+len(w.marker):]
		w.observed = true
	}
	keep := len(w.marker) - 1
	if len(w.pending) > keep {
		count := len(w.pending) - keep
		if err := w.writeOutput(w.pending[:count]); err != nil {
			return 0, err
		}
		w.pending = append(w.pending[:0], w.pending[count:]...)
	}
	return n, nil
}
func (w *privilegePromptWriter) flush() error {
	if len(w.pending) == 0 {
		return nil
	}
	err := w.writeOutput(w.pending)
	w.pending = nil
	return err
}

func flushPrivilegePrompt(writer io.Writer) error {
	if w, ok := writer.(*privilegePromptWriter); ok {
		return w.flush()
	}
	return nil
}

func (c *Client) resolvePrivilegeCandidate(ctx context.Context, req SecretRequest, loginToken string) ([]byte, error) {
	value, err := c.resolver.ResolveSecret(ctx, req)
	if req.Kind != SecretKindSudoPassword || (err != nil && !errors.Is(err, ErrInteractionRequired)) || (err == nil && len(value) > 0) {
		return value, err
	}
	zeroBytes(value)
	req.Kind, req.VersionToken = SecretKindLoginPassword, loginToken
	return c.resolver.ResolveSecret(ctx, req)
}

func (w *privilegePromptWriter) writeOutput(data []byte) error {
	n, err := w.target.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (c *Client) confirmDetectedSudo(ctx context.Context, material *PrivilegeMaterial) error {
	if err := c.updateSudoMode(ctx, SudoModeSudo); err != nil {
		return err
	}
	if !material.verified || material.confirmedSave == nil {
		return nil
	}
	// Mode publication advances exactly this connection's sudo token. Bind the
	// verified candidate to that committed version, not to the pre-probe token.
	snapshot := c.ConnectionConfig()
	material.confirmedSave = func(work context.Context, value []byte) error {
		return c.recordPrivilegeSecret(work, SecretKindSudoPassword, snapshot, string(value))
	}
	return c.confirmPrivilege(ctx, material)
}
