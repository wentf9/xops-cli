package sshexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

const ptyCloseTimeout = time.Second

type ptySession struct {
	client    *ssh.Client
	session   *cryptoSSH.Session
	stdin     io.WriteCloser
	writeMu   sync.Mutex
	pipeR     *io.PipeReader
	pipeW     *io.PipeWriter
	waitDone  <-chan struct{}
	release   func() error
	closeOnce sync.Once
	closeErr  error
}

// OpenClientPTY opens a persistent PTY-backed shell session on client.
// Ownership of release is transferred to the returned PTYSession on success,
// or invoked immediately if setup fails.
func OpenClientPTY(ctx context.Context, client *ssh.Client, release func() error) (ports.PTYSession, error) {
	if release == nil {
		release = func() error { return nil }
	}
	if ctx == nil {
		_ = release()
		return nil, errors.New("PTY context is required")
	}
	if err := ctx.Err(); err != nil {
		_ = release()
		return nil, err
	}
	if client == nil || client.SSHClient() == nil {
		_ = release()
		return nil, errors.New("SSH client is not connected")
	}
	raw := client.SSHClient()

	type setupResult struct {
		sess  *cryptoSSH.Session
		stdin io.WriteCloser
		err   error
	}
	done := make(chan setupResult, 1)
	pr, pw := io.Pipe()

	go func() {
		sess, err := raw.NewSession()
		if err != nil {
			done <- setupResult{err: fmt.Errorf("create PTY SSH session: %w", err)}
			return
		}
		modes := cryptoSSH.TerminalModes{
			cryptoSSH.ECHO:          0,
			cryptoSSH.NOFLSH:        1,
			cryptoSSH.TTY_OP_ISPEED: 14400,
			cryptoSSH.TTY_OP_OSPEED: 14400,
		}
		if err := sess.RequestPty("xterm-256color", 40, 120, modes); err != nil {
			_ = sess.Close()
			done <- setupResult{err: fmt.Errorf("request SSH PTY: %w", err)}
			return
		}
		stdin, err := sess.StdinPipe()
		if err != nil {
			_ = sess.Close()
			done <- setupResult{err: fmt.Errorf("open SSH PTY stdin: %w", err)}
			return
		}
		sess.Stdout = pw
		sess.Stderr = pw
		if err := sess.Shell(); err != nil {
			_ = stdin.Close()
			_ = sess.Close()
			done <- setupResult{err: fmt.Errorf("start SSH PTY shell: %w", err)}
			return
		}
		done <- setupResult{sess: sess, stdin: stdin}
	}()

	var res setupResult
	select {
	case res = <-done:
	case <-ctx.Done():
		_ = pw.Close()
		_ = pr.Close()
		_ = client.Interrupt()
		res = <-done
		if res.sess != nil {
			_ = res.sess.Close()
		}
		_ = release()
		return nil, ctx.Err()
	}

	if res.err != nil {
		_ = pw.Close()
		_ = pr.Close()
		_ = release()
		return nil, res.err
	}

	waitDone := make(chan struct{})
	go func() {
		defer close(waitDone)
		err := res.sess.Wait()
		_ = pw.CloseWithError(err)
	}()

	return &ptySession{
		client:   client,
		session:  res.sess,
		stdin:    res.stdin,
		pipeR:    pr,
		pipeW:    pw,
		waitDone: waitDone,
		release:  release,
	}, nil
}

func (p *ptySession) Read(b []byte) (int, error) {
	return p.pipeR.Read(b)
}

func (p *ptySession) Write(b []byte) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.stdin.Write(b)
}

func (p *ptySession) Signal(sig string) error {
	normalized := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(sig)), "SIG")
	switch normalized {
	case "INT":
		p.writeMu.Lock()
		_, _ = p.stdin.Write([]byte{0x03})
		p.writeMu.Unlock()
		return p.session.Signal(cryptoSSH.SIGINT)
	case "EOF":
		p.writeMu.Lock()
		_, err := p.stdin.Write([]byte{0x04})
		p.writeMu.Unlock()
		return err
	case "TERM":
		return p.session.Signal(cryptoSSH.SIGTERM)
	case "KILL":
		return p.session.Signal(cryptoSSH.SIGKILL)
	case "QUIT":
		return p.session.Signal(cryptoSSH.SIGQUIT)
	default:
		return p.session.Signal(cryptoSSH.Signal(normalized))
	}
}

func (p *ptySession) Close() error {
	p.closeOnce.Do(func() {
		_ = p.pipeR.Close()
		_ = p.pipeW.Close()

		closeDone := make(chan error, 1)
		go func() {
			_ = p.session.Close()
			p.writeMu.Lock()
			_ = p.stdin.Close()
			p.writeMu.Unlock()
			<-p.waitDone
			closeDone <- p.release()
		}()

		timer := time.NewTimer(ptyCloseTimeout)
		defer timer.Stop()
		select {
		case err := <-closeDone:
			p.closeErr = err
		case <-timer.C:
			interruptErr := p.client.Interrupt()
			releaseErr := <-closeDone
			p.closeErr = errors.Join(interruptErr, releaseErr)
		}
	})
	return p.closeErr
}
