package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// Numeric spacing mirrors OpenSSH log.h: repeated -v after -q advances through
// FATAL, ERROR, INFO and VERBOSE before it reaches DEBUG1 again.
const (
	scpSSHQuiet  = 0
	scpSSHInfo   = 3
	scpSSHDebug1 = 5
	scpSSHDebug3 = 7
)

// scpOutputFlag preserves argument order, including combined short flags.
// OpenSSH scp keeps its own verbose output after -q, but passes both switches
// to ssh, whose log level is order-dependent (ssh.c's 'q' and 'v' cases).
type scpOutputFlag struct {
	value *bool
	set   func(bool)
}

func (f scpOutputFlag) String() string { return strconv.FormatBool(*f.value) }
func (f scpOutputFlag) Type() string   { return "bool" }
func (f scpOutputFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	*f.value = v
	f.set(v)
	return nil
}

func (o *ScpOptions) registerOutputFlags(cmd *cobra.Command) {
	cmd.Flags().VarP(scpOutputFlag{&o.Quiet, func(v bool) {
		if v {
			o.sshLogLevel = scpSSHQuiet
		}
	}}, "quiet", "q", i18n.T("flag_scp_quiet"))
	cmd.Flags().Lookup("quiet").NoOptDefVal = "true"
	cmd.Flags().VarP(scpOutputFlag{&o.Verbose, func(v bool) {
		if !v {
			o.verboseSeen = false
			o.verboseLevel = 0
			o.sshLogLevel = scpSSHInfo
			return
		}
		o.verboseLevel = min(o.verboseLevel+1, 3)
		if !o.verboseSeen {
			o.verboseSeen = true
			o.sshLogLevel = scpSSHDebug1
		} else if o.sshLogLevel < scpSSHDebug3 {
			o.sshLogLevel++
		}
	}}, "verbose", "v", i18n.T("flag_scp_verbose"))
	cmd.Flags().Lookup("verbose").NoOptDefVal = "true"
}

const scpDiagnosticCapacity = 128

// scpDiagnostics owns its bounded queue, output binding and (when supported)
// writer goroutine. Core callbacks only enqueue and never wait for the sink.
// Progress and status messages use the same queue. Unsupported sinks are disabled;
// no raw fallback write or uninterruptible background worker is installed.
// The target stream itself is always borrowed.
type scpDiagnostics struct {
	mu          sync.Mutex
	sshVerbose  bool
	scpLevel    int
	lines       chan string
	dropped     int
	closed      bool
	disabled    bool
	stream      string
	writer      io.Writer
	cancel      context.CancelFunc
	closeOutput func() error
	done        chan error
	finishOnce  sync.Once
	finishErr   error
}

func newSCPDiagnostics(ctx context.Context, target io.Writer, stream string, sshVerbose bool, scpLevel int) (*scpDiagnostics, error) {
	outputCtx, cancel := context.WithCancel(ctx)
	writer, closeOutput, cancelable, err := ssh.BindOutput(outputCtx, target)
	if err != nil {
		cancel()
		return nil, &SCPOutputError{Stream: stream, Err: err}
	}
	d := &scpDiagnostics{sshVerbose: sshVerbose, scpLevel: scpLevel, lines: make(chan string, scpDiagnosticCapacity), writer: writer,
		cancel: cancel, closeOutput: closeOutput, done: make(chan error, 1), disabled: !cancelable, stream: stream}
	if cancelable {
		go func() {
			var outputErr error
			for line := range d.lines {
				// A stopped reader cannot hold up connector shutdown. Canceling
				// the owned binding releases Linux pipe/terminal writes.
				if outputErr == nil {
					timer := time.AfterFunc(time.Second, cancel)
					_, outputErr = io.WriteString(writer, line)
					timer.Stop()
				}
			}
			d.done <- outputErr
		}()
	}
	return d, nil
}

func (d *scpDiagnostics) enqueue(line string) {
	if d.disabled {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	select {
	case d.lines <- line:
	default:
		d.dropped++
	}
}

// Write queues a progress frame without blocking the transfer callback. Actual
// I/O errors are reported by finish after all producers and the writer join.
func (d *scpDiagnostics) Write(p []byte) (int, error) {
	d.enqueue(string(p))
	return len(p), nil
}

// quotedDiagnostic bounds untrusted metadata and escapes terminal controls.
func quotedDiagnostic(s string) string {
	if len(s) > 256 {
		s = s[:256] + "..."
	}
	return strconv.QuoteToASCII(s)
}

func (d *scpDiagnostics) DiagnosticLevel() int { return max(d.scpLevel, 1) }

func (d *scpDiagnostics) ObserveDiagnostic(e corelog.Diagnostic) {
	if !corelog.DiagnosticEnabled(d, e.Level) {
		return
	}
	if d.observeSFTP(e) {
		return
	}
	// OpenSSH's SFTP client diagnostics belong to scp, whose verbose mode
	// survives -q even when the underlying ssh diagnostics are quiet.
	subsystem := e.Kind == corelog.SubsystemStarting || e.Kind == corelog.SubsystemReady || e.Kind == corelog.SubsystemFailed
	if !d.sshVerbose && !subsystem {
		return
	}
	q := quotedDiagnostic
	peer := q(e.NodeID)
	if e.NodeID == "" {
		peer = q(e.User + "@" + e.Host)
	}
	var message string
	switch e.Kind {
	case corelog.Connecting:
		message = fmt.Sprintf("Connecting to %s port %d as %s (via proxy: %t).", q(e.Host), e.Port, q(e.User), e.Proxied)
	case corelog.Connected:
		message = "Connection established for " + peer + "."
	case corelog.ConnectionReused:
		message = "Reusing SSH connection for " + peer + "."
	case corelog.HandshakeFailed:
		message = "SSH connection/handshake failed for " + peer + "."
	case corelog.HostKeyChecked:
		message = fmt.Sprintf("Server host key for %s: %s %s; verification accepted: %t.", peer, q(e.HostKey), q(e.Fingerprint), e.Accepted)
	case corelog.AuthenticationMethods:
		message = "Authentications that can continue for " + peer + ": " + q(strings.Join(e.Methods, ","))
	case corelog.AuthenticationAttempt:
		message = "Next authentication method for " + peer + ": " + q(e.Method)
	case corelog.Authenticated:
		message = fmt.Sprintf("Authenticated to %s. Local version %s; remote version %s.\ndebug1: kex: algorithm: %s; host key algorithm: %s\ndebug1: cipher server->client: %s MAC: %s; client->server: %s MAC: %s",
			peer, q(e.ClientVersion), q(e.ServerVersion), q(e.KeyExchange), q(e.HostKey), q(e.ReadCipher), q(e.ReadMAC), q(e.WriteCipher), q(e.WriteMAC))
	case corelog.SubsystemStarting:
		message = "Sending subsystem: sftp to " + peer
	case corelog.SubsystemReady:
		message = "SFTP subsystem ready for " + peer + " (protocol version 3)."
	case corelog.SubsystemFailed:
		message = "SFTP subsystem setup failed for " + peer + "."
	default:
		return
	}
	prefix := "debug1: "
	if subsystem {
		prefix = "scp: debug1: "
	}
	d.enqueue(prefix + message + "\n")
}

func (d *scpDiagnostics) transfer(source, dest, status string) {
	d.enqueue(fmt.Sprintf("scp: transfer %s: %s -> %s\n", status, quotedDiagnostic(source), quotedDiagnostic(dest)))
}

// finish joins the owned writer after all producers stop. It is idempotent so
// error paths and test cleanup can release the binding without double-closing.
func (d *scpDiagnostics) finish() error {
	d.finishOnce.Do(func() { d.finishErr = d.finishOutput() })
	return d.finishErr
}

func (d *scpDiagnostics) finishOutput() error {
	d.mu.Lock()
	d.closed = true
	close(d.lines)
	dropped := d.dropped
	d.mu.Unlock()
	var err error
	if !d.disabled {
		err = <-d.done
	}
	if !d.disabled && dropped > 0 && err == nil {
		// Reuse the bounded output binding; no core callback is involved.
		timer := time.AfterFunc(time.Second, d.cancel)
		_, err = fmt.Fprintf(d.writer, "scp: output buffer full; omitted %d updates\n", dropped)
		timer.Stop()
	}
	d.cancel()
	err = errors.Join(err, d.closeOutput())
	if err != nil {
		return &SCPOutputError{Stream: d.stream, Err: err}
	}
	return nil
}
