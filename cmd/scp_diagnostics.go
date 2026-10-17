package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func (o *ScpOptions) registerOutputFlags(cmd *cobra.Command) {
	cmd.Flags().VarP(orderedOutputFlag{&o.Quiet, func(v bool) {
		if v {
			o.sshLogLevel = sshLogQuiet
		}
	}}, "quiet", "q", i18n.T("flag_scp_quiet"))
	cmd.Flags().Lookup("quiet").NoOptDefVal = "true"
	cmd.Flags().VarP(orderedOutputFlag{&o.Verbose, func(v bool) {
		if !v {
			o.verboseSeen = false
			o.verboseLevel = 0
			o.sshLogLevel = sshLogInfo
			return
		}
		o.verboseLevel = min(o.verboseLevel+1, 3)
		if !o.verboseSeen {
			o.verboseSeen = true
			o.sshLogLevel = sshLogDebug1
		} else if o.sshLogLevel < sshLogDebug3 {
			o.sshLogLevel++
		}
	}}, "verbose", "v", i18n.T("flag_scp_verbose"))
	cmd.Flags().Lookup("verbose").NoOptDefVal = "true"
}

// scpDiagnostics owns its bounded queue, output binding and (when supported)
// writer goroutine. Core callbacks only enqueue and never wait for the sink.
// Progress and status messages use the same queue. Unsupported sinks are disabled;
// no raw fallback write or uninterruptible background worker is installed.
// The target stream itself is always borrowed.
type scpDiagnostics struct {
	*diagnosticOutput
	sshVerbose bool
	scpLevel   int
}

func newSCPDiagnostics(ctx context.Context, target io.Writer, stream string, sshVerbose bool, scpLevel int) (*scpDiagnostics, error) {
	output, err := newDiagnosticOutput(ctx, target, stream, "scp")
	if err != nil {
		return nil, &SCPOutputError{Stream: stream, Err: err}
	}
	return &scpDiagnostics{diagnosticOutput: output, sshVerbose: sshVerbose, scpLevel: scpLevel}, nil
}

func (d *scpDiagnostics) DiagnosticLevel() int { return max(d.scpLevel, 1) }

func (d *scpDiagnostics) ObserveDiagnostic(e corelog.Diagnostic) {
	if !corelog.DiagnosticEnabled(d, e.Level) {
		return
	}
	// SSH's pre-authentication negotiation event supplements its failure
	// diagnostics; SCP preserves its existing authenticated summary.
	if e.Kind == corelog.Negotiated {
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
	message := formatSSHDiagnostic(e)
	if message == "" {
		return
	}
	prefix := fmt.Sprintf("debug%d: ", max(e.Level, 1))
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
	if err := d.diagnosticOutput.finish(); err != nil {
		return &SCPOutputError{Stream: d.stream, Err: err}
	}
	return nil
}
