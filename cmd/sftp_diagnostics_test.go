package cmd

import (
	"bytes"
	"net"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestSFTPVerboseFlags(t *testing.T) {
	for _, tc := range []struct {
		flags []string
		level int
	}{
		{nil, sshLogInfo}, {[]string{"-v"}, sshLogDebug1}, {[]string{"-vv"}, sshLogDebug1 + 1},
		{[]string{"-vvv"}, sshLogDebug3}, {[]string{"-vvvvv"}, sshLogDebug3},
		{[]string{"--verbose", "--verbose"}, sshLogDebug1 + 1}, {[]string{"-v", "--verbose=false"}, sshLogInfo},
	} {
		var options sshDiagnosticOptions
		command := &cobra.Command{}
		options.registerVerbose(command, "flag_sftp_verbose")
		if err := command.ParseFlags(tc.flags); err != nil {
			t.Fatal(err)
		}
		if options.level != tc.level {
			t.Errorf("%v: level=%d want=%d", tc.flags, options.level, tc.level)
		}
	}

	command := NewCmdSftp()
	if err := command.ParseFlags([]string{"-vv"}); err != nil {
		t.Fatalf("sftp rejected -v: %v", err)
	}
	if verbose := command.Flags().ShorthandLookup("v"); verbose == nil || verbose.Name != "verbose" {
		t.Fatal("sftp -v is not the verbose diagnostic flag")
	}
	// sftp has no progress meter or warnings for -q to control.
	if command.Flags().ShorthandLookup("q") != nil {
		t.Fatal("sftp registered an unsupported quiet flag")
	}
}

func TestSFTPDiagnosticEventLevels(t *testing.T) {
	events := []corelog.Diagnostic{
		{Kind: corelog.SFTPVersion, Level: 1, StreamID: 7, Direction: "Remote", ProtocolVersion: 3},
		{Kind: corelog.FileTransfer, Level: 2, StreamID: 7, Operation: "upload", Outcome: "starting", Source: "a", Destination: "b"},
		{Kind: corelog.SFTPPacket, Level: 3, StreamID: 7, Direction: "send", PacketType: 3, PacketLength: 9},
	}
	for level := 1; level <= 3; level++ {
		var output bytes.Buffer
		d, err := newSSHDiagnostics(t.Context(), &output, level)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			d.ObserveDiagnostic(event)
		}
		if err := d.finish(); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		for want, minimum := range map[string]int{"debug1: [sftp 7] Remote SFTP version 3": 1, "debug2: [sftp 7] upload starting": 2, "debug3: [sftp 7] send packet SSH2_FXP_OPEN": 3} {
			if got := strings.Contains(text, want); got != (level >= minimum) {
				t.Errorf("level %d: %q present=%t\n%s", level, want, got, text)
			}
		}
		if strings.Contains(text, "scp:") {
			t.Errorf("sftp diagnostics carry scp prefix: %q", text)
		}
	}
}

// The command-level wiring passes one observer to both the connector and the
// SFTP client; this checks that those hooks together report a real session.
func TestSFTPDiagnosticsEndToEnd(t *testing.T) {
	for level := 1; level <= 3; level++ {
		var output bytes.Buffer
		d, err := newSSHDiagnostics(t.Context(), &output, level)
		if err != nil {
			t.Fatal(err)
		}
		fixture := newSCPTransferFixture(t, ssh.WithDiagnostics(d))
		_, port, err := net.SplitHostPort(fixture.address)
		if err != nil {
			t.Fatal(err)
		}
		client, err := fixture.connector.Connect(fixture.ctx, "test@"+net.JoinHostPort("scp.fixture.invalid", port))
		if err != nil {
			t.Fatal(err)
		}
		sftpClient, err := sftp.NewClient(fixture.ctx, client, sftp.WithDiagnostics(d))
		if err != nil {
			t.Fatal(err)
		}
		local := filepath.Join(t.TempDir(), "payload.txt")
		writeSCPTestFile(t, local, "file-content-must-not-appear-in-diagnostics")
		if err := sftpClient.Upload(fixture.ctx, local, path.Join(fixture.remoteHome, "uploaded.txt"), nil); err != nil {
			t.Fatal(err)
		}
		if err := sftpClient.Close(); err != nil {
			t.Fatal(err)
		}
		if err := fixture.connector.CloseAll(); err != nil {
			t.Fatal(err)
		}
		if err := d.finish(); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		for _, want := range []string{"debug1: Connecting to", "Authenticated to", "SFTP subsystem ready"} {
			if !strings.Contains(text, want) {
				t.Errorf("level %d: missing %q\n%s", level, want, text)
			}
		}
		if got := strings.Contains(text, "debug2: [sftp"); got != (level >= 2) {
			t.Errorf("level %d: DEBUG2 SFTP events present=%t\n%s", level, got, text)
		}
		if got := strings.Contains(text, "debug3: [sftp"); got != (level >= 3) {
			t.Errorf("level %d: DEBUG3 SFTP packets present=%t\n%s", level, got, text)
		}
		if strings.Contains(text, "content-must-not-appear") || strings.Contains(text, "scp:") {
			t.Errorf("level %d: leaked content or scp prefix\n%s", level, text)
		}
	}
}
