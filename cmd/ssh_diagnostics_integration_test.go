package cmd

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"golang.org/x/crypto/ssh/knownhosts"
)

//nolint:gocyclo // Keep each verbosity's transport, output and privacy checks together.
func TestSSHDiagnosticsEndToEnd(t *testing.T) {
	for level := 1; level <= 3; level++ {
		t.Run(strconv.Itoa(level), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			server, err := sshfixture.New(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := server.Close(); err != nil {
					t.Error(err)
				}
			})
			var diagnostics, stdout, stderr bytes.Buffer
			d, err := newSSHDiagnostics(ctx, &diagnostics, level)
			if err != nil {
				t.Fatal(err)
			}
			// Registered before the connector: the sink outlives all event producers.
			t.Cleanup(func() {
				if err := d.finish(); err != nil {
					t.Error(err)
				}
			})
			host, portText, err := net.SplitHostPort(server.Address)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			connector := ssh.NewConnector(tunnelTestProvider{cfg: &ssh.ClientConfig{
				NodeID: "diagnostic-fixture", Address: host, Port: port, User: "fixture", AuthType: "password", Password: sshfixture.Password,
			}}, ssh.WithHostKeyVerifier(execFixtureVerifier{server.HostKey}), ssh.WithDiagnostics(d))
			t.Cleanup(func() {
				if err := connector.CloseAll(); err != nil {
					t.Error(err)
				}
			})
			client, err := connector.Connect(ctx, "diagnostic-fixture")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := ssh.PlanCommand("private-command-marker", ssh.CommandOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := client.RunCommandPlanWithIO(ctx, plan, strings.NewReader("private-input-marker"), &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if err := connector.CloseAll(); err != nil {
				t.Fatal(err)
			}
			if err := d.finish(); err != nil {
				t.Fatal(err)
			}
			text := diagnostics.String()
			for _, required := range []string{"debug1: Connecting", "Server host key", "kex:", "Next authentication method", "Authenticated to", "Entering", "Exit status 0"} {
				if !strings.Contains(text, required) {
					t.Fatalf("missing %q: %s", required, text)
				}
			}
			for _, private := range []string{sshfixture.Password, "private-command-marker", "private-input-marker", "fixture-output"} {
				if strings.Contains(text, private) {
					t.Fatalf("diagnostic leaked %q", private)
				}
			}
			if stdout.String() != "fixture-output" || stderr.Len() != 0 || server.Executed.Load() != 1 {
				t.Fatalf("remote output/execution changed: %q / %q", stdout.String(), stderr.String())
			}
			if strings.Contains(text, "debug2:") != (level >= 2) || strings.Contains(text, "debug3:") != (level >= 3) {
				t.Fatalf("incorrect verbosity: %s", text)
			}
			if !errors.Is((&ssh.OutputError{Target: os.Stderr, Err: os.ErrClosed}), os.ErrClosed) || !HasStandardOutputError(&ssh.OutputError{Target: os.Stderr, Err: os.ErrClosed}) {
				t.Fatal("diagnostic stream failure not recognized")
			}
		})
	}
}

// Compare flag ordering with the actual OpenSSH client, not its packet text.
// The pinned loopback peer rejects exec, so command failure is expected.
func TestSystemSSHQuietVerbosity(t *testing.T) {
	binary, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("system ssh unavailable")
	}
	version, err := exec.CommandContext(t.Context(), binary, "-V").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "OpenSSH") {
		t.Skip("OpenSSH client unavailable")
	}
	fixture := newSCPTransferFixture(t)
	host, port, err := net.SplitHostPort(fixture.address)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte(knownhosts.Line([]string{fixture.address}, fixture.hostKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, flags := range []string{"-v", "-vv", "-vvv", "-q", "-qv", "-vq", "-vqv"} {
		t.Run(flags, func(t *testing.T) {
			args := []string{"-F", os.DevNull, "-o", "BatchMode=yes", "-o", "IdentityAgent=none", "-o", "IdentityFile=none", "-o", "CertificateFile=none", "-o", "GlobalKnownHostsFile=none", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + knownHosts, "-p", port, flags, "fixture@" + host, "fixture-reject-exec"}
			output, err := exec.CommandContext(fixture.ctx, binary, args...).CombinedOutput()
			if err == nil {
				t.Fatal("fixture unexpectedly accepted exec")
			}
			want := flags == "-v" || flags == "-vv" || flags == "-vvv" || flags == "-qv"
			if got := strings.Contains(string(output), "debug1: Connecting to"); got != want {
				t.Fatalf("OpenSSH verbosity/order changed: %s", output)
			}
		})
	}
}
