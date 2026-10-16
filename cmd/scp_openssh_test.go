package cmd

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
)

// TestSystemSCPQuietVerbosity checks the documented flag-order contract against
// a real OpenSSH client using only the loopback fixture and a pinned public key.
func TestSystemSCPQuietVerbosity(t *testing.T) {
	client, err := exec.LookPath("scp")
	if err != nil {
		t.Skip("system scp unavailable")
	}
	sshClient, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("system ssh unavailable")
	}
	version, err := exec.CommandContext(t.Context(), sshClient, "-V").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "OpenSSH") {
		t.Skip("OpenSSH client unavailable")
	}
	match := regexp.MustCompile(`OpenSSH_(?:for_Windows_)?([0-9]+)\.`).FindStringSubmatch(string(version))
	if len(match) != 2 {
		t.Skip("unrecognized OpenSSH version")
	}
	major, err := strconv.Atoi(match[1])
	if err != nil || major < 9 {
		t.Skip("requires OpenSSH 9+ with default SFTP transport")
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
	local := filepath.Join(t.TempDir(), "payload.txt")
	writeSCPTestFile(t, local, "OpenSSH local fixture payload")
	for _, flags := range []string{"-q", "-qv", "-vq", "-vqv"} {
		t.Run(flags, func(t *testing.T) {
			args := []string{"-S", sshClient, "-F", os.DevNull, "-o", "BatchMode=yes", "-o", "IdentityAgent=none", "-o", "IdentityFile=none", "-o", "CertificateFile=none", "-o", "GlobalKnownHostsFile=none", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + knownHosts, "-P", port, flags, local, "test@" + host + ":system-" + flags + ".txt"}
			output, err := exec.CommandContext(fixture.ctx, client, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("system scp: %v\n%s", err, output)
			}
			text := string(output)
			if got := strings.Contains(text, "debug1: Connecting to"); got != (flags == "-qv") {
				t.Fatalf("OpenSSH SSH verbosity changed: %s", text)
			}
			if got := strings.Contains(text, "Executing:"); got != (flags != "-q") {
				t.Fatalf("OpenSSH SCP verbosity changed: %s", text)
			}
			if flags == "-q" && text != "" {
				t.Fatalf("OpenSSH quiet transfer emitted output: %s", text)
			}
			assertSCPTestFile(t, filepath.Join(fixture.home, "system-"+flags+".txt"), "OpenSSH local fixture payload")
		})
	}
}
