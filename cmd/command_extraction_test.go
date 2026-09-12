package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// Exercise flag binding, argv routing, completion and validation together;
// only the SSH connection/execution is omitted.
func TestRoutedCommandExtraction(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		args                         []string
		command, host, hostFile, tag string
	}{
		{"exec host", []string{"--color", "never", "exec", "--host", "web-01", "uname", "-a"}, "uname -a", "web-01", "", ""},
		{"exec file", []string{"exec", "--ifile", "hosts.txt", "uname", "-a"}, "uname -a", "", "hosts.txt", ""},
		{"exec tag", []string{"exec", "--tag", "web", "uname", "-a"}, "uname -a", "", "", "web"},
		{"exec single", []string{"exec", "--host", "web-01", "uptime"}, "uptime", "web-01", "", ""},
		{"exec positional", []string{"exec", "web-01", "uname", "-a"}, "uname -a", "web-01", "", ""},
		{"exec explicit command", []string{"exec", "--ifile", "hosts.txt", "-c", "uname -a"}, "uname -a", "", "hosts.txt", ""},
		{"ssh host", []string{"--color", "never", "ssh", "--host", "web-01", "uname", "-a"}, "uname -a", "web-01", "", ""},
		{"ssh single", []string{"ssh", "--host=web-01", "uptime"}, "uptime", "web-01", "", ""},
		{"ssh command looks like host", []string{"ssh", "--host", "web-01", "printf", "user@host:22"}, "printf user@host:22", "web-01", "", ""},
		{"ssh separator", []string{"ssh", "--host", "web-01", "--", "echo", "--help"}, "echo --help", "web-01", "", ""},
		{"ssh positional", []string{"ssh", "web-01", "uname", "-a"}, "uname -a", "web-01", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			initRootFlags(root)
			root.PersistentPreRunE = nil
			execOptions := NewExecOptions()
			sshOptions := NewSshOptions()
			execCmd := newCmdExecWithOptions(execOptions)
			sshCmd := newCmdSshWithOptions(sshOptions)
			var command, host, hostFile, tag string
			execCmd.RunE = func(c *cobra.Command, args []string) error {
				if err := execOptions.Complete(c, args); err != nil {
					return err
				}
				if err := execOptions.Validate(); err != nil {
					return err
				}
				command, host, hostFile, tag = execOptions.Command, execOptions.Host, execOptions.HostFile, execOptions.Tag
				return nil
			}
			sshCmd.RunE = func(c *cobra.Command, args []string) error {
				if err := sshOptions.Complete(c, args); err != nil {
					return err
				}
				if err := sshOptions.Validate(); err != nil {
					return err
				}
				command, host = sshOptions.Command, sshOptions.Target.Selector
				if sshOptions.User != "" || sshOptions.Port != 0 {
					t.Fatalf("command changed connection identity: %+v", sshOptions.Target)
				}
				return nil
			}
			root.AddCommand(execCmd, sshCmd)
			root.SetArgs(normalizeCommandArgs(root, tc.args))
			if err := root.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if command != tc.command || host != tc.host || hostFile != tc.hostFile || tag != tc.tag {
				t.Fatalf("got command=%q host=%q file=%q tag=%q", command, host, hostFile, tag)
			}
		})
	}
}
