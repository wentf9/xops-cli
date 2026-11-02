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
		scriptFile                   string
		scriptArgs                   []string
	}{
		{"exec host", []string{"--color", "never", "exec", "--host", "web-01", "uname", "-a"}, "uname -a", "web-01", "", "", "", nil},
		{"exec file", []string{"exec", "--ifile", "hosts.txt", "uname", "-a"}, "uname -a", "", "hosts.txt", "", "", nil},
		{"exec tag", []string{"exec", "--tag", "web", "uname", "-a"}, "uname -a", "", "", "web", "", nil},
		{"exec single", []string{"exec", "--host", "web-01", "uptime"}, "uptime", "web-01", "", "", "", nil},
		{"exec positional", []string{"exec", "web-01", "uname", "-a"}, "uname -a", "web-01", "", "", "", nil},
		{"exec explicit command", []string{"exec", "--ifile", "hosts.txt", "-c", "uname -a"}, "uname -a", "", "hosts.txt", "", "", nil},
		{"exec dash separator", []string{"exec", "--host", "web-01", "--", "uname", "-a"}, "uname -a", "web-01", "", "", "", nil},
		{"exec dash with flags", []string{"exec", "--host", "web-01", "--", "arg1", "-l", "-p", "2222"}, "arg1 -l -p 2222", "web-01", "", "", "", nil},
		{"exec positional with dash", []string{"exec", "web-01", "--", "uname", "-a"}, "uname -a", "web-01", "", "", "", nil},
		{"exec positional user@host with dash", []string{"exec", "user@web-01:22", "--", "echo", "1"}, "echo 1", "web-01", "", "", "", nil},
		{"exec shell with dash args", []string{"exec", "--host", "web-01", "--shell", "check.sh", "--", "arg1", "arg 2", "--flag"}, "", "web-01", "", "", "check.sh", []string{"arg1", "arg 2", "--flag"}},
		{"exec positional shell with dash args", []string{"exec", "web-01", "--shell", "check.sh", "--", "arg1", "arg 2"}, "", "web-01", "", "", "check.sh", []string{"arg1", "arg 2"}},
		{"exec tag with dash", []string{"exec", "--tag", "web", "--", "uname", "-a"}, "uname -a", "", "", "web", "", nil},
		{"exec ifile with dash", []string{"exec", "--ifile", "hosts.txt", "--", "uname", "-a"}, "uname -a", "", "hosts.txt", "", "", nil},
		{"exec tag shell with dash args", []string{"exec", "--tag", "web", "--shell", "check.sh", "--", "arg1", "arg 2"}, "", "", "", "web", "check.sh", []string{"arg1", "arg 2"}},
		{"exec ifile shell with dash args", []string{"exec", "--ifile", "hosts.txt", "--shell", "check.sh", "--", "arg1", "arg 2"}, "", "", "hosts.txt", "", "check.sh", []string{"arg1", "arg 2"}},
		{"exec shell with empty arg", []string{"exec", "--host", "web-01", "--shell", "check.sh", "--", ""}, "", "web-01", "", "", "check.sh", []string{""}},
		{"ssh host", []string{"--color", "never", "ssh", "--host", "web-01", "uname", "-a"}, "uname -a", "web-01", "", "", "", nil},
		{"ssh single", []string{"ssh", "--host=web-01", "uptime"}, "uptime", "web-01", "", "", "", nil},
		{"ssh command looks like host", []string{"ssh", "--host", "web-01", "printf", "user@host:22"}, "printf user@host:22", "web-01", "", "", "", nil},
		{"ssh separator", []string{"ssh", "--host", "web-01", "--", "echo", "--help"}, "echo --help", "web-01", "", "", "", nil},
		{"ssh positional", []string{"ssh", "web-01", "uname", "-a"}, "uname -a", "web-01", "", "", "", nil},
		{"exec command contains separator", []string{"exec", "--host", "web-01", "ls", "-l", "--", "/tmp"}, "ls -l -- /tmp", "web-01", "", "", "", nil},
		{"ssh command contains separator", []string{"ssh", "web-01", "ls", "-a", "--", "/tmp"}, "ls -a -- /tmp", "web-01", "", "", "", nil},
		{"exec whitespace command flag", []string{"exec", "--host", "web-01", "-c", "   "}, "   ", "web-01", "", "", "", nil},
		{"exec whitespace command after dash", []string{"exec", "--host", "web-01", "--", "   "}, "   ", "web-01", "", "", "", nil},
		{"exec multiple empty strings after dash", []string{"exec", "--host", "web-01", "--", "", ""}, " ", "web-01", "", "", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			initRootFlags(root)
			root.PersistentPreRunE = nil
			execOptions := NewExecOptions()
			sshOptions := NewSshOptions()
			execCmd := newCmdExecWithOptions(execOptions)
			sshCmd := newCmdSshWithOptions(sshOptions)
			var command, host, hostFile, tag, scriptFile string
			var scriptArgs []string
			execCmd.RunE = func(c *cobra.Command, args []string) error {
				if err := execOptions.Complete(c, args); err != nil {
					return err
				}
				if err := execOptions.Validate(); err != nil {
					return err
				}
				command, host, hostFile, tag = execOptions.Command, execOptions.Host, execOptions.HostFile, execOptions.Tag
				scriptFile = execOptions.ShellFile
				scriptArgs = execOptions.ScriptArgs
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
			if command != tc.command || host != tc.host || hostFile != tc.hostFile || tag != tc.tag || scriptFile != tc.scriptFile {
				t.Fatalf("got command=%q host=%q file=%q tag=%q scriptFile=%q", command, host, hostFile, tag, scriptFile)
			}
			if len(scriptArgs) != len(tc.scriptArgs) {
				t.Fatalf("got scriptArgs=%v want %v", scriptArgs, tc.scriptArgs)
			}
			for i := range scriptArgs {
				if scriptArgs[i] != tc.scriptArgs[i] {
					t.Fatalf("got scriptArgs[%d]=%q want %q", i, scriptArgs[i], tc.scriptArgs[i])
				}
			}
		})
	}
}

func TestRoutedCommandExtractionErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no host with dash command", []string{"exec", "--", "uname", "-a"}},
		{"cmd flag and dash conflict", []string{"exec", "--host", "web-01", "-c", "uptime", "--", "arg1"}},
		{"shell without separator but has args", []string{"exec", "--host", "web-01", "--shell", "check.sh", "arg1"}},
		{"positional shell without separator but has args", []string{"exec", "web-01", "--shell", "check.sh", "arg1"}},
		{"extra positional before dash with host flag", []string{"exec", "--host", "web-01", "--shell", "check.sh", "node2", "--", "arg1"}},
		{"extra positional before dash without host flag", []string{"exec", "web-01", "--shell", "check.sh", "node2", "--", "arg1"}},
		{"extra positional before dash with tag flag", []string{"exec", "--tag", "web", "--shell", "check.sh", "node2", "--", "arg1"}},
		{"extra positional before dash with ifile flag", []string{"exec", "--ifile", "hosts.txt", "--shell", "check.sh", "node2", "--", "arg1"}},
		{"cmd long flag and dash conflict", []string{"exec", "--host", "web-01", "--cmd", "uptime", "--", "arg1"}},
		{"cmd flag with extra positional", []string{"exec", "--host", "web-01", "-c", "uptime", "extra"}},
		{"positional host with cmd flag and extra positional", []string{"exec", "web-01", "-c", "uptime", "extra"}},
		{"tag shell without separator but has args", []string{"exec", "--tag", "web", "--shell", "check.sh", "arg1"}},
		{"ifile shell without separator but has args", []string{"exec", "--ifile", "hosts.txt", "--shell", "check.sh", "arg1"}},
		{"empty command after dash", []string{"exec", "--host", "web-01", "--"}},
		{"empty string command after dash", []string{"exec", "--host", "web-01", "--", ""}},
		{"empty cmd flag", []string{"exec", "--host", "web-01", "-c", ""}},
		{"nul byte in script args", []string{"exec", "--host", "web-01", "--shell", "check.sh", "--", "bad\x00arg"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			initRootFlags(root)
			root.PersistentPreRunE = nil
			execOptions := NewExecOptions()
			execCmd := newCmdExecWithOptions(execOptions)
			execCmd.RunE = func(c *cobra.Command, args []string) error {
				if err := execOptions.Complete(c, args); err != nil {
					return err
				}
				return execOptions.Validate()
			}
			root.AddCommand(execCmd)
			root.SetArgs(normalizeCommandArgs(root, tc.args))
			if err := root.ExecuteContext(t.Context()); err == nil {
				t.Fatalf("expected error for %s, but succeeded", tc.name)
			}
		})
	}
}

func TestExecOptionsDirectValidation(t *testing.T) {
	t.Run("both command and shell", func(t *testing.T) {
		o := NewExecOptions()
		o.Host = "web-01"
		o.Command = "uptime"
		o.ShellFile = "script.sh"
		if err := o.Validate(); err == nil {
			t.Fatal("expected error when both Command and ShellFile are set, got nil")
		}
	})

	t.Run("script args without shell", func(t *testing.T) {
		o := NewExecOptions()
		o.Host = "web-01"
		o.Command = "uptime"
		o.ScriptArgs = []string{"arg1"}
		if err := o.Validate(); err == nil {
			t.Fatal("expected error when ScriptArgs set without ShellFile, got nil")
		}
	})
}
