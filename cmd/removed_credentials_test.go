package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestRemovedCredentialFlagsRejected(t *testing.T) {
	for _, tc := range []struct {
		path  []string
		flags []string
	}{
		{[]string{"ssh"}, []string{"--password", "--passphrase"}},
		{[]string{"sftp"}, []string{"--password", "--passphrase"}},
		{[]string{"scp"}, []string{"--password", "--passphrase"}},
		{[]string{"exec"}, []string{"--password", "--passphrase", "--suPwd"}},
		{[]string{"firewall", "list"}, []string{"--password", "-w"}},
		{[]string{"host", "add"}, []string{"--password", "-P", "--key-pass", "-w"}},
		{[]string{"host", "edit"}, []string{"--password", "-P", "--key-pass", "-w"}},
		{[]string{"inventory", "add"}, []string{"--password", "-P", "--key-pass", "-w"}},
		{[]string{"inventory", "edit"}, []string{"--password", "-P", "--key-pass", "-w"}},
		{[]string{"identity", "add"}, []string{"--password", "-p", "--key-pass", "-K"}},
		{[]string{"identity", "edit"}, []string{"--password", "-p", "--key-pass", "-w"}},
		{[]string{"id", "edit"}, []string{"--password", "--key-pass"}},
		{[]string{"auth", "add"}, []string{"--password", "--key-pass"}},
	} {
		for _, flag := range tc.flags {
			for _, form := range []string{"separate", "equals", "attached"} {
				if form == "attached" && strings.HasPrefix(flag, "--") {
					continue
				}
				t.Run(strings.Join(tc.path, "/")+"/"+flag+"/"+form, func(t *testing.T) {
					root := newRootCmd()
					initRootFlags(root)
					registerCommands(root)
					root.PersistentPreRunE = func(*cobra.Command, []string) error {
						t.Fatal("removed flag reached command initialization")
						return nil
					}
					args := slices.Clone(tc.path)
					switch form {
					case "equals":
						args = append(args, flag+"=synthetic-secret")
					case "attached":
						args = append(args, flag+"synthetic-secret")
					default:
						args = append(args, flag, "synthetic-secret")
					}
					var out bytes.Buffer
					root.SetOut(&out)
					root.SetErr(&out)
					root.SetArgs(normalizeCommandArgs(root, args))
					err := root.ExecuteContext(t.Context())
					if err == nil || !strings.Contains(err.Error(), "unknown") {
						t.Fatalf("removed flag error = %v", err)
					}
					if strings.Contains(out.String()+err.Error(), "synthetic-secret") {
						t.Fatal("removed flag diagnostic exposed its value")
					}
				})
			}
		}
	}
}

func TestRemovedCredentialRouting(t *testing.T) {
	for _, command := range []string{"ssh", "exec"} {
		for _, target := range [][]string{{"node"}, {"--host", "node"}, {"--host=node"}} {
			for _, flag := range []string{"--password", "--passphrase", "--suPwd"} {
				root := newRootCmd()
				initRootFlags(root)
				registerCommands(root)
				cmd, _, err := root.Find([]string{command})
				if err != nil {
					t.Fatal(err)
				}
				args := append(slices.Clone(target), flag+"=synthetic-secret")
				if err := cmd.ParseFlags(preprocessSubArgs(args, cmd)); err == nil || !strings.Contains(err.Error(), "unknown flag") {
					t.Fatalf("%s %v: removed credential became a remote command: %v", command, args, err)
				}
			}
			for _, remote := range [][]string{{"echo", "--password", "remote-value"}, {"--", "--password", "remote-value"}} {
				root := newRootCmd()
				initRootFlags(root)
				registerCommands(root)
				cmd, _, err := root.Find([]string{command})
				if err != nil {
					t.Fatal(err)
				}
				args := append(slices.Clone(target), remote...)
				if err := cmd.ParseFlags(preprocessSubArgs(args, cmd)); err != nil {
					t.Fatalf("remote argument rejected: %v", err)
				}
				if !slices.Contains(cmd.Flags().Args(), "--password") {
					t.Fatal("remote argument lost")
				}
			}
		}
	}
}

type failingCredentialInput struct{ err error }

func (r failingCredentialInput) Read([]byte) (int, error) { return 0, r.err }

func TestInventoryStdinConflictsRejectedBeforeRead(t *testing.T) {
	for _, path := range [][]string{{"identity", "add"}, {"identity", "edit", "admin"}, {"host", "add"}, {"host", "edit", "node"}} {
		for _, flags := range [][]string{
			{"--password-stdin", "--passphrase-stdin"},
			{"--password-stdin", "--key", "key-file"},
		} {
			root := newRootCmd()
			initRootFlags(root)
			registerCommands(root)
			root.PersistentPreRunE = nil
			root.SetIn(failingCredentialInput{errors.New("must not read input")})
			err := executePhase6(t, root, append(slices.Clone(path), flags...)...)
			if err == nil || !strings.Contains(err.Error(), "none of the others can be") {
				t.Fatalf("%v %v: conflict error = %v", path, flags, err)
			}
		}
	}
}

func TestInventoryStdinFailurePreservesConfiguration(t *testing.T) {
	readErr := errors.New("synthetic input failure")
	for _, path := range [][]string{{"identity", "add", "--name", "new"}, {"identity", "edit", "admin"}, {"host", "add", "--address", "127.0.0.2", "--skip-verify"}, {"host", "edit", "node"}} {
		for _, flag := range []string{"--password-stdin", "--passphrase-stdin"} {
			for _, input := range []io.Reader{strings.NewReader("\n"), failingCredentialInput{readErr}} {
				t.Run(strings.Join(path, "/")+"/"+flag, func(t *testing.T) {
					phase6Config(t, config.StoreConfig{Type: config.StoreTypeNone})
					file, _, err := utils.GetConfigFilePath()
					if err != nil {
						t.Fatal(err)
					}
					before, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					root := newRootCmd()
					initRootFlags(root)
					registerCommands(root)
					root.PersistentPreRunE = nil
					root.SetIn(input)
					err = executePhase6(t, root, append(slices.Clone(path), flag)...)
					if err == nil || !strings.Contains(err.Error(), "read inventory credential from stdin") {
						t.Fatalf("input failure = %v", err)
					}
					if _, failing := input.(failingCredentialInput); failing && !errors.Is(err, readErr) {
						t.Fatalf("input error was not preserved: %v", err)
					}
					after, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(before, after) {
						t.Fatal("failed input changed configuration")
					}
				})
			}
		}
	}
}
