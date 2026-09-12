package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
)

func TestArgumentRouting(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args, want []string
	}{
		{"global", []string{"--color", "never", "exec", "--host", "vps", "uname", "-a"}, []string{"uname", "-a"}},
		{"inline", []string{"--color=never", "ssh", "-p3922", "vps", "uname", "-a"}, []string{"vps", "uname", "-a"}},
		{"after host", []string{"ssh", "vps", "--color", "never", "--sudo", "uname", "-a"}, []string{"vps", "uname", "-a"}},
		{"explicit separator", []string{"exec", "--host", "vps", "--", "echo", "--color", "always"}, []string{"echo", "--color", "always"}},
		{"tag", []string{"exec", "--tag", "test", "echo", "--help"}, []string{"echo", "--help"}},
		{"command flag", []string{"exec", "--host", "vps", "-c", "echo --help"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd()
			initRootFlags(root)
			registerCommands(root)
			root.PersistentPreRunE = nil
			var got []string
			for _, c := range root.Commands() {
				if c.Name() == "exec" || c.Name() == "ssh" {
					c.RunE = func(_ *cobra.Command, args []string) error { got = append([]string(nil), args...); return nil }
				}
			}
			before := append([]string(nil), tc.args...)
			root.SetArgs(normalizeCommandArgs(root, tc.args))
			if err := root.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			if !reflect.DeepEqual(tc.args, before) {
				t.Fatal("mutated input")
			}
		})
	}
}
