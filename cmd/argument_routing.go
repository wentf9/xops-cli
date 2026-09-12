package cmd

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// normalizeCommandArgs locates the subcommand in the original token stream.
// Cobra.Find removes tokens, so its remainder is not an offset into args.
func normalizeCommandArgs(root *cobra.Command, args []string) []string {
	result := append([]string(nil), args...)
	for i := 0; i < len(args); {
		if args[i] == "--" {
			return result
		}
		if strings.HasPrefix(args[i], "-") {
			n, _, ok := routingFlag(root, args[i])
			if !ok { // Leave invalid flags to Cobra for diagnostics.
				return result
			}
			i += n
			continue
		}
		command, _, err := root.Find([]string{args[i]})
		if err != nil || (command.Name() != "ssh" && command.Name() != "exec") {
			return result
		}
		return append(result[:i+1], preprocessSubArgs(args[i+1:], command)...)
	}
	return result
}

func routingLookup(cmd *cobra.Command, name string, short bool) *pflag.Flag {
	for _, fs := range []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags(), cmd.InheritedFlags()} {
		var flag *pflag.Flag
		if short {
			flag = fs.ShorthandLookup(name)
		} else {
			flag = fs.Lookup(name)
		}
		if flag != nil {
			return flag
		}
	}
	return nil
}

// routingFlag returns the number of argv tokens consumed, registered flag
// names, and whether the token consists entirely of known flags.
func routingFlag(cmd *cobra.Command, arg string) (int, []string, bool) {
	if strings.HasPrefix(arg, "--") {
		name, _, inline := strings.Cut(arg[2:], "=")
		f := routingLookup(cmd, name, false)
		if f == nil {
			return 0, nil, false
		}
		if !inline && f.NoOptDefVal == "" {
			return 2, []string{f.Name}, true
		}
		return 1, []string{f.Name}, true
	}
	if len(arg) < 2 || arg[0] != '-' {
		return 0, nil, false
	}
	var names []string
	for i := 1; i < len(arg); i++ {
		f := routingLookup(cmd, arg[i:i+1], true)
		if f == nil {
			return 0, nil, false
		}
		names = append(names, f.Name)
		if f.NoOptDefVal == "" {
			if i+1 == len(arg) {
				return 2, names, true
			}
			return 1, names, true
		}
		if i+1 < len(arg) && arg[i+1] == '=' {
			return 1, names, true
		}
	}
	return 1, names, true
}

// preprocessSubArgs preserves flags before the remote command, including
// flags after a positional host. An explicit separator always wins.
func preprocessSubArgs(args []string, cmd *cobra.Command) []string {
	target := false
	for i := 0; i < len(args); {
		if args[i] == "--" {
			return append([]string(nil), args...)
		}
		if strings.HasPrefix(args[i], "-") {
			n, names, ok := routingFlag(cmd, args[i])
			if !ok {
				if target {
					return separateRemoteArgs(args, i)
				}
				return append([]string(nil), args...)
			}
			for _, name := range names {
				if name == "host" || (cmd.Name() == "exec" && (name == "tag" || name == "ifile")) {
					target = true
				}
			}
			i += n
			continue
		}
		if target {
			return separateRemoteArgs(args, i)
		}
		target = true
		i++
	}
	return append([]string(nil), args...)
}

func separateRemoteArgs(args []string, offset int) []string {
	result := make([]string, 0, len(args)+1)
	result = append(result, args[:offset]...)
	result = append(result, "--")
	return append(result, args[offset:]...)
}
