package cli

import (
	"io"

	"github.com/wentf9/xops-cli/internal/entry/cli/cmdasset"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdops"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdssh"
	"github.com/wentf9/xops-cli/internal/entry/cli/cmdtransfer"
)

const rootHelpText = `Usage:
  xops [global flags] <command> [flags] [args...]

Global Flags:
  --json              Emit canonical JSON/v2 output on stdout
  --policy <profile>  Security policy profile: direct_operator, strict_operator, strict_agent
  -F <configfile>     Alternative per-user OpenSSH configuration file ("none" to disable)
  -h, --help          Show help information
  -V, --version       Print XOps build version metadata

Commands:
  ssh                 Connect to a remote host, execute a command, or manage forwards/mux
  exec                Execute a single or batch command across one or more target nodes
  scp                 Upload or download files over parallel SFTP/SCP transfer
  sftp                Launch interactive SFTP shell or execute a single remote SFTP operation
  hosts               Manage inventory hosts, identities, nodes, DAG validation & secret refs
  creds, vault        Manage encrypted credential vault lifecycle, diagnostics & safe GC
  tunnel, forward     Start local (-L), remote (-R), dynamic SOCKS5 (-D), or TUN (-w) forwards
  mux                 Control OpenSSH-compatible ControlMaster multiplexers
  playbook            Validate or run declarative v2 automation playbooks (YAML/JSON)
  doctor              Run inventory and credential vault health diagnostics
  audit               Reconcile crashed audit locks or inspect local audit log records
  config              Inspect registered import formats or import external configurations
  mcp                 Start the Model Context Protocol (MCP) server (stdio or Streamable HTTP)
  tui                 Launch the interactive Bubble Tea v2 terminal workbench
  version             Print XOps build version metadata without initializing Engine state
  help                Show help for a specific command

Run 'xops <command> --help' or 'xops help <command>' for details on a specific command.
`

const versionHelpText = `Usage:
  xops version [--json]

Print XOps version, commit, build time, and Go toolchain metadata without initializing Engine state.
`

func writeRootHelp(w io.Writer) {
	_, _ = io.WriteString(w, rootHelpText)
}

func writeVersionHelp(w io.Writer) {
	_, _ = io.WriteString(w, versionHelpText)
}

func lookupHelpTopic(topic string) (string, bool) {
	switch topic {
	case "ssh":
		return cmdssh.SSHHelpText(), true
	case "exec":
		return cmdssh.ExecHelpText(), true
	case "tunnel", "forward":
		return cmdssh.TunnelHelpText(), true
	case "mux":
		return cmdssh.MuxHelpText(), true
	case "scp":
		return cmdtransfer.SCPHelpText(), true
	case "sftp":
		return cmdtransfer.SFTPHelpText(), true
	case "hosts", "host", "inventory":
		return cmdasset.HostsHelpText(), true
	case "creds", "cred", "vault":
		return cmdasset.VaultHelpText(), true
	case "config":
		return cmdasset.ConfigHelpText(), true
	case "playbook", "play":
		return cmdops.PlaybookHelpText(), true
	case "doctor":
		return cmdops.DoctorHelpText(), true
	case "audit":
		return cmdops.AuditHelpText(), true
	case "mcp":
		return cmdops.MCPHelpText(), true
	case "tui":
		return cmdops.TUIHelpText(), true
	case "version":
		return versionHelpText, true
	default:
		return "", false
	}
}
