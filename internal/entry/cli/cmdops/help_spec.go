package cmdops

// PlaybookHelpText 返回 `xops playbook` 的帮助文档文本。
func PlaybookHelpText() string {
	return `Usage:
  xops playbook validate (<file> | --file <file> | --stdin) [--json]
  xops playbook run      [flags] (<file> | --file <file> | --stdin)

Aliases:
  play

Flags:
  -p/-l/-i/-J/-o/-F          Standard OpenSSH connection options
  --file <path>              Playbook vNext (version: 2) YAML or JSON file ("-" for stdin)
  --stdin                    Read Playbook document from stdin
  --target <spec,...>        Explicit target specs overriding selector (repeatable)
  --concurrency <n>          Maximum concurrent target nodes
  --timeout <duration>       Overall playbook timeout (e.g. 5m)
  --var <KEY=VALUE>          Extra template/step variable override (repeatable)
  --scoped-root <dir>        ScopedRootFS source root directory
  --symlink-policy <policy>  reject | contained_relative | follow_operator_source
  --dialect <dialect>        Default launch dialect: posix | powershell | cmd | raw
  --interpreter <interp>     Default interpreter: server | sh | bash | zsh | powershell | pwsh | cmd
  --login <mode>             Default login mode: disabled | login | inherit
  --policy <profile>         Policy profile: direct_operator | strict | strict_agent
  --json                     Emit canonical JSON/v2 report
  -h, --help                 Show this help message
`
}

// DoctorHelpText 返回 `xops doctor` 的帮助文档文本。
func DoctorHelpText() string {
	return `Usage:
  xops doctor [flags]

Flags:
  --scope <scope>       Diagnostic scope: all (default) | inventory | vault
  --check-vault         Verify referenced secrets exist in unlocked vault
  --check-keys          Verify local private key fingerprints
  --skip-vault-probe    Skip probing individual secrets during vault doctor
  --policy <profile>    Policy profile: direct_operator | strict | strict_agent
  --json                Emit canonical JSON/v2 diagnostic report
  -h, --help            Show this help message
`
}

// AuditHelpText 返回 `xops audit` 的帮助文档文本。
func AuditHelpText() string {
	return `Usage:
  xops audit reconcile [--json]
  xops audit list      [--limit N] [--phase <p>] [--outcome <o>] [--node <id>] [--op-id <id>] [--trace-id <id>] [--json]
  xops audit tail      [--limit N] [--phase <p>] [--outcome <o>] [--node <id>] [--json]
  xops audit inspect   <operation_id> [--json]

Flags:
  --limit <n>           Maximum number of audit records to return (default 50)
  --phase <phase>       Filter by phase: denied | authorized | finalized
  --outcome <outcome>   Filter by outcome: pending | denied | succeeded | failed | canceled | escalated | aborted_by_crash | outcome_unknown
  --node <id>           Filter by target node ID
  --op-id <id>          Filter by OperationID
  --trace-id <id>       Filter by TraceID
  --policy <profile>    Policy profile: direct_operator | strict | strict_agent
  --json                Emit canonical JSON/v2 output
  -h, --help            Show this help message
`
}

// TUIHelpText 返回 `xops tui` 的帮助文档文本。
func TUIHelpText() string {
	return `Usage:
  xops tui [flags]

Flags:
  --node <id>           Initial focused node ID
  --refresh <duration>  Metrics/projection refresh interval (e.g. 2s)
  --no-alt-screen       Disable alternate screen buffer
  -F <configfile>       Alternative OpenSSH configuration file
  --policy <profile>    Policy profile: direct_operator | strict | strict_agent
  -h, --help            Show this help message
`
}

// MCPHelpText 返回 `xops mcp` 的帮助文档文本。
func MCPHelpText() string {
	return `Usage:
  xops mcp [serve] [flags]

Flags:
  --transport <mode>         Transport mode: stdio (default) | http
  --listen <addr>            HTTP listen address (default 127.0.0.1:8080 when --transport=http)
  --transfer-root <dir>      ScopedRootFS root for MCP file transfers
  --artifact-root <dir>      ScopedRootFS root for MCP GUI/output artifacts
  --allow-non-loopback       Allow binding HTTP listener on non-loopback interfaces
  --allowed-origin <origin>  Allowed HTTP Origin header (repeatable)
  --allowed-host <host>      Allowed HTTP Host header (repeatable)
  -F <configfile>            Alternative OpenSSH configuration file
  --policy <profile>         Policy profile: direct_operator | strict | strict_agent
  -h, --help                 Show this help message
`
}
