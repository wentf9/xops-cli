package cmdasset

// HostsHelpText 返回 `xops hosts` 的帮助文档文本。
func HostsHelpText() string {
	return `Usage:
  xops hosts list              [--kind nodes|hosts|identities|all] [--tag <tag>]
  xops hosts get               [--kind node|host|identity] <id>
  xops hosts resolve           [ssh-flags] <target>
  xops hosts validate-dag
  xops hosts check-secret-refs (--ref <store/item> | --store <store_id>)
  xops hosts create-host       --id <id> --address <host:port> [--alias <a>] [--desc <d>] [--tag <t>] [--expected-revision <rev>]
  xops hosts update-host       --id <id> --address <host:port> [--alias <a>] [--desc <d>] [--tag <t>] [--expected-revision <rev>]
  xops hosts delete-host       [--expected-revision <rev>] <id>
  xops hosts create-identity   --id <id> --user <u> --auth-kind agent|password|private_key [auth-flags] [--expected-revision <rev>]
  xops hosts update-identity   --id <id> --user <u> --auth-kind agent|password|private_key [auth-flags] [--gc-old-secrets]
  xops hosts delete-identity   [--delete-unused-secrets] [--require-unreferenced] [--expected-revision <rev>] <id>
  xops hosts create-node       --id <id> --host <host_id> --identity <identity_id> [--alias <a>] [--tag <t>] [--jump <hops>] [--proxy-command <cmd>]
  xops hosts update-node       --id <id> --host <host_id> --identity <identity_id> [node-flags] [--gc-old-secrets]
  xops hosts delete-node       [--delete-unused-secrets] [--require-unreferenced] [--expected-revision <rev>] <id>

Aliases:
  host, inventory

Common Flags:
  --policy <profile>           Policy profile: direct_operator | strict | strict_agent
  --json                       Emit canonical JSON/v2 output
  -h, --help                   Show this help message
`
}

// VaultHelpText 返回 `xops creds` / `xops vault` 的帮助文档文本。
func VaultHelpText() string {
	return `Usage:
  xops creds status
  xops creds init
  xops creds unlock
  xops creds lock
  xops creds doctor     [--skip-probe]
  xops creds refs       <store>/<item>
  xops creds delete     <store>/<item>
  xops creds gc         <store>/<item> [<store>/<item>...]
  xops creds enroll-key --id <identity_id> --user <u> --key-path <path> --store <store> [--cert-path <p>] [--fingerprint <fp>] [--replace]

Aliases:
  cred, vault

Common Flags:
  --policy <profile>    Policy profile: direct_operator | strict | strict_agent
  --json                Emit canonical JSON/v2 output
  -h, --help            Show this help message
`
}

// ConfigHelpText 返回 `xops config` 的帮助文档文本。
func ConfigHelpText() string {
	return `Usage:
  xops config formats
  xops config import --format <format> [--file <path> | --stdin] [--plan] [--dry-run] [--expected-revision <rev>] [--source-name <name>] [--symlink-policy <policy>]

Flags:
  --format <format>            Registered FormatImporter name (e.g. openssh, csv)
  --file <path>                Input file path (read via OperatorReadFS hook; "-" for stdin)
  --stdin                      Read import payload from stdin
  --plan                       Run read-only PlanImport conflict/DAG preview without writing
  --dry-run                    Run ApplyImport in dry-run mode without persisting
  --expected-revision <rev>    Optional CAS expected revision token
  --source-name <name>         Override logical source label in diagnostics
  --symlink-policy <policy>    reject | contained_relative | follow_operator_source
  --policy <profile>           Policy profile: direct_operator | strict | strict_agent
  --json                       Emit canonical JSON/v2 output
  -h, --help                   Show this help message
`
}
