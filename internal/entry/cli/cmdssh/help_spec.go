package cmdssh

// SSHHelpText 返回 `xops ssh` 的帮助文档文本。
func SSHHelpText() string {
	return `Usage:
  xops ssh [flags] [user@]host [command [args...]]

Flags:
  -p <port>              Port to connect to on the remote host
  -l <user>              Login name on the remote machine
  -i <identity_file>     Private key file for public key authentication (repeatable)
  -J <proxy_jump>        Jump host destination chain (e.g. jump1,jump2)
  -L <[bind:]port:host:port | unix:...>  Local port or StreamLocal forwarding (repeatable)
  -R <[bind:]port:host:port | unix:...>  Remote port or StreamLocal forwarding (repeatable)
  -D <[bind:]port>       Dynamic SOCKS5 forwarding (repeatable)
  -w <local[:remote]>    TUN/TAP device forwarding (repeatable)
  -W <host:port>         Standard input/output forwarding target
  -o <Key=Value>         OpenSSH option override (repeatable)
  -M                     Place connection in ControlMaster mode (-MM for ask)
  -S <ctl_path>          Location of ControlMaster control socket ("none" to disable)
  -O <ctl_cmd>           Control active ControlMaster (check|forward|cancel|exit|stop|proxy)
  -N                     Do not execute a remote command (useful with -L/-R/-D/-w/-M)
  -f                     Background / hand off to muxdaemon before execution
  -t                     Force pseudo-terminal allocation (-tt forces even without local TTY)
  -T                     Disable pseudo-terminal allocation
  -F <configfile>        Alternative per-user OpenSSH configuration file ("none" to disable)
  --tun-mode <mode>      TUN forwarding mode: point_to_point (default) | ethernet
  --policy <profile>     Policy profile: direct_operator | strict | strict_agent
  --json                 Emit canonical JSON/v2 output (non-interactive commands & mux control)
  -h, --help             Show this help message
`
}

// ExecHelpText 返回 `xops exec` 的帮助文档文本。
func ExecHelpText() string {
	return `Usage:
  xops exec [flags] <target> [--] <command [args...]>
  xops exec [flags] (--all | --nodes <id,...> | --tags <tag,...> | --target <t>...) -- <command [args...]>

Flags:
  -p/-l/-i/-J/-o/-F/-t/-T   Standard OpenSSH connection and TTY flags
  --all                     Target all managed inventory nodes (batch mode)
  --nodes <id,...>          Select managed nodes by ID (repeatable, batch mode)
  --tags <tag,...>          Select managed nodes by tag (repeatable, batch mode)
  --target <spec,...>       Explicit target specs (repeatable)
  --exclude-nodes <id,...>  Exclude node IDs in batch mode
  --exclude-tags <tag,...>  Exclude tags in batch mode
  --concurrency <n>         Maximum concurrent nodes in batch mode
  --fail-fast               Cancel remaining nodes on first batch failure
  --stream                  Stream live prefixed output lines in batch mode
  --out-dir <dir>           Write per-node stdout/stderr logs into ScopedRootFS directory
  --max-output-bytes <n>    Maximum captured output bytes per node
  --timeout <duration>      Per-command execution timeout (e.g. 30s, 5m)
  --dialect <dialect>       Launch dialect: posix | powershell | cmd | raw
  --interpreter <interp>    Interpreter: server | sh | bash | zsh | powershell | pwsh | cmd
  --login <mode>            Login mode: disabled | login | inherit
  --workdir <remote_path>   Remote working directory
  --env <KEY=VALUE>         Remote environment variable override (repeatable)
  --sudo | --su | --doas    Execute single-target command with privilege escalation
  --privilege-user <user>   Target escalation user (e.g. root)
  --password-ref <s/i>      Vault secret reference for privilege password
  --prompt-password         Prompt interactively for privilege password
  --policy <profile>        Policy profile: direct_operator | strict | strict_agent
  --json                    Emit canonical JSON/v2 output
  -h, --help                Show this help message
`
}

// TunnelHelpText 返回 `xops tunnel` / `xops forward` 的帮助文档文本。
func TunnelHelpText() string {
	return `Usage:
  xops tunnel [start] [ssh-flags] (-L|-R|-D|-w <spec>)... <target>
  xops tunnel local   [ssh-flags] <target> <[bind:]port:host:port>
  xops tunnel remote  [ssh-flags] <target> <[bind:]port:host:port>
  xops tunnel dynamic [ssh-flags] <target> <[bind:]port>
  xops tunnel tun     [ssh-flags] [--tun-mode point_to_point|ethernet] <target> <local[:remote]>

Aliases:
  forward

Flags:
  -p/-l/-i/-J/-o/-F        Standard OpenSSH connection options
  -L / -R / -D / -w        OpenSSH forwarding specifications (repeatable)
  --tun-mode <mode>        TUN mode: point_to_point | ethernet
  --policy <profile>       Policy profile: direct_operator | strict | strict_agent
  --json                   Emit canonical JSON/v2 summary
  -h, --help               Show this help message
`
}

// MuxHelpText 返回 `xops mux` 的帮助文档文本。
func MuxHelpText() string {
	return `Usage:
  xops mux start   [ssh-flags] [-S <socket>] [-f|--daemon] [-L/-R/-D/-w ...] <target>
  xops mux check   [ssh-flags] [-S <socket>] <target>
  xops mux forward [ssh-flags] [-S <socket>] (-L|-R|-D|-w <spec>) <target>
  xops mux cancel  [ssh-flags] [-S <socket>] (-L|-R|-D/-w <spec>) <target>
  xops mux exit    [ssh-flags] [-S <socket>] <target>
  xops mux stop    [ssh-flags] [-S <socket>] <target>
  xops mux proxy   [ssh-flags] [-S <socket>] <target>
  xops mux daemon  [ssh-flags] [-S <socket>] [-L/-R/-D/-w ...] <target>

Flags:
  -p/-l/-i/-J/-o/-F        Standard OpenSSH connection options
  -S, --socket <path>      ControlMaster socket path override
  -f, --daemon             Hand off to background muxdaemon runner
  --policy <profile>       Policy profile: direct_operator | strict | strict_agent
  --json                   Emit canonical JSON/v2 output
  -h, --help               Show this help message
`
}
