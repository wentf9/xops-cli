package cmdtransfer

// SCPHelpText 返回 `xops scp` 的帮助文档文本。
func SCPHelpText() string {
	return `Usage:
  xops scp [flags] <local_src> [user@]host:<remote_dest>
  xops scp [flags] [user@]host:<remote_src> <local_dest>

Flags:
  -P <port>                  Port to connect to on the remote host
  -p, --preserve             Preserve modification times and file modes
  -r, --recursive            Recursively copy entire directories
  -l <user>                  Login name on the remote machine
  -i <identity_file>         Private key file for authentication (repeatable)
  -J <proxy_jump>            Jump host destination chain
  -o <Key=Value>             OpenSSH option override (repeatable)
  -F <configfile>            Alternative per-user OpenSSH configuration file
  --resume                   Resume interrupted transfer with digest verification
  --no-clobber               Refuse to overwrite existing destination file
  --expand-into-dir          Expand uploaded file into existing remote directory
  --symlink-policy <policy>  Symlink policy: reject | contained_relative | follow_operator_source
  --local-root <dir>         Explicit ScopedRootFS root directory for local file I/O
  --perm <octal>             Override remote file permissions (e.g. 0644)
  --chunk-size <bytes>       Chunk size in bytes for parallel transfer
  --concurrency <n>          Maximum parallel chunk workers
  --max-files <n>            Maximum files for recursive transfer
  --max-bytes <n>            Maximum total bytes for transfer
  --expected-digest <sha256> Verify content SHA-256 digest
  --policy <profile>         Policy profile: direct_operator | strict | strict_agent
  --json                     Emit canonical JSON/v2 transfer report
  -h, --help                 Show this help message
`
}

// SFTPHelpText 返回 `xops sftp` 的帮助文档文本。
func SFTPHelpText() string {
	return `Usage:
  xops sftp [ssh-flags] [--dir <remote_dir>] <target>
  xops sftp ls       [ssh-flags] <target> <remote_path>
  xops sftp stat     [ssh-flags] [--follow-symlinks] <target> <remote_path>
  xops sftp read|cat [ssh-flags] [--max-bytes N] <target> <remote_path>
  xops sftp write    [ssh-flags] [--file <local>|-] [--perm 0644] [--no-clobber] [--create-parents] <target> <remote_path>
  xops sftp patch    [ssh-flags] --old <text> --new <text> [--all] <target> <remote_path>
  xops sftp mkdir    [ssh-flags] [--perm 0755] <target> <remote_path>
  xops sftp mv|rename [ssh-flags] [--no-clobber] <target> <old_path> <new_path>
  xops sftp rm       [ssh-flags] <target> <remote_path>
  xops sftp rmdir    [ssh-flags] <target> <remote_path>
  xops sftp chmod    [ssh-flags] <target> <mode> <remote_path>
  xops sftp realpath [ssh-flags] <target> <remote_path>
  xops sftp readlink [ssh-flags] <target> <remote_path>
  xops sftp recover  [ssh-flags] [--prune] [<target> <transfer_id>]

Flags:
  -P/-p/-l/-i/-J/-o/-F       Standard OpenSSH connection options
  --policy <profile>         Policy profile: direct_operator | strict | strict_agent
  --json                     Emit canonical JSON/v2 output
  -h, --help                 Show this help message
`
}
