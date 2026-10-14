# Installation and setup

## 1. Install

Download the binary for your OS and architecture from [GitHub Releases](https://github.com/wentf9/xops-cli/releases):
- **Linux / macOS**: Place `xops` in a directory on your `PATH` (such as `/usr/local/bin`).
- **Windows**: Add the folder containing `xops.exe` to `PATH`, or run `./xops.exe` directly in PowerShell.

Install on Linux / macOS with Bash (amd64 / arm64, no administrator privileges required):

```bash
curl -fsSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash

# Specify the installation directory
curl -fsSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash -s -- --install-dir "$HOME/tools/xops"
```

On Windows, install the latest release from PowerShell 5.1+ (x64 / ARM64, no administrator privileges required):

```powershell
irm https://raw.githubusercontent.com/wentf9/xops-cli/master/install.ps1 | iex

# To customize the directory, download the script and pass a parameter:
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/wentf9/xops-cli/master/install.ps1 -OutFile install.ps1
.\install.ps1 -InstallDir "$HOME\tools\xops"
```

The scripts detect the system architecture, install to `%LOCALAPPDATA%\Programs\xops\xops.exe` on Windows or `$HOME/.local/bin/xops` on Linux / macOS, and configure PATH. Restart other open terminals before running `xops` there. Running the installer again updates the binary; if XOps is running, close it before retrying.

To build from source (**Go 1.26+** required; the Makefile supports Linux, macOS, and Windows CMD / PowerShell / Git Bash):

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
./bin/xops --help
```

On Windows, `make build` produces `bin/xops.exe`; on any platform, `make windows` cross-compiles the Windows binary. Pass `make GOPATH_BIN=/path/to/bin build` to specify the Go tool directory, or `GOPATH_BIN=` to skip automatic discovery and keep the current `PATH`.

## 2. Import SSH config or connect directly

If you already have hosts in `~/.ssh/config`, run `xops init` to import all non-wildcard `Host` entries into `~/.xops/xops_config.yaml` (local read only, no network connections, and safe to re-run without overwriting existing nodes):

```bash
xops init
xops host list
```

You can also import from a custom OpenSSH file or create an empty configuration:

```bash
xops init --ssh-config ~/.ssh/config.work
xops init --skip-ssh-import
```

You can also connect directly without running `xops init` first. On first connection, verify the host key fingerprint through a trusted channel and type `yes` (or `no` to abort; do not treat a changed-fingerprint warning as a normal first connection):

```bash
xops ssh user@192.0.2.10
```

Once the SSH handshake and authentication succeed, XOps saves the node and encrypts the verified password or key passphrase in `~/.xops/credentials/` so you do not have to type it again next time. See [credential storage](./credentials) for saving policies and backups.

## 3. Next steps

| Task | Example command | Guide |
| --- | --- | --- |
| Manage hosts, metrics, and logs in the terminal UI | `xops tui` | [Terminal interface](./tui) |
| Bulk-import hosts from CSV with tags | `xops host import hosts.csv --tag web` | [Hosts and identities](./hosts) |
| Run commands or scripts in parallel by tag | `xops exec --tag web -c 'uptime'` | [Command execution](./exec) |
| Transfer files or open an interactive SFTP shell | `xops scp ./app.tar.gz web-01:~/tmp/` | [SFTP and file transfer](./sftp) |
| Run declarative YAML Playbooks or start the MCP server | `xops play deploy.yaml` | [Playbooks and MCP](./automation) |

Switch CLI output language at any time with `--lang zh` or `--lang en`. This documentation tracks `master`; check `xops <command> --help` for options in your installed build.
