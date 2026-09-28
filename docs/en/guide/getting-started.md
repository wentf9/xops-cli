# Installation and setup

## Install

Download the binary for your OS and architecture from [GitHub Releases](https://github.com/wentf9/xops-cli/releases). Put `xops` on PATH on Linux/macOS. On Windows, add the directory containing `xops.exe` to PATH or run `./xops.exe` in PowerShell.

Building from source requires **Go 1.26+** (the Makefile natively supports Linux, macOS, and Windows CMD / PowerShell / Git Bash environments):

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
./bin/xops --help
```

On Windows, `make build` automatically produces `bin/xops.exe`. You can also cross-build Windows binaries on any platform with `make windows`.

Use `make GOPATH_BIN=/path/to/bin build` to specify the Go tool directory. Setting `GOPATH_BIN=` skips automatic Go tool directory discovery and preserves the existing `PATH`.

## Initialize configuration

```bash
xops init
xops host list
```

`init` creates `~/.xops/xops_config.yaml` and imports non-wildcard Host entries from `~/.ssh/config` by default. It does not connect to servers. Repeating initialization does not overwrite existing nodes.

```bash
xops init --ssh-config ~/.ssh/config.work
xops init --skip-ssh-import
```

New installations use an offline encrypted credential store. The store and key file are created when a verified password is first saved. See [credential storage](./credentials) for saving policies and backups.

## First connection

```bash
xops ssh user@192.0.2.10
```

Verify a new host's key fingerprint through a trusted channel before entering `yes`. Enter `no` to reject it. A changed fingerprint is not an ordinary first-connection confirmation.

The CLI supports `--lang zh` and `--lang en`. This documentation follows master and may describe unreleased changes. Use `xops <command> --help` for your installed version.
