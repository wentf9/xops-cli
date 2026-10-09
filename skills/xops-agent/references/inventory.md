# Inventory and credentials

## Inspect and initialize

```bash
xops host list
xops host list --tag web
xops host tags
xops identity list
xops credential store list
xops credential doctor
```

Use the actual node IDs/aliases from inventory; tables are human-readable, not a stable JSON API. `xops --color never` removes ANSI colors from captured output. Listing inventory does not test network connectivity.

When initial setup is requested:

```bash
xops init
xops init --ssh-config ~/.ssh/config.work
xops init --skip-ssh-import
```

Choose the appropriate variant. `init` creates Schema v2 configuration, normally imports non-wildcard OpenSSH entries, makes no remote connections, and does not create an encryption key. It can be repeated without overwriting existing nodes.

## Hosts, nodes, identities, and tags

Host represents the network address, Identity represents authentication, and Node combines them. The same address can have multiple users or ports. Explicit `user@host` selects a distinct identity while reusing applicable host/ProxyJump information.

```bash
xops host add --address 192.0.2.10 --user deploy --key ~/.ssh/id_ed25519 --alias web-01 --tags web
xops host edit web-01 --alias web-primary --jump bastion
xops host import --template ./hosts-template.csv
xops host import ./hosts.csv --tag web
xops host tag add web web-01,web-02
xops host tag remove web web-02
xops identity add --name deploy --user deploy --key ~/.ssh/id_ed25519
```

`host edit --alias` replaces the alias list; preserve needed aliases explicitly. A jump name such as `bastion` must resolve to a configured node/alias. CSV import accepts headers `host,port,alias,user,password,key,keypass`; keep CSVs containing secrets private. `--template` exports the import template, not the current host inventory. `host delete NODE` and `identity delete NAME` remove saved assets; inspect the affected references before an authorized deletion.

Host add/import verify SSH by default. Add asks whether to save after verification fails; import normally saves only successful rows and returns nonzero for failed verification. For an explicitly requested offline import use `--skip-verify`; `--save-on-verify-failure` instead attempts verification but saves failed nodes too. These import options are mutually exclusive. Use canonical `host import`, not removed `loadHost`.

New nodes discovered by SSH, exec, SCP, or SFTP are saved after successful SSH authentication, even when the later command/transfer fails. `--remember never` controls automatic saving of prompted secrets, not node metadata. Failed authentication does not create a new node.

## Noninteractive access

The default store named `file` uses the `encrypted-file` backend with a separate key file. Verified secrets are saved according to the remember policy; first saving can initialize the default vault and key. Available backends also include `system`, `pass`, `helper`, and `none`.

Batch execution and Playbooks need already accessible credentials. A prompt-unlocked vault is not unlocked across separate processes. Linux system-keyring access requires the appropriate user D-Bus/Secret Service session; `locked` is not repaired by adding `exec -x` to a batch job.

Use `credential doctor` to check noninteractive access. It does not initialize an absent vault, prove write access, or verify all encrypted records. Missing credentials, locked stores, and unknown SSH host keys are separate failures; resolve the actual issue in the CLI environment.

For explicit credential changes, inspect the command's current help:

```bash
xops identity credential set --help
xops identity credential delete --help
xops host edit --help
```

Asset/connection commands support `--password-stdin` or `--passphrase-stdin`, not removed plaintext password flags. These stdin options are mutually exclusive; password input also conflicts with key-based options in asset commands. Obtain input from a trusted secret source without placing values in shell arguments. Do not combine a credential stdin stream with a script/SFTP command stream that also requires stdin.

## Store maintenance

Perform maintenance when requested, using existing configuration and backups:

| Need | CLI entry points | Important distinction |
| --- | --- | --- |
| Check store metadata/filesystem | `credential store inspect`, `inspect --verify`, `probe` | Metadata verification is not a complete credential read/write test. `probe` uses temporary filesystem data. |
| Initialize a configured new store | `credential store init` | Do not initialize over a damaged existing vault or generate a replacement for a lost key. |
| Change unlock material / data key | `credential store rewrap` / `reencrypt` | Preserve recovery material until new access is verified. |
| Resume, clone, restore | `credential store resume`, `clone`, `restore` | Read the specific help and keep the source/backup intact. |
| Prune old generations | `credential store prune`, then `prune --apply` | The first command previews; the latter deletes eligible generations. |
| Move references between backends | `credential migrate --dry-run --to STORE`, then `credential migrate --to STORE` | Preview does not prove destination write access; changing only `default_store` does not migrate existing secrets. |
| Clean legacy v1 materials | `credential finalize-migration` | Only after validating migrated access; not a general backend cleanup command. |
| Remove eligible orphan credentials | `credential gc` | Mutates stores and may need keyring access; not a read-only health check. |

For detailed recovery procedures use the [credential](https://wentf9.github.io/xops-cli/guide/credentials), [offline store](https://wentf9.github.io/xops-cli/guide/offline-store), and [migration](https://wentf9.github.io/xops-cli/guide/migration) guides. Back up configuration, the complete vault, and unlock material; configuration references alone cannot restore secrets.
