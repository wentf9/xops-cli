# CLI 命令参考

本页列出 **XOps v2** 全部顶层命令、别名、核心选项、退出码、规范 JSON/v2 错误信封与环境变量。已安装二进制的精确用法以 `xops <command> --help` 或 `xops help <command>` 为准。

## 全局选项

可置于子命令之前或子命令参数列表内：

| 选项 | 说明 |
| --- | --- |
| `--json`（支持 `=true\|false`） | 在 `stdout` 输出规范确定性 JSON/v2（`Deterministic(true)`）；交互式 `tui` 与交互式 `sftp <target>` 拒绝 `--json` |
| `--policy <profile>` | 安全策略配置档：`direct_operator`（CLI 默认）\| `strict` / `strict_operator` \| `strict_agent`（MCP 默认） |
| `-F <configfile>` / `--ssh-config <file>` | 替代每用户 OpenSSH 配置文件（传 `none` 禁用） |
| `-h` / `--help` | 显示根帮助或子命令帮助 |
| `-V` / `--version` | 输出构建版本元信息（不初始化 Engine） |

## 顶层命令总览

| 命令 | 别名 | 说明 |
| --- | --- | --- |
| `ssh` | — | 交互式登录、执行单条命令、建立 `-L/-R/-D/-w/-W` 转发或 `-M/-S/-O/-f` 多路复用 |
| `exec` | — | 单目标命令、单目标提权（`--sudo`/`--su`/`--doas`）与多节点并发批量执行 |
| `scp` | — | 并行分片可续传文件/目录上传与下载 |
| `sftp` | — | 交互式 SFTP Shell 或 15 个单步原子远端 SFTP 子命令 |
| `hosts` | `host`, `inventory` | 资产图查询、目标解析、Tarjan DAG 校验、凭据引用检查与 CAS CRUD |
| `creds` | `cred`, `vault` | 凭据库初始化/解锁/锁定、健康诊断、交互录入（`enroll-key`/`enroll-password`/`set-node-privilege`）、轮换与安全 GC |
| `tunnel` | `forward` | 独立本地（`-L`）、远端（`-R`）、动态 SOCKS5（`-D`）、StreamLocal 与 TUN（`-w`）转发管理 |
| `mux` | — | OpenSSH 兼容 ControlMaster 多路复用控制与 `muxdaemon` 守护管理 |
| `playbook` | `play` | 声明式 Playbook v2（YAML/JSON）离线校验（`validate`）与编排执行（`run`） |
| `doctor` | — | 整合资产图与凭据库的只读零泄露健康诊断 |
| `audit` | — | 跨进程崩溃锁 O(1) 对账（`reconcile`）与本地 `audit.jsonl` 查询（`list`/`tail`/`inspect`） |
| `config` | — | 列出注册导入格式（`formats`）与导入外部配置（`import --format openssh\|csv`） |
| `mcp` | — | 启动内置 7 工具沙箱 MCP 服务端（`stdio` 或 Streamable HTTP） |
| `tui` | — | 启动 Bubble Tea v2 实时交互式终端工作台 |
| `version` | `-V`, `--version` | 输出版本、Commit、构建时间与 Go 工具链元信息（零 Engine 初始化） |
| `help` | `-h`, `--help` | 查看根帮助或指定主题帮助（`xops help <topic>`） |

## 各命令核心子命令与标志速查

### `ssh`、`tunnel`、`mux`

```text
xops ssh [flags] [user@]host [command [args...]]
  -p <port>  -l <user>  -i <key> (可重复)  -J <jumps>  -o <K=V> (可重复)
  -L/-R/-D/-w <spec> (可重复)  -W <host:port>  --tun-mode point_to_point|ethernet
  -M (-MM)  -S <ctl_path>  -O check|forward|cancel|exit|stop|proxy
  -N  -f  -t (-tt)  -T  -F <cfg>  --policy <p>  --json

xops tunnel [start] [ssh-flags] (-L|-R|-D|-w <spec>)... <target>
xops tunnel local|remote|dynamic|tun [ssh-flags] <target> <spec>

xops mux start|check|forward|cancel|exit|stop|proxy|daemon [ssh-flags] [-S <socket>] [-f|--daemon] [-L/-R/-D/-w ...] <target>
```

### `exec`

```text
xops exec [flags] <target> [--] <command [args...]>
xops exec [flags] (--all | --nodes <id,...> | --tags <tag,...> | --target <t>...) -- <command [args...]>
  批量控制: --exclude-nodes  --exclude-tags  --concurrency <n>  --fail-fast  --stream  --out-dir <dir>
  执行计划: --timeout <dur>  --max-output-bytes <n>  --workdir <remote_path>  --env <K=V>
            --dialect posix|powershell|cmd|raw  --interpreter server|sh|bash|zsh|powershell|pwsh|cmd
            --login disabled|login|inherit
  单机提权: --sudo | --su | --doas  --privilege-user <user>  --password-ref <s/i>  --prompt-password
```

### `scp` 与 `sftp`

```text
xops scp [flags] <local_src> [user@]host:<remote_dest>
xops scp [flags] [user@]host:<remote_src> <local_dest>
  -P <port>  -p|--preserve  -r|--recursive  -l  -i  -J  -o  -F
  --resume  --no-clobber  --expand-into-dir[=bool]  --symlink-policy reject|contained_relative|follow_operator_source
  --local-root <dir>  --perm <octal>  --chunk-size <bytes>  --concurrency <n>
  --max-files <n>  --max-bytes <n>  --expected-digest <sha256>

xops sftp [ssh-flags] [--dir <remote_dir>] <target>
xops sftp ls|stat|read|cat|write|patch|mkdir|mv|rename|rm|rmdir|chmod|realpath|readlink|recover [flags] ...
```

### `hosts`、`creds`、`config`

```text
xops hosts list [--kind nodes|hosts|identities|all] [--tag <tag>]
xops hosts get [--kind node|host|identity] <id>
xops hosts resolve [ssh-flags] <target>
xops hosts validate-dag
xops hosts check-secret-refs (--ref <store/item> | --store <store_id>)
xops hosts create-host|update-host|delete-host ...
xops hosts create-identity|update-identity|delete-identity ...
xops hosts create-node|update-node|delete-node ...

xops creds status|init|unlock|lock|doctor [--skip-probe]
xops creds refs|delete <store>/<item>
xops creds gc <store>/<item> [...]
xops creds enroll-key --id <id> --user <u> --key-path <path> --store <store> [--cert-path <p>] [--fingerprint <fp>] [--replace]
xops creds enroll-password --id <id> --user <u> (--store <store> | --ref <store>/<item>) [--replace] [--desc <d>] [--tag <tags>]
xops creds set-node-privilege --node <node_id> (--store <store> | --ref <store>/<item>) [--expected-revision <rev>]
xops creds rotate <old_store>/<item> (--store <store> | --new-ref <store>/<item>) [--expected-revision <rev>]

xops config formats
xops config import --format openssh|csv [--file <path> | --stdin] [--plan] [--dry-run] [--expected-revision <rev>] [--source-name <name>] [--symlink-policy <policy>]
```

### `playbook`、`doctor`、`audit`、`mcp`、`tui`

```text
xops playbook validate (<file> | --file <file> | --stdin) [--json]
xops playbook run [flags] (<file> | --file <file> | --stdin)
  --target <spec,...>  --concurrency <n>  --timeout <dur>  --var <K=V>  --scoped-root <dir>
  --symlink-policy <p>  --dialect <d>  --interpreter <i>  --login <m>

xops doctor [--scope all|inventory|vault] [--check-vault] [--check-keys] [--skip-vault-probe] [--json]

xops audit reconcile [--json]
xops audit list|tail [--limit N] [--phase denied|authorized|finalized] [--outcome ...] [--node <id>] [--op-id <id>] [--trace-id <id>] [--json]
xops audit inspect <operation_id> [--json]

xops mcp [serve] [--transport stdio|http] [--listen <addr>] [--transfer-root <dir>] [--artifact-root <dir>]
                 [--allow-non-loopback] [--allowed-origin <o>] [--allowed-host <h>]

xops tui [--node <id>] [--refresh <duration>] [--no-alt-screen]
```

## 退出码规范

| 退出码 | 常量 | 含义 |
| --- | --- | --- |
| `0` | `ExitOK` | 成功退出 |
| `1` | `ExitGeneral` | 通用运行期错误、诊断不健康、资产/凭据错误或关闭清理失败 |
| `2` | `ExitUsage` | 命令行子命令、标志或参数语法错误 |
| `128 + N` | `ExitSignalBase + sig` | 远端进程被 POSIX 信号终止（如 `137` = `SIGKILL`、`143` = `SIGTERM`） |
| `255` | `ExitSSHError` | SSH 建连/认证失败、主机密钥拦截、`OutcomeNotStarted`、`OutcomeUnknown` 或审计后置失败 |

## 统一 `--json` 错误信封

当 `--json` 开启且命令失败时，`stdout` 始终输出规范单行 JSON/v2：

```json
{
  "error": "detailed sanitized message",
  "error_code": "approval_required",
  "exit_code": 1,
  "ok": false,
  "approval_challenge": { "digest": "sha256:...", "escalated": false, "envelope": {} }
}
```

常见 `error_code`：`usage_error`、`engine_halted`、`approval_required`、`approval_rejected`、`authorization_denied`、`not_found`、`already_exists`、`revision_conflict`、`still_referenced`、`import_conflict`、`uncertain_durability`、`outcome_unknown`、`vault_unavailable`、`vault_locked`、`secret_not_found`、`auth_failed`、`host_key_unknown`、`host_key_mismatch`、`host_key_revoked`、`dial_failed`、`remote_anchor_mismatch`、`patch_conflict`、`digest_mismatch`、`symlink_rejected`、`limit_exceeded`、`unsupported`、`canceled`、`timeout`。

## 环境变量

| 变量 | 用途 |
| --- | --- |
| `XOPS_HOME` | 覆盖默认状态目录 `~/.xops`（影响 `config.yaml`、`vault/`、`audit.jsonl`、`run/`、`journals/`） |
| `HOME` / `USERPROFILE` | 用户主目录（决定 `~/.ssh/config` 与默认 `~/.xops` 位置） |
| `SSH_AUTH_SOCK` | Unix 下 `ssh-agent` 套接字路径（Windows 自动连接受验 `\\.\pipe\openssh-ssh-agent`） |
| `DBUS_SESSION_BUS_ADDRESS` | Linux `os_keychain`（Secret Service）连接 D-Bus 会话总线地址 |
