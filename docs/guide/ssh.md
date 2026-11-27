# SSH、隧道与多路复用

XOps v2 在命令体验上对齐 OpenSSH `ssh(1)`，同时基于纯函数四层策略求解、结构化并发连接池与受监督多路复用守护（`muxdaemon`）提供跨平台一致的连接、转发与复用能力。

## 1. 交互式 SSH 与单次命令（`xops ssh`）

```bash
# 使用资产节点别名或 ~/.ssh/config 虚拟主机登录
xops ssh web-01

# 临时直连地址或覆写端口、用户、私钥与跳板链
xops ssh -p 2222 -l deploy -i ~/.ssh/id_ed25519 192.0.2.10
xops ssh -J bastion1,bastion2 deploy@192.0.2.10

# 传递 OpenSSH -o 选项与替代配置文件（-F none 禁用 ~/.ssh/config）
xops ssh -o ConnectTimeout=10 -o ServerAliveInterval=30 -F ~/.ssh/config.work web-01

# 分配或禁用伪终端执行远端命令（遇到首个位置参数后，后续 -flag 完整透传给远端命令）
xops ssh -t web-01 top
xops ssh -tt web-01 htop
xops ssh -T web-01 uname -a

# 非交互命令可附加 --json 输出规范 JSON/v2 结果
xops ssh --json web-01 uname -a
```

### 常用 OpenSSH 兼容标志

| 标志 | 说明 |
| --- | --- |
| `-p <port>` / `-l <user>` | 覆写远端端口 / 登录用户名 |
| `-i <identity_file>` | 指定私钥文件（可重复） |
| `-J <proxy_jump>` | 单级或多级跳板链（逗号分隔，如 `jump1,jump2`） |
| `-o <Key=Value>` | OpenSSH 选项覆盖（可重复，按 FirstWins 折叠入 Tier-1） |
| `-F <configfile>` | 替代 OpenSSH 配置文件路径（传 `none` 禁用） |
| `-t` / `-tt` / `-T` | 请求 PTY / 即使本地无 TTY 仍强制分配 PTY / 禁用 PTY |
| `-L` / `-R` / `-D` / `-w` | 本地转发、远端转发、动态 SOCKS5、TUN/TAP 转发（均可重复） |
| `-W <host:port>` | 标准输入/输出 TCP 转发（适合作为 `ProxyCommand` 目标） |
| `-M` / `-MM` | 启用 ControlMaster（`-M` = `yes`，`-MM` = `ask`） |
| `-S <ctl_path>` | 指定 ControlPath 控制套接字路径（传 `none` 禁用） |
| `-O <ctl_cmd>` | 控制活跃 ControlMaster：`check` \| `forward` \| `cancel` \| `exit` \| `stop` \| `proxy` |
| `-N` / `-f` | 不执行远端命令 / 移交后台 `muxdaemon` 运行（需配合 `-N`/`-M` 或转发规则，不可附带远端命令） |
| `--tun-mode <mode>` | `-w` 隧道模式：`point_to_point`（默认）\| `ethernet` |

> **提权说明**：在 XOps v2 中，非交互与受控 `sudo`/`su`/`doas` 提权由 [`xops exec --sudo|--su|--doas`](./exec) 统一承载（支持从 Vault 引用 `--password-ref` 或 `--prompt-password` 交互采集，零明文参数）。

## 2. SSH 隧道与转发（`xops tunnel` / `xops forward`）

除通过 `xops ssh -N -L/-R/-D/-w` 启动外，XOps v2 提供专用 `xops tunnel`（别名 `forward`）命令族，支持统一 `--json` 就绪摘要与干净信号退出清理：

```bash
# 本地端口转发（-L）：本地 127.0.0.1:18080 -> 远端 127.0.0.1:80
xops tunnel local web-01 127.0.0.1:18080:127.0.0.1:80

# 远端端口转发（-R）：远端 127.0.0.1:9000 -> 本地 127.0.0.1:3000
xops tunnel remote worker-01 127.0.0.1:9000:127.0.0.1:3000

# 动态 SOCKS5 代理（-D）
xops tunnel dynamic web-01 127.0.0.1:1080

# 同一会话组合多条转发规则（含 StreamLocal Unix 套接字）
xops tunnel start -L 127.0.0.1:5432:127.0.0.1:5432 -L unix:/tmp/app.sock:/run/app.sock -D 127.0.0.1:1080 web-01

# TUN/TAP 隧道转发（-w / tun）
xops tunnel tun --tun-mode point_to_point gateway-01 0:0
```

### 平台支持说明

- **TCP `-L`/`-R`/`-D` 与 StreamLocal**：全平台（Linux / macOS / Windows）均原生支持。
- **TUN/TAP (`-w` / `tunnel tun`)**：Linux 通过 `/dev/net/tun`、macOS 通过 `AF_SYSTEM` `utun` 原生支持（需相应内核设备权限）；Windows 与 FreeBSD 返回明确的 `unsupported` 错误。
- **安全与生命周期**：所有转发在收到 `SIGINT`/`SIGTERM` 时严格按逆序排空并关闭本地监听与远端通道；默认请绑定回环地址 `127.0.0.1`，仅在明确授权时暴露非回环网卡。

## 3. ControlMaster 多路复用与后台守护（`xops mux`）

XOps v2 支持 OpenSSH 兼容的 ControlMaster 协议与受结构化并发监督的 `muxdaemon`，可通过 `xops ssh -M/-S/-O/-f` 或专用 `xops mux` 命令操作：

```bash
# 1. 启动 ControlMaster（-f / --daemon 移交 muxdaemon，并支持 ControlPersist 空闲保活）
xops mux start -S ~/.xops/mux-%C -o ControlPersist=10m --daemon web-01
# 等价 OpenSSH 写法：
xops ssh -M -f -N -S ~/.xops/mux-%C -o ControlPersist=10m web-01

# 2. 检查主控连接存活状态与 PID
xops mux check -S ~/.xops/mux-%C web-01 --json
xops ssh -O check -S ~/.xops/mux-%C web-01

# 3. 向已运行的主控动态增删转发
xops mux forward -S ~/.xops/mux-%C -L 127.0.0.1:18080:127.0.0.1:80 web-01
xops mux cancel  -S ~/.xops/mux-%C -L 127.0.0.1:18080:127.0.0.1:80 web-01

# 4. 通过主控以 stdio 代理模式运行（-O proxy）
xops mux proxy -S ~/.xops/mux-%C web-01

# 5. 优雅停止接受新会话（stop）或立即退出主控（exit）
xops mux stop -S ~/.xops/mux-%C web-01
xops mux exit -S ~/.xops/mux-%C web-01
```

### ControlMaster 关键机制

- **安全套接字与残余探测**：本地控制套接字经 `core/osfs` 创建并校验所有者权限（Linux/macOS 使用 `AF_UNIX` 对端凭证与 `0600` 权限）；若检测到异常崩溃遗留的死套接字，自动探活并安全清理后再绑定。
- **配置层控制**：可在 `~/.xops/config.yaml` 的节点或全局 `options.control` 中持久化 `master`（`no`/`yes`/`auto`/`ask`/`autoask`）、`path`（支持 `%C`/`%h`/`%p`/`%r` 等 OpenSSH 令牌）与 `persist`（如 `10m`/`yes`/`no`）。
- **无交互后台限制**：`xops mux daemon` 与 `ssh -f` 运行于非交互输入流下；若配置了 `ControlMaster=ask/autoask` 或需人工解锁密钥，将会严格失败关闭而非挂起等待。

## 4. 主机密钥信任（KnownHosts & SSHFP）

- 默认遵循 `StrictHostKeyChecking=ask`（交互式终端核对指纹确认，非交互或 `StrictHostKeyChecking=yes` 下遇到未知主机密钥严格失败关闭返回 `host_key_unknown`）。
- 已知主机指纹失配或吊销分别返回 `host_key_mismatch` 与 `host_key_revoked`，严禁自动忽略。
- 本地 `known_hosts` 读写全程走 `ScopedRootFS` 与旁路锁，避免并发写损坏。
