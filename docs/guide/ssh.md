# SSH 与提权

`xops ssh` 用于交互式登录主机、执行单条远程命令或建立端口转发隧道。

```bash
# 通过节点别名快速登录
xops ssh web-01

# 指定私钥与用户名登录
xops ssh -i ~/.ssh/id_ed25519 deploy@192.0.2.10

# 通过跳板机（ProxyJump）登录
xops ssh -J bastion.example.com deploy@192.0.2.10
```

直连跳板支持 IP、FQDN 或 `host:port`；不带域名后缀的单标签跳板名称（如 `-J jumphost`）需预先保存为节点或别名。以显式用户名连接同一台主机时，凭据保持独立隔离。

## 执行远程命令与管道脚本

除进入交互式终端外，`xops ssh` 也可以直接在远端执行命令或通过管道运行脚本：

```bash
# 原生执行单条远程命令（默认 server 模式，原样转发给远端默认 Shell）
xops ssh web-01 uptime
xops ssh --host web-01 --interpreter server uname -a

# 显式指定解释器与登录环境（当前 xops ssh 显式执行参数仅在 Linux 客户端开放）
xops ssh --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false id
```

- **解释器选择**：支持 `--interpreter server`（默认，原生透传）、`bash`、`sh`、`zsh`、`fish`、`powershell`、`pwsh` 及 `cmd`（注：`xops ssh` 的命令行显式执行参数依赖本地可取消原生输出句柄，当前仅在 Linux 客户端支持；Windows / macOS 客户端可通过[节点配置](./hosts#节点执行环境配置-execution)或改用 `xops exec`）。
- **登录环境控制**：使用 `bash`、`zsh` 或 `fish` 时可通过 `--login-shell` 控制是否加载登录环境；`--no-login` 为 Bash 兼容参数（等效于非登录 `bash -c`）；`server` 模式不接受登录选项。
- **输入流与 Shell 路由**：
  - **终端无命令**：标准输入为终端且未传命令时，打开交互式 PTY 登录 Shell。
  - **管道脚本（如 `cat script.sh | xops ssh web-01`）**：根据目标节点的执行配置自动路由——若节点为 `server`（默认），启动无 PTY 的原生 Shell 会话流式执行并保留退出码；若节点配置为 `bash`、`sh`、`zsh` 或 `fish`，则启动对应解释器读取标准输入脚本并应用节点的登录配置。
  - **空命令保护**：显式传入空字符串（如 `xops ssh web-01 ""`）会直接报错拒绝，不会误打开交互式 Shell。
- **取消与输出保护**：执行期间按 `Ctrl+C` 或超时会主动中断 SSH 会话并回收本地终端、管道与文件句柄。

## 首次连接自动保存节点

通过 `ssh`、`sftp`、`scp` 或 `exec` 首次连接新主机时，XOps 先在内存中准备连接信息，**仅在 SSH 握手和身份认证成功后**才将节点、主机和身份写入配置：
- 连接超时、拒绝连接、认证失败或认证前取消不会留下垃圾节点。
- 节点保存在打开 Shell 或执行命令之前完成，后续命令失败不会删除已认证节点；已有节点连接失败也不会被删除。
- `--remember never` 仅禁止保存密码/口令机密，认证成功的节点地址信息仍会保存。

例如，首次执行 `xops ssh root@192.0.2.10`（默认 22 端口）连接失败不会创建 `:22` 节点；随后执行 `xops ssh root@192.0.2.10:2222` 认证成功后仅保存 `:2222` 节点，下次省略端口即可直接匹配它（若同一主机保存了多个不同端口，仍需指定端口或使用别名）。

若保存节点时写入失败，XOps 会报错并关闭尚未交付的连接；若配置文件已替换但目录同步（fsync）失败，则保留已生效配置而不回滚。

## Sudo / Su 提权

```bash
# 打开提权后的交互式 Shell
xops ssh --sudo web-01

# 在 PTY 下以提权身份执行单条命令
xops exec -x --sudo web-01 id
```

提权方式由节点的 `sudo_mode` 配置决定（支持 `auto`、`root`、`sudoer` 免密、`sudo` 密码、`su` 密码）：
- **禁止 root 直接登录的主机**：可配置为 `su` 模式，使用普通用户建立 SSH 连接后再通过 `su` 和 root 密码切换身份，无需开放 `PermitRootLogin`。
- **传统 `sudo` 与 `sudo-rs` 兼容**：自动提权认证会过滤远端密码提示与 `sudo-rs` 的星号回显（兼容带或不带尾随空格的 PAM `Password:` 提示）；缺少凭据或密码被拒时会在本地安全提示输入。`exec -x --sudo` 仅输出命令本身的结果，不回显多余的 root 提示符。
- **多 Shell 提权支持（`bash` / `sh` / `zsh` / `fish`）**：
  - 节点配置 `launch_dialect: fish` + `interpreter: fish`（或 `bash`/`sh`/`zsh`），或配置 `launch_dialect: posix` + `interpreter: zsh` 后，均可使用 `xops ssh --sudo`、`xops exec --sudo` 和 Playbook `sudo: true`。
  - 认证握手固定在 `/bin/sh` 中完成（`su` 通过 `-s /bin/sh` 固定控制 Shell，目标系统需支持该参数，见 [su 手册](https://man7.org/linux/man-pages/man1/su.1.html)），认证通过后再启动目标解释器，确保密码、握手确认与用户 `stdin` 严格隔离。
  - CLI 显式 `--interpreter` 参数暂不支持与 `--sudo` 同时传入，请在节点或 Playbook 的 `execution` 中配置。

## 端口转发与隧道

```bash
# 本地转发（-L）：将本机 127.0.0.1:8080 转发至远端看到的 127.0.0.1:80
xops ssh -L 8080:127.0.0.1:80 -N web-01

# 动态 SOCKS5 代理（-D）：在本机 127.0.0.1:1080 开启 SOCKS5 代理
xops ssh -D 1080 -N web-01

# 远程转发（-R）：将远端 127.0.0.1:9000 转发至本机 127.0.0.1:3000
xops ssh -R 9000:127.0.0.1:3000 -N web-01
```

- **绑定与校验时机**：`-L` 和 `-D` 在本地端口收到连接时才按需打开 SSH 通道；`-R` 在启动时立即向服务器申请远端监听（建立与关闭各有 10 秒超时上限），若被服务器拒绝则立即报错退出。
- **单连接故障隔离**：单次转发连接失败（如 `administratively prohibited` 或目标端口未监听）会打印到 `stderr`，但不会中断主 SSH 会话或转发监听器。
- **连接保活与断开退出**：使用 `-L`、`-R`、`-D` 或 `-N` 时自动启用连接监测——连续 15 秒无远端数据时发送 SSH 心跳，等待期间若连续 10 秒既无心跳回复也无数据进展则判定断线，自动关闭本地监听端口并以非零状态退出。后台运行可组合 `-f -N`。
