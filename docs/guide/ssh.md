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

## 连接诊断

```bash
xops ssh -v web-01
xops ssh -vv web-01 uptime
xops ssh -vvv -N -L 8080:127.0.0.1:80 web-01
xops ssh -v web-01 uptime >output.log 2>ssh.log
```

- `-v` 显示连接、主机密钥验证、认证、协商算法和会话结果；`-vv` 增加请求确认及转发连接信息；`-vvv` 再增加会话清理信息。诊断采用 OpenSSH 风格的 `debug1/2/3:` 前缀，写入 stderr，不改变远程 stdout。
- `-q` 隐藏诊断及隧道就绪提示，不隐藏远程输出、失败报错或安全确认。与 OpenSSH 一样，顺序有影响：`-qv` 启用诊断，`-vq` 关闭诊断，`-vqv` 不立即恢复 DEBUG1。
- `--debug` / `--log-level` 控制另一套内部日志，不受 `-v/-q` 改写。远程命令自己的 `-v` 放在命令名称之后，例如 `xops ssh -v web-01 curl -v https://example.com`。
- 诊断不打印命令、脚本、密码或私钥正文，但包含主机、用户名、指纹及转发地址，分享日志前仍需检查。`-vvv` 不提供完整的 SSH 内部报文跟踪。
- 若某类管道不支持诊断输出，请将 stderr 重定向到普通日志文件。诊断输出失败会使本次操作报错，不代表远程命令未执行，请勿因此直接重试。`-f -N` 只显示前台验证阶段的诊断，不保留后台持续日志。

## 执行远程命令与管道脚本

除进入交互式终端外，`xops ssh` 也可以直接在远端执行命令或通过管道运行脚本：

```bash
# 原生执行单条远程命令（默认 server 模式，原样转发给远端默认 Shell）
xops ssh web-01 uptime
xops ssh --host web-01 --interpreter server uname -a

# 使用 Bash 执行命令，不加载登录环境
xops ssh --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false id
```

- **解释器选择**：默认使用远端 Shell；需要指定时，可选择 `server`、`bash`、`sh`、`zsh`、`fish`、`powershell`、`pwsh` 或 `cmd`。参数搭配见[命令执行](./exec#解释器选择与跨平台执行)。Windows、macOS 和 Linux 均可在终端中运行。
- **登录环境控制**：使用 `bash`、`zsh` 或 `fish` 时可通过 `--login-shell` 控制是否加载登录环境；`--no-login` 为 Bash 兼容参数（等效于非登录 `bash -c`）；`server` 模式不接受登录选项。
- **输入流与 Shell 路由**：
  - **终端无命令**：标准输入为终端且未传命令时，打开交互式 PTY 登录 Shell。
  - **管道脚本（如 `cat script.sh | xops ssh web-01`）**：默认由远端 Shell 读取并执行；若节点配置了 `bash`、`sh`、`zsh` 或 `fish`，则使用该解释器和节点的登录设置。
  - **空命令保护**：显式传入空字符串（如 `xops ssh web-01 ""`）会直接报错拒绝，不会误打开交互式 Shell。
- **中断与输出**：可按 `Ctrl+C` 中断操作。若通过管道输出时提示不支持，可改为直接在终端运行，或用 `xops exec` 执行非交互命令并将结果保存到文件。

## 首次连接自动保存节点

通过 `ssh`、`sftp`、`scp` 或 `exec` 首次连接新主机时，XOps **仅在连接和身份认证成功后**才保存节点、主机和身份信息：
- 连接超时、拒绝连接、认证失败或认证前取消不会留下垃圾节点。
- 节点保存在打开 Shell 或执行命令之前完成，后续命令失败不会删除已认证节点；已有节点连接失败也不会被删除。
- `--remember never` 仅禁止保存密码/口令机密，认证成功的节点地址信息仍会保存。

例如，首次执行 `xops ssh root@192.0.2.10`（默认 22 端口）连接失败不会创建 `:22` 节点；随后执行 `xops ssh root@192.0.2.10:2222` 认证成功后仅保存 `:2222` 节点，下次省略端口即可直接匹配它（若同一主机保存了多个不同端口，仍需指定端口或使用别名）。

若保存节点失败，本次连接会报错。若提示配置可能已经保存，请先用 `xops host list` 检查，再决定是否重试。

## Sudo / Su 提权

```bash
# 打开提权后的交互式 Shell
xops ssh --sudo web-01

# 在 PTY 下以提权身份执行单条命令
xops exec -x --sudo web-01 id
```

提权方式由节点的 `sudo_mode` 配置决定（支持 `auto`、`root`、`sudoer` 免密、`sudo` 密码、`su` 密码）：
- **禁止 root 直接登录的主机**：可配置为 `su` 模式，使用普通用户建立 SSH 连接后再通过 `su` 和 root 密码切换身份，无需开放 `PermitRootLogin`。
- **传统 `sudo` 与 `sudo-rs` 兼容**：缺少凭据或密码被拒时，会提示重新输入。`exec -x --sudo` 仅显示命令结果，不显示多余的 root 提示符。
- **多 Shell 提权支持（`bash` / `sh` / `zsh` / `fish`）**：
  - 节点配置 `launch_dialect: fish` + `interpreter: fish`（或 `bash`/`sh`/`zsh`），或配置 `launch_dialect: posix` + `interpreter: zsh` 后，均可使用 `xops ssh --sudo`、`xops exec --sudo` 和 Playbook `sudo: true`。
  - 目标系统需提供 `/bin/sh`；使用 `su` 时还需支持 `-s` 选项，见 [su 手册](https://man7.org/linux/man-pages/man1/su.1.html)。
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
- **单连接故障隔离**：单次转发连接失败（如 `administratively prohibited` 或目标端口未监听）通过受控队列提示到 `stderr`，但不会中断主 SSH 会话或转发监听器。`-N` 就绪提示仍写 stdout。堵塞输出不会卡住转发回调，输出失败在结束时作为错误返回；不支持的管道可能略过辅助提示，可将对应输出流重定向到普通文件。
- **连接保活与断开退出**：使用 `-L`、`-R`、`-D` 或 `-N` 时自动启用连接监测——连续 15 秒无远端数据时发送 SSH 心跳，等待期间若连续 10 秒既无心跳回复也无数据进展则判定断线，自动关闭本地监听端口并以非零状态退出。后台运行可组合 `-f -N`。
