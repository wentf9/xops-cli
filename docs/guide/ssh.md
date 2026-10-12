# SSH 与提权

`xops ssh` 提供了完整的 SSH 连接与远程会话管理能力，集成别名连接、跳板机穿透、执行解释器适配、提权会话以及高可靠端口转发隧道。

```bash
# 使用节点别名快速登录
xops ssh web-01

# 指定密钥与用户连接
xops ssh -i ~/.ssh/id_ed25519 deploy@192.0.2.10

# 通过跳板机（Bastion）建立连接
xops ssh -J bastion.example.com deploy@192.0.2.10
```

单标签跳板名称需要预先配置为节点或别名。显式用户连接同一主机时，凭据保持独立。

## 命令执行与解释器适配

`xops ssh` 支持直接执行单次远程命令（通过位置参数或 `--host` 后跟命令），并提供解释器与登录控制：

```bash
# 原生执行远程命令（默认）
xops ssh web-01 uptime
xops ssh --host web-01 --interpreter server uname -a

# 显式使用 Bash 执行并控制登录环境
xops ssh --host linux-01 --interpreter bash --launch-dialect posix --login-shell=false id
```

- **解释器选择**：支持 `--interpreter server`（原生执行，默认）、`bash`、`sh`、`zsh`、`fish`、`powershell`、`pwsh` 及 `cmd`。
- **登录环境控制**：当使用 `bash` 解释器时，支持 `--login-shell`（加载登录配置）与 `--no-login`（不加载登录配置）；`server` 解释器原生透传，不接受登录选项。
- **输入流与 Shell 路由**：
  - **终端交互 Shell**：未指定命令且标准输入为终端时，启动交互式 PTY 登录 Shell；
  - **管道脚本流式执行**：当未指定命令且标准输入来自管道（例如 `cat script.sh | xops ssh web-01`）时，XOps 会根据目标节点的执行配置自动路由：
    - 若节点为 `server`（默认），启动原生非 PTY Shell 会话流式传输执行；
    - 若节点配置为 `bash` 或 `sh`，则启动对应解释器流式读取标准输入脚本，并完整应用节点的登录/非登录配置；
  - 显式空命令（如 `xops ssh web-01 ""`）会被安全拒绝，不会误触发交互式 Shell。
- **输出与取消保障**：命令执行流接入了可取消输出保护，支持常规终端、管道输出、文件重定向与空设备。在发生 Ctrl+C 中断或超时时，安全中断 SSH 会话并回收系统资源。

## 自动保存节点

SSH、SFTP、SCP 和 exec 首次连接时先在内存中准备连接信息，SSH 握手及身份认证成功后才保存节点、主机和认证模板。超时、拒绝连接、认证失败或认证前取消均不会新增这些配置；其他节点的保存也不会顺带写入尚未认证的节点。

保存发生在打开 Shell、执行命令或启动文件传输之前，因此这些后续操作失败不会删除已经认证成功的节点。已有节点连接失败仍会保留；显式添加和导入节点也默认先验证，可通过 `--skip-verify` 跳过；添加时验证失败会询问是否保存，导入可用 `--save-on-verify-failure` 保留验证失败的节点。`--remember never` 只禁止自动保存密码等机密，认证成功的节点信息仍会保存。

例如，首次执行 `xops ssh root@192.0.2.10` 使用默认端口 22 且失败，不会留下 `:22` 节点。随后执行 `xops ssh root@192.0.2.10:2222` 并认证成功后，只保存 `:2222` 节点；下次省略端口即可匹配它。如果确实保存了同一主机的多个端口，仍需指定端口或使用唯一别名。旧版本留下的错误节点需要手动删除。

节点保存失败会报告错误并关闭本次尚未交付的 SSH 连接；若配置已经写入但同步到磁盘失败，不会自动回滚。连接期间发生冲突的配置修改也不会被覆盖。

## 提权管理

```bash
# 启动提权后的交互式 Shell
xops ssh --sudo web-01

# 直接以提权身份执行命令
xops exec -x --sudo web-01 id
```

提权方式由节点配置决定，包括 root、免密 sudo、密码 sudo、su 等模式。只能普通用户登录的服务器可以使用 su 模式，在普通用户的 SSH 连接中通过 root 密码切换身份，不要求开放 root SSH 登录。

`ssh --sudo` 提供提权后的交互 shell；`exec -x --sudo` 直接执行提权命令。后者保留 PTY 认证，但不额外显示 root shell 提示符和注入命令回显。自定义 su/PAM 多轮认证和登录脚本应在目标环境验证。

密码 sudo 支持传统 sudo 和 sudo-rs：使用可用凭据自动认证时，会过滤远端密码提示及 sudo-rs 的星号反馈；sudo-rs 的 PAM `Password:` 提示无论是否带尾随空格，均可识别。缺少凭据或密码被拒绝时，仍会提示输入密码。认证错误和提权后命令的输出会正常显示。

Fish 节点也支持上述提权模式：在节点 `execution` 中保存 `launch_dialect: fish`，选择 `interpreter: fish`（也可选择 bash/sh/zsh），再使用 `xops exec --host fish-01 --sudo -c 'id'`、`xops exec -x --host fish-01 --sudo -c 'id'` 或 `xops ssh fish-01 --sudo`。Playbook 的 fish 脚本也支持提权。认证握手在固定 `/bin/sh` 中执行，成功后才启动所选解释器；密码、握手确认与用户 stdin 分离。fish 路径不使用 `sudo -i` 拼接命令，登录模式由所选解释器控制。su 通过 `-s /bin/sh` 固定控制 Shell，目标系统需支持该选项（见 [su 手册](https://man7.org/linux/man-pages/man1/su.1.html)）。CLI 显式 `--interpreter` 与 `--sudo` 仍不可组合，请使用节点或 Playbook 执行配置。

zsh 节点配置 `interpreter: zsh` 与 `launch_dialect: posix` 后，可使用相同的 `--sudo` 命令和 Playbook 提权配置。zsh 复用 POSIX 认证协议，支持 sudo 和 su，命令与脚本保留 zsh 语义。登录模式使用 `zsh -l`；su 同样通过 `-s /bin/sh` 固定控制 Shell。

## 端口转发与隧道

```bash
# 本地端口转发：将本地 8080 端口转发至远程服务器的 127.0.0.1:80
xops ssh -L 8080:127.0.0.1:80 -N web-01

# 动态 SOCKS5 代理：在本地 1080 端口开启 SOCKS5 代理
xops ssh -D 1080 -N web-01

# 远程端口转发：将远程 9000 端口转发至本地 3000 端口
xops ssh -R 9000:127.0.0.1:3000 -N web-01
```

- **生命周期**：会话正常退出后隧道自动关闭。连接断开或心跳超时后，命令关闭转发监听端口并返回失败状态。
- **错误排查与连接隔离**：单次转发连接失败会直接输出到标准错误（stderr），包含转发类型和错误详情。服务器拒绝转发时会显示 `administratively prohibited` 等原因；该连接关闭后，主 SSH 会话和转发监听继续保持运行。
- **延迟绑定与即时校验**：
  - `-L` 和 `-D` 在实际访问转发端口时才申请 SSH 通道；
  - `-R` 则在启动时向服务器申请远端监听，服务器拒绝该请求时命令会直接报错退出。
- **有界超时控制**：`-R` 的监听建立与关闭请求各有独立的 10 秒等待上限，超时或被取消时会安全释放本地与连接资源。
- **智能保活与心跳检测**：使用 `-L`、`-R`、`-D` 或 `-N` 时持续监测连接。连续 15 秒无远端数据时发送 SSH 心跳；等待回复期间，只有连续 10 秒既无回复也无数据进展才会判定超时。持续传输的数据会自动刷新计时，避免高负载网络下产生误判。
