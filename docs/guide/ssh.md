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

- `-v` 显示连接、主机密钥验证、最终成功的认证方式、协商算法和会话结果；`-vv` 增加请求确认、提权交互及转发连接信息；`-vvv` 再增加终端交接与会话清理信息。诊断采用 OpenSSH 风格的 `debug1/2/3:` 前缀，写入 stderr，不改变远程 stdout。
- 认证成功行中的 `using "publickey"`、`using "password"` 或 `using "none"` 表示实际完成握手的方法；多阶段认证还显示成功链。`MAC: <implicit>` 表示 AES-GCM 或 ChaCha20-Poly1305 自带完整性保护，无需独立 MAC，并非没有校验；非 AEAD 算法显示实际 HMAC 名称，无法确认的值显示 `<unknown>`。
- `-q` 隐藏诊断及隧道就绪提示，不隐藏远程输出、失败报错或安全确认。与 OpenSSH 一样，顺序有影响：`-qv` 启用诊断，`-vq` 关闭诊断，`-vqv` 不立即恢复 DEBUG1。
- `--debug` / `--log-level` 控制另一套内部日志，不受 `-v/-q` 改写。远程命令自己的 `-v` 放在命令名称之后，例如 `xops ssh -v web-01 curl -v https://example.com`。
- 诊断不打印用户命令、脚本、密码或私钥正文；提权调用使用脱敏载荷，但包含主机、用户名、指纹、密码提示词及转发地址，分享日志前仍需检查。`-vvv` 不提供完整的 SSH 内部报文跟踪。
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
- **伪终端控制（PTY）**：
  - `-T`（`--disable-tty`）：禁止为会话分配伪终端（对应 `-o RequestTTY=no`）。
  - `-t`（`--force-tty`）：在本地输入为终端时强制为远程命令分配 PTY；多次指定（`-tt`）即使本地标准输入被重定向或非终端也强制请求远端分配 PTY（对应 `-o RequestTTY=no|yes|force|auto`）。命令行出现多个 `-T` 与 `-t` 时按最后出现的选项生效，显式 Flag 优先于 `-o RequestTTY` 选项。
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

## SSH 认证方式与多因素认证 (MFA)

XOps 支持标准 SSHv2 的多种身份认证机制，以及由服务器端发起的任意多阶段多因素认证（MFA / 2FA）流程。

### 支持的认证方式

| 认证方式 | 协议方法名 | 说明与特性 |
| --- | --- | --- |
| **公钥认证** | `publickey` | 支持 RSA、Ed25519、ECDSA、PKCS#8、PEM 等密钥格式；支持口令保护的私钥文件，支持交互式提示或 `--passphrase-stdin` 管道传入口令。 |
| **密码认证** | `password` | 传统静态口令认证；支持安全凭据库安全加密存储（zero-plaintext），支持交互式安全提示或 `--password-stdin` 管道传入。 |
| **键盘交互质询** | `keyboard-interactive` (RFC 4256) | 服务器发起的交互式问答（如 PAM 动态质询、静态安全问题等）。支持**人工交互输入**（自动根据提示属性开启/关闭回显）、**正则自动化匹配规则**（`keyboard_interactive.rules`），答案来源支持复用登录密码（`login_password`）、复用动态口令（`otp`）、凭据库托管机密（`secret`）以及外部命令提供者（`command`）。 |
| **一次性动态口令** | `otp` (RFC 6238 / RFC 4226) | 基于时间的动态口令（TOTP）。内置纯 Go 标准库实现的 RFC 6238 算法（支持标准 Base32 密钥及 `otpauth://` URI 格式，支持 SHA1/SHA256/SHA512、6/8 位及自定义步长）。支持凭据库托管密钥（`totp_secret_ref`）、外部命令提供者（`command`）以及命令行单次会话覆盖参数（`--otp` / `--otp-stdin`）。 |
| **多阶段多因素认证** | `PartialSuccessMethods` 编排 | 自动识别服务器的多阶段认证要求（例如：公钥 + 密码、密码 + TOTP、公钥 + TOTP、密码 + 静态安全问题等），按阶段自动流转至全部认证通过。 |

### 配置与使用示例

#### 1. 配置文件（`~/.xops/xops_config.yaml`）

XOps 严格遵守 Schema v2 架构规范与零明文安全策略：
- `hosts` 定义网络主机与端口；
- `identities` 维护认证身份，私钥口令、登录密码、TOTP 密钥和质询答案一律由凭据库托管，配置文件中仅保存 `*_ref` 引用；
- `nodes` 聚合 `host_ref` 与 `identity_ref`，形成可直接连接的节点条目。

```yaml
hosts:
  bastion-host:
    address: 198.51.100.1
    port: 22

identities:
  opsadmin-mfa:
    user: opsadmin
    auth_type: auto             # 可选：auto、key、password、agent、otp、keyboard-interactive
    key_path: ~/.ssh/id_ed25519 # 公钥认证密钥路径
    
    # 方式 A：TOTP (OTP) 自动化配置
    otp:
      totp_secret_ref:          # 凭据库托管的 TOTP 种子引用（通过 xops identity credential set 录入生成）
        store_id: file
        item_id: totp-seed
      prompt_pattern: '(?i)verification code|otp' # 可选：当质询提示词匹配该正则时自动提供 OTP
      # 也可通过外部命令动态获取 OTP（与 totp_secret_ref 二选一，禁止使用 Shell 特殊元字符）：
      # command: "/usr/local/bin/get-totp"
      # args: ["--account", "opsadmin"]
      # timeout: 5s

    # 方式 B：键盘交互质询 (Keyboard-Interactive) 自动化规则
    keyboard_interactive:
      rules:
        # 规则 1：静态安全问题，答案由安全凭据库托管（source: secret）
        - name: security_question
          prompt_pattern: '(?i)favorite city'          # 正则匹配服务器 Prompt 文本（必填）
          instruction_pattern: '(?i)answer carefully' # 可选：正则匹配服务器说明文本
          source: secret                              # 来源类型：secret、command、login_password、otp
          secret_ref:                                 # 凭据引用（通过 xops identity credential set 录入生成）
            store_id: file
            item_id: city-answer

        # 规则 2：外部命令提供者（source: command），从外部密码管理器动态读取答案
        - name: corporate_sso_token
          prompt_pattern: '(?i)one-time passcode'
          source: command
          command: "op"
          args: ["read", "op://Employee/bastion/passcode"]
          timeout: 5s

        # 规则 3：服务器通过质询提问密码时，自动复用当前身份的登录密码
        - name: pam_password
          prompt_pattern: '(?i)password'
          source: login_password

        # 规则 4：服务器通过质询提问动态口令时，自动复用当前身份配置的 OTP
        - name: pam_otp
          prompt_pattern: '(?i)authenticator code'
          source: otp

nodes:
  bastion-mfa:
    host_ref: bastion-host
    identity_ref: opsadmin-mfa
    sudo_mode: none
```

#### 2. 通过 CLI 安全录入凭据

机密无需（且不允许）在 YAML 文件中手写明文，使用 `xops identity credential set` 配合 `--password-stdin` 即可安全录入对应机密：

```bash
# 录入登录密码与私钥解密口令
xops identity credential set opsadmin-mfa --kind login_password --password-stdin
xops identity credential set opsadmin-mfa --kind passphrase --password-stdin

# 录入 TOTP 共享密钥（支持 Base32 密钥或 otpauth:// URI，自动在身份中配置 totp_secret_ref）
printf '%s\n' 'JBSWY3DPEHPK3PXP' | xops identity credential set opsadmin-mfa --kind totp_secret --password-stdin

# 录入特定质询规则的静态回答（需在 keyboard_interactive.rules 中已声明该规则 name）
printf '%s\n' 'Beijing' | xops identity credential set opsadmin-mfa --kind challenge_answer --rule security_question --password-stdin
```

#### 3. 命令行临时覆盖与人工交互回退

- **临时传入当前动态口令（会话单次覆盖）**：
  在终端中临时连接开启了 2FA/OTP 的服务器时，可直接通过命令行参数传入当前的动态口令，单次优先使用，不改动身份的持久化配置：
  ```bash
  # 通过 --otp 传入当前动态口令
  xops ssh --otp 839201 bastion-mfa

  # 通过管道安全传入动态口令（避免暴露在进程列表）
  printf '%s\n' '839201' | xops ssh --otp-stdin bastion-mfa
  ```

- **无配置时的交互式提示**：
  若服务器启用了 `keyboard-interactive` 挑战，而当前配置中未指定匹配规则，XOps 不会凭关键字猜测问题类型，而是直接在终端安全展示服务器发起的原始挑战问题，由用户人工输入答案：
  - 若服务器标记该问题不需要回显（如密码/PIN），终端将关闭回显以保护隐私；
  - 若服务器标记该问题允许回显（如确认信息/普通文本），终端将正常显示用户键入的字符。

## Sudo / Su 提权

```bash
# 打开提权后的交互式 Shell
xops ssh --sudo web-01

# 排查提权：显示模式选择、密码交互与远端就绪阶段
xops ssh -vv --sudo web-01

# 在 PTY 下以提权身份执行单条命令
xops exec -x --sudo web-01 id
```

提权诊断中，`-v` 显示模式选择、提权调用、尝试/重试、远端提权 Shell 就绪及结束结果；`-vv` 补充 root/免密探测、凭据查找、密码提示匹配规则及实际识别到的提示词/响应阶段；`-vvv` 还显示终端交接与恢复。sudo/su 的选项、目标用户和控制 Shell 可见；用户命令/脚本显示为 `<privileged payload>`，随机提示标记显示为 `<password-prompt>`（例如 `[sudo: <password-prompt>] Password:`）。密码等凭据响应内容及控制帧不会写入诊断。模式被选中不代表已提权成功；提权 Shell 就绪也不代表后续用户命令成功。root 或免密路径不会虚构密码交互。

提权方式由节点的 `sudo_mode` 配置决定（支持 `auto`、`root`、`sudoer` 免密、`sudo` 密码、`su` 密码）：
- **禁止 root 直接登录的主机**：可配置为 `su` 模式，使用普通用户建立 SSH 连接后再通过 `su` 和 root 密码切换身份，无需开放 `PermitRootLogin`。
- **传统 `sudo` 与 `sudo-rs` 兼容**：缺少凭据或密码被拒时，会提示重新输入。`exec -x --sudo` 仅显示命令结果，不显示多余的 root 提示符。
- **sudo/PAM 忽略 `-p` 时**：可在节点或全局配置中显式设置 `password_prompt_pattern`，例如 `password_prompt_pattern: '(?m)^Password:[ \t]*$'`。sudo 优先识别随机标记，未匹配时才使用该配置回退；节点配置优先于全局配置。未配置、正则无效或可匹配空字符串时不会自动启用内置默认正则作为 sudo 回退；`sudoer` 免密模式不回退。`-vv` 显示回退规则和命中情况。请按真实密码提示精确配置，避免匹配 banner 或其他输入；此功能不支持 OTP/多因素认证，也不会重新执行用户命令。
- **多 Shell 提权支持（`bash` / `sh` / `zsh` / `fish`）**：
  - 节点配置 `launch_dialect: fish` + `interpreter: fish`（或 `bash`/`sh`/`zsh`），或配置 `launch_dialect: posix` + `interpreter: zsh` 后，均可使用 `xops ssh --sudo`、`xops exec --sudo` 和 Playbook `sudo: true`。
  - 目标系统需提供 `/bin/sh`；使用 `su` 时还需支持 `-s` 选项，见 [su 手册](https://man7.org/linux/man-pages/man1/su.1.html)。
  - CLI 显式 `--interpreter` 参数暂不支持与 `--sudo` 同时传入，请在节点或 Playbook 的 `execution` 中配置。

## 端口转发与隧道

```bash
# 本地端口转发（-L）：将本机 127.0.0.1:8080 转发至远端看到的 127.0.0.1:80
xops ssh -L 8080:127.0.0.1:80 -N web-01

# 本地 Unix 域套接字（StreamLocal）转发：
xops ssh -L /tmp/local.sock:/var/run/docker.sock -N web-01

# 动态 SOCKS 代理（-D）：在本机 127.0.0.1:1080 开启 SOCKS4/SOCKS4a/SOCKS5 代理（也支持本地 Unix 套接字）
xops ssh -D 1080 -N web-01
xops ssh -D /tmp/socks.sock -N web-01

# 远程端口转发（-R）：将远端 127.0.0.1:9000 转发至本机 127.0.0.1:3000
xops ssh -R 9000:127.0.0.1:3000 -N web-01

# 远程动态分配端口（-R 0:...）：远端动态分配空闲端口并在 stderr 输出分配提示
xops ssh -R 0:127.0.0.1:8080 -N web-01

# 远程反向动态 SOCKS 代理（-R）：在远端开放 SOCKS 代理并回传本地
xops ssh -R 1080 -N web-01

# 远程 Unix 域套接字转发：
xops ssh -R /run/user/1000/gnupg/S.gpg-agent:/run/user/1000/gnupg/S.gpg-agent.extra -N web-01

# 开启网关端口（-g）：允许外部网络主机连接本地转发的端口
xops ssh -g -L 8080:127.0.0.1:80 -N web-01

# 后台静默运行转发（-f -N 或执行单条远程命令）：
xops ssh -f -N -L 8080:127.0.0.1:80 web-01
xops ssh -f web-01 "sleep 10"

# 多路复用控制指令动态添加转发并捕获动态分配端口：
PORT=$(xops ssh -O forward -R 0:127.0.0.1:8080 web-01)

# 标准输入输出转发（-W）：将 stdin/stdout 通过安全通道转发至目标 host:port（常用作 ProxyCommand 跳板）
xops ssh -W 192.0.2.20:22 bastion

# 隧道设备转发（-w）：建立点对点 (tun) 虚拟网卡隧道（需服务端开启 PermitTunnel）
xops ssh -w 0:0 -N gw

# 二层以太网 (tap) 隧道转发（须在 -w 之前指定 -o Tunnel=ethernet）
xops ssh -o Tunnel=ethernet -w 1:any -N gw
```

- **本地端口转发 (`-L [bind_address:]port:host:hostport` 或 `-L local_socket:remote_socket`)**：
  - 将本地监听端口或 Unix 域套接字（StreamLocal）请求通过加密隧道转发至远端目标。
  - 省略 `bind_address` 时默认仅监听本地 `127.0.0.1`；配合 `-g` (`--gateway-ports`) 或 `-o GatewayPorts=yes` 可允许外部网络主机连接本地转发端口。
- **远程端口转发 (`-R [bind_address:]port[:host:hostport]` 或 `-R remote_socket[:local_socket]`)**：
  - 将远程服务端监听的端口或 Unix 域套接字请求反向转发至本地目标。
  - **动态端口分配 (`-R 0:...`)**：当远程端口指定为 `0` 时（如 `-R 0:127.0.0.1:8080`），服务器动态分配可用端口。普通连接会话在标准错误 (`stderr`) 输出 `Allocated port <port> for remote forward to ...`（避免污染远程命令的 `stdout` 数据流）；使用多路复用控制命令 `-O forward -R 0:...` 时则将纯端口号输出至标准输出 (`stdout`)，便于脚本直接捕获（例如 `PORT=$(xops ssh -O forward -R 0:127.0.0.1:8080 host)`），状态与确认信息写入 `stderr`。注意，因 `-f` 后台运行会在分离子进程中重建连接并将标准输入输出重定向至 `/dev/null`，直接将 `-f` 与 `-R 0:...` 连用不会输出后台进程分配的端口号；若脚本需要捕获后台隧道的动态分配端口，可先启动后台 Master（`-M -f -N`）再执行 `PORT=$(xops ssh -O forward -R 0:... <host>)`。
  - **反向动态代理**：省略目标 `host:hostport` 时（如 `-R 1080` 或 `-R remote_socket`），在远端开启反向 SOCKS 代理通道。
- **动态应用级转发 (`-D [bind_address:]port` 或 `-D local_socket`)**：
  - 在本地开启 SOCKS 代理服务器，支持 SOCKS4、SOCKS4a 与 SOCKS5 协议，亦支持绑定到本地 Unix 域套接字。
- **网关端口 (`-g` / `--gateway-ports`)**：
  - 允许外部网络主机连接本地转发的端口（对应 `-o GatewayPorts=yes`）。
- **会话控制与后台运行 (`-f`, `-N`, `-n`)**：
  - `-N`（`--no-cmd`）：不执行远程命令也不分配 Shell，专用于端口转发与隧道（对应 `-o SessionType=none`）。与显式远程命令互斥。
  - `-f`（`--background`）：在身份验证和端口转发建立后转入后台运行。支持 `xops ssh -f host <cmd>`（后台执行远程命令）以及 `xops ssh -f -N ...`（后台运行转发隧道），后台模式自动隐含 `-n`（标准输入重定向至 `/dev/null`）。若未指定远程命令且未指定 `-N`，则直接报错拒绝。
  - `-n`（`--stdin-redirect`）：将标准输入重定向到 `/dev/null`，防止后台读取终端输入（对应 `-o StdinNull=yes`）。
- **多路复用动态转发 (`-O forward`)**：
  - 向活动 Master 发送控制命令动态增减转发。建立 `-R 0:...` 动态分配端口转发时，动态分配的端口号输出到 `stdout`，而 `Forwarding request sent.` 提示写入 `stderr`。
- **绑定与校验时机**：`-L` 和 `-D` 在本地端口收到连接时才按需打开 SSH 通道；`-R` 在启动时立即向服务器申请远端监听（建立与关闭各有 10 秒超时上限），若被服务器拒绝则立即报错退出。
- **标准输入输出转发 (`-W host:port` / `--stdio-forward`)**：
  - 将客户端 `stdin`/`stdout` 通过 SSH `direct-tcpip` 安全通道转发至远端可访问的 `host:port`（如配合原生 `ssh -o ProxyCommand="xops ssh -W %h:%p bastion" target` 作为跳板通道）。
  - 默认隐含 `-N`（不执行远程命令）、`-T`（禁止分配 PTY）、`ExitOnForwardFailure=yes` 与 `ClearAllForwardings=yes`（可通过配置文件或 `-o` 显式覆盖，例如 `-o ClearAllForwardings=no`、`-o ExitOnForwardFailure=no`）。
  - `-W` 转发为专用纯净二进制流通道，不可与远程命令、`-f` 后台运行、`--sudo` 或 `-O` 多路复用控制命令（`-O proxy` 除外）同时使用。
- **隧道设备转发 (`-w local_tun[:remote_tun]` / `--tunnel-device`)**：
  - 建立客户端与服务端（需 `sshd` 开启 `PermitTunnel`）之间的三层（`point-to-point`）或二层（`ethernet`）虚拟网卡隧道。
  - 单元号可为非负整数或 `any`（由系统自动分配空闲设备），省略 `:remote_tun` 时默认为 `any`（例如 `-w 0` 等价于 `-w 0:any`）。
  - **模式与顺序规则**：若未提前指定 `Tunnel` 指令，默认采用 `point-to-point` 模式；如需 `ethernet` 二层模式，需在 `-w` **之前**指定 `-o Tunnel=ethernet`（例如 `xops ssh -o Tunnel=ethernet -w 0:0 gw`）。
  - **平台支持说明**：Linux 原生支持 `tun` (`point-to-point`) 与 `tap` (`ethernet`)；macOS 原生支持 `utun` (`point-to-point`)；Windows 暂不支持本地内核虚拟网卡创建（配置项与 `-o` 解析仍全平台可用）。
- **单连接故障隔离**：单次转发连接失败（如 `administratively prohibited` 或目标端口未监听）通过受控队列提示到 `stderr`，但不会中断主 SSH 会话或转发监听器。`-N` 就绪提示仍写 stdout。堵塞输出不会卡住转发回调，输出失败在结束时作为错误返回；不支持的管道可能略过辅助提示，可将对应输出流重定向到普通文件。
- **连接保活与断开退出**：使用 `-L`、`-R`、`-D`、`-w` 或 `-N` 时自动启用连接监测——连续 15 秒无远端数据时发送 SSH 心跳，等待期间若连续 10 秒既无心跳回复也无数据进展则判定断线，自动关闭本地监听端口并以非零状态退出。后台运行可组合 `-f -N`。
