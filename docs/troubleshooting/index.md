# 故障排查

本页汇总 XOps v2 在配置解析、凭据库、安全护栏、审计熔断、MCP 沙箱认证、SFTP/SCP 传输与多路复用中的常见故障与处置流程。

## 1. 配置文件被拒绝（`version: 2` / 未知字段 / 权限错误）

- **症状**：报错提示 `unsupported schema version`、未知 YAML 字段、禁止多文档或 `config.yaml` 权限不安全。
- **原因与处置**：
  1. XOps v2 仅支持 `~/.xops/config.yaml`（`XOPS_HOME` 可覆写），强制 **`version: 2`** 与 `KnownFields(true)`，100% 不读取 v1 `xops_config.yaml` 或明文密码字段。
  2. 请对照 [配置 Schema v2 参考](../reference/config) 修正字段名，或使用 `xops config import --format openssh|csv` 重新生成规范资产。
  3. 确保 `~/.xops` 目录权限为仅当前用户可访问（Unix `0700`，Windows 为受保护 Owner-Only DACL），且不要将 `policy.guardrail.audit_log` 直接放在裸 `$HOME` 根目录。

## 2. MCP 模式下 `AuthPrivateKey` 报错 `ErrSignerUnavailable`

- **症状**：同一节点在 `xops ssh` 下可正常使用本地私钥登录，但在 `xops mcp serve` 下连接失败并提示无可用私钥签名器（`ErrSignerUnavailable`）。
- **原因**：MCP 模式为阻断宿主机任意文件读取，物理强制 **`OperatorReadFS == nil`**，因此无法直接读取 `~/.ssh/id_ed25519` 等本地磁盘私钥文件。
- **处置**：
  1. 将私钥加载到本机 **`ssh-agent`**（Unix 执行 `ssh-add ~/.ssh/id_ed25519` 并确认 `SSH_AUTH_SOCK` 已传入 MCP 进程环境；Windows 启动 `ssh-agent` 服务使 `\\.\pipe\openssh-ssh-agent` 就绪并执行 `ssh-add`）。
  2. 将该节点的 Identity 设为 `kind: agent`（或在 `composite` 认证链中加入 `agent`）。

## 3. 凭据库锁定、未初始化或 Linux Secret Service 不可用

- **排查命令**：

  ```bash
  xops creds status --json
  xops doctor --json
  ```

- **离线凭据库（`offline_aead`）**：
  - `Uninitialized`：请执行 `xops creds init` 初始化（**切勿在已有 `items/*.enc` 的目录删掉 `vault.meta.json` 重新初始化**）。
  - `Locked`：离线库解锁态仅保存在当前进程内存中；无人值守批处理或 MCP 服务请改用 `os_keychain`、`external_helper` 或 `ssh-agent`。
- **Linux `os_keychain`**：需要用户 D-Bus 会话总线（`DBUS_SESSION_BUS_ADDRESS`）与运行中的 Secret Service（如 GNOME Keyring / KWallet）。在无桌面 SSH/容器环境中，请改用 `offline_aead` 或 `external_helper`。

## 4. 收到 `outcome_unknown`（`do_not_retry: true`）或 `uncertain_durability`

- **症状**：命令执行返回退出码 `255` 且提示 `OutcomeUnknown` / `do_not_retry: true`，或 `xops creds` 录入/轮换返回 `uncertain_durability: true`。
- **处置原则（严禁盲目重试）**：
  1. **远端执行 `OutcomeUnknown`**：命令可能已在远端生效但回报通道中断。先通过只读命令（如 `xops sftp stat`、`xops exec` 只读检查）与 `xops audit tail` 核实远端状态，确认未生效后再手动决定是否重跑。
  2. **凭据 Saga `UncertainDurability`（`Applied && !Durable`）**：严禁自动重试或手动删除旧/新凭据条目；先运行 `xops creds doctor` 与 `xops hosts list` 核对实际已落盘引用后再安全 `xops creds gc`。

## 5. `strict_agent` 触发 `engine_halted`（`SECURITY GATE HALTED`）

- **症状**：MCP 端点返回 HTTP `503`（`code: "gate_halted"`），或 CLI/TUI 报错 `engine_halted`。
- **原因**：在 `strict_agent` 策略档下，终态审计写入 `audit.jsonl` 失败（磁盘满、权限被改或目录损坏），系统按 Fail-Closed 原则不可逆熔断并吊销全部活跃受管句柄。
- **处置**：
  1. 检查磁盘剩余空间与 `~/.xops/` 及 `audit.jsonl` 权限。
  2. 运行 `xops audit reconcile --json` 对账并清理死亡进程遗留锁，再用 `xops audit tail --limit 20` 复查最近记录。
  3. 排除底层存储故障后重启 MCP / 引擎进程。

## 6. 主机密钥校验失败（`host_key_unknown` / `host_key_mismatch` / `host_key_revoked`）

- 非交互批处理、Playbook 或 MCP 模式下，默认 `StrictHostKeyChecking=ask` 遇未知主机密钥会严格失败关闭（`host_key_unknown`）。请先通过交互式 `xops ssh <target>` 核验指纹并写入 `known_hosts`。
- 遇到 `host_key_mismatch` 或 `host_key_revoked` 时，先与基础设施负责人核实主机是否重装或发生中间人攻击，绝不可盲目跳过校验。

## 7. SFTP / SCP 软链拒绝、锚定失配或中断恢复

- **`symlink_rejected`**：下载与递归上传（`scp -r`）默认严禁跟随越界软链；仅单文件上传可按需评估使用 `--symlink-policy follow_operator_source`，下载仅允许 `reject` 或 `contained_relative`。
- **`remote_anchor_mismatch` / `patch_conflict`**：`sftp patch` / 原子写期间检测到远端文件类型或 `(dev, ino)` 发生变化（并发修改或软链替换），请重新读取最新内容后再打补丁。
- **传输中断恢复**：运行 `xops sftp recover --json` 查看双代 WAL 日志状态；对健康未提交传输可使用 `scp --resume` 或 MCP `transfer` `resume` 续传；对处于 `TransferUncertainCommit` 的条目请先核对远端文件摘要再人工处置。

## 8. ControlMaster 套接字异常或后台守护退出

- 若旧 `ControlMaster` 异常崩溃，可运行 `xops mux check -S <socket> <target>` 探测存活状态；重新 `xops mux start` 会自动探测并安全回收死套接字。
- 若使用 `xops ssh -f` / `xops mux daemon` 立即报错退出，检查是否配置了需要人工交互的 `ControlMaster=ask/autoask` 或需交互输入主口令的凭据——守护模式无交互终端，须改用 `ControlMaster=yes` 与非交互认证方式。
