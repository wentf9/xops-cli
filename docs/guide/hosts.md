# 主机资产与配置导入

XOps v2 将 SSH 资产建模为不可变强类型三实体资产图（**Host / Identity / Node**），持久化在 `~/.xops/config.yaml`（`version: 2`），并通过乐观并发 CAS（`--expected-revision`）、旁路文件锁（`config.yaml.lock`）与 Tarjan 跳板 DAG 校验保障一致性。

## 1. 三实体资产图模型

| 实体 | 职责 | 关键字段 |
| --- | --- | --- |
| **Host** | 网络端点与标签 | `address`、`port`（默认 `22`）、`alias`、`tags`、`description` |
| **Identity** | 登录用户与认证方式（封闭和类型） | `user`、`auth`（`agent` / `password` / `private_key` / `keyboard_interactive` / `composite`）、`tags`、`description` |
| **Node** | 绑定单个 Host 与 Identity 的连接目标 | `host`、`identity`、`aliases`、`tags`、`proxy`（`jump` / `command` / `disabled`）、`execution`、`options`、`privilege_password_ref`、`origin` |

解耦三实体后，同一台服务器地址（Host）可同时关联运维账号（`deploy`）与审计账号（`audit`），各自拥有独立的认证身份、提权凭据与 OpenSSH 选项，互不串扰。

### 节点来源分类（`NodeOrigin`）

XOps v2 严格区分 4 类节点来源，以确定 OpenSSH 配置层（Tier-4）的合并规则：

1. `managed`：由 XOps 托管并持久化在 `config.yaml` 中的标准节点。
2. `openssh_virtual`：运行时直接从 `~/.ssh/config` 解析的只读虚拟主机。
3. `openssh_derived`：通过 `xops config import --format openssh` 导入生成的持久化派生节点。
4. `ad_hoc`：命令行临时输入的 `user@host[:port]` 目标（未写入资产库）。

## 2. 查询、解析与诊断资产

命令主名为 `xops hosts`（别名 `host`、`inventory`）：

```bash
# 列出节点（默认）、主机、身份或全量快照
xops hosts list
xops hosts list --tag web
xops hosts list --kind hosts
xops hosts list --kind identities
xops hosts list --kind all --json

# 查看单个资产详情与当前 CAS revision
xops hosts get web-01
xops hosts get --kind host h-web1 --json
xops hosts get --kind identity id-deploy

# 解析目标生效连接计划（展示来源、最终端点、跳数与 PlanDigest）
xops hosts resolve web-01
xops hosts resolve -J bastion -p 2222 deploy@192.0.2.10 --json

# 使用 Tarjan 强连通算法校验跳板机 DAG（检出环路与最大跳板深度）
xops hosts validate-dag

# 检索引用了指定凭据或存储的全部资产位置
xops hosts check-secret-refs --ref offline/web-pass
xops hosts check-secret-refs --store offline
```

## 3. 声明式 CRUD 与乐观锁 CAS

所有写操作支持传入 `--expected-revision <rev>` 执行乐观并发控制（若磁盘配置在读后被并发修改或手工编辑，提交将失败关闭返回 `revision_conflict`）：

```bash
# 创建与更新 Host
xops hosts create-host --id h-web1 --address 192.0.2.10:22 --alias web1-ep --tag prod,web --desc "Primary web"
xops hosts update-host --id h-web1 --address 192.0.2.11:22 --expected-revision <rev>

# 创建与更新 Identity（--auth-kind 支持 agent | password | private_key）
xops hosts create-identity --id id-agent --user deploy --auth-kind agent
xops hosts create-identity --id id-key --user deploy --auth-kind private_key \
  --key-path ~/.ssh/id_ed25519 --cert-path ~/.ssh/id_ed25519-cert.pub
xops hosts create-identity --id id-pass --user app --auth-kind password --password-ref offline/app-login

# 若私钥带口令，passphrase_ref 与 key_fingerprint 必须成对出现（推荐使用 xops creds enroll-key 自动计算指纹）
xops hosts update-identity --id id-key --user deploy --auth-kind private_key \
  --key-path ~/.ssh/id_ed25519 --passphrase-ref offline/key-pass --key-fingerprint SHA256:... --gc-old-secrets

# 创建与更新 Node（支持 --jump / --proxy-command、--dialect / --interpreter / --login、--priv-password-ref）
xops hosts create-node --id web-01 --host h-web1 --identity id-key \
  --alias prod-web --tag prod,web --jump bastion \
  --dialect posix --interpreter bash --login disabled
xops hosts update-node --id web-01 --host h-web1 --identity id-key --gc-old-secrets

# 删除资产（自动执行引用完整性检查；若仍被其他 Node 引用将拒绝删除）
xops hosts delete-node web-01 --delete-unused-secrets
xops hosts delete-identity id-key --require-unreferenced
xops hosts delete-host h-web1
```

> **提示**：创建密码身份或加密私钥口令身份时，更推荐使用交互式 [`xops creds enroll-password`](./credentials) 与 [`xops creds enroll-key`](./credentials)，可在单次 Saga 事务内安全采集口令、写入凭据库、自动绑定指纹并更新资产图。

## 4. 统一配置导入（`xops config import`）

XOps v2 通过 `ports.FormatImporter` 扩展接口支持外部清单导入（100% 零 v1 兼容代码），内置 **`openssh`** 与 **`csv`** 两种格式：

```bash
# 列出可用格式
xops config formats

# OpenSSH 导入：先预览冲突/告警，再确认落盘
xops config import --format openssh --file ~/.ssh/config --plan
xops config import --format openssh --file ~/.ssh/config

# 从 stdin 导入或执行 dry-run
cat ./hosts.csv | xops config import --format csv --stdin --dry-run --json
```

### OpenSSH 导入规则（`--format openssh`）

- 纯内存流式解析，不主动建立远端 SSH 连接，也不跟踪外部 `Include` 磁盘文件（遇到 `Include` 会产出结构化 `ImportWarning`）。
- 自动将具名主机块转换为 `openssh_derived` 节点，保留 `ProxyJump` / `ProxyCommand` 与 OpenSSH `options` 策略层；无法直接导入的通配符或模板键路径会记录警告而非静默丢弃。

### CSV 导入规则（`--format csv`）

- 支持 **无表头 4 列紧凑格式**：`alias,address,port,user`（默认生成 `agent` 认证身份）。
- 支持 **带表头格式**（列名大小写无关，支持 `#` 注释行与 `;` 分隔多值字段）：
  - 必填列：`name`/`alias`/`id`/`node`/`node_id`、`host`/`address`/`hostname`、`user`/`username`
  - 可选列：`port`（默认 `22`）、`key_path`/`key_paths`/`identity_file`、`cert_path`/`cert_paths`/`certificate_file`、`proxy_jump`/`jump`、`aliases`、`tags`、`description`/`desc`
- **零明文铁律**：若 CSV 表头包含 `password`、`passwd`、`pass`、`passphrase`、`secret`、`token`、`private_key`、`key_content`、`totp_secret`、`sudo_password`、`privilege_password` 中的任意一列，导入器将**立即失败关闭**并拒绝导入。

```csv
name,address,port,user,key_path,proxy_jump,tags,description
bastion,bastion.example.com,22,deploy,~/.ssh/id_ed25519,,infra,Jump bastion
web-01,192.0.2.10,22,deploy,~/.ssh/id_ed25519,bastion,prod;web,Web server 1
web-02,192.0.2.11,22,deploy,~/.ssh/id_ed25519,bastion,prod;web,Web server 2
```

## 5. 四层 OpenSSH 选项优先级模型

当执行 `ssh`、`exec`、`scp`、`sftp`、`tunnel`、`mux` 或 `hosts resolve` 时，XOps v2 使用纯函数求解器按严格固定优先级折叠 OpenSSH 选项（FirstWins 幺半群）：

```text
Tier-1: CLI 命令行参数（-p / -l / -i / -J / -o / -M / -S）
   > Tier-2: 托管节点自身 options（inventory.nodes.<id>.options）
      > Tier-3: XOps 全局选项（config.yaml 顶层 options）
         > Tier-4: OpenSSH 配置文件（~/.ssh/config 或 -F 指定文件）
            > 内置安全默认层（ControlMaster=no, StrictHostKeyChecking=ask, ForwardAgent=no, PermitLocalCommand=no）
```

### 安全隔离裁剪规则（INV-D2）

- 对于 `openssh_virtual` 与 `openssh_derived` 节点，完整应用 Tier-4（`~/.ssh/config`）的全部有效选项。
- 对于 `managed`（XOps 原生托管）与 `ad_hoc`（临时命令行地址）节点，系统仅从 Tier-4 继承**多路复用与传输层选项**（如 `ControlMaster`/`ControlPath`/`ControlPersist`、超时/保活/算法），防止 `~/.ssh/config` 中宽泛的 `Host *` 规则静默篡改托管节点的认证身份或路由。
- 若需彻底禁用 Tier-4 读取，可在全局或任意命令传入 `-F none`（或 `--ssh-config none`）。
