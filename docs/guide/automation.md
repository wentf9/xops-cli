# Playbook v2、护栏与审计

XOps v2 将声明式多节点编排（`xops playbook` / `xops play`）、能力门控护栏（`PolicyProfile` + `policy.guardrail`）与同步 Fail-Closed 审计日志（`xops audit`）深度整合，保证每一次远端变更均经过统一风险评估、确定性摘要绑定与可追溯审计闭环。

## 1. Playbook v2 声明式编排

Playbook v2 同时支持 **YAML** 与严格 **JSON** 文档，且统一经过 `core/domain/playbook` 判别式校验器：强制 `version: 2`，严格拒绝未知字段、重复键、YAML 别名引用、JSON `null` 动作、嵌套 `ensure` 与篡改摘要。

### 完整示例（`deploy.yaml`）

```yaml
version: 2
id: deploy-web
name: "Deploy Web Application"
description: "Install nginx, render config, and reload service"
on_error: fail_fast # fail_fast | continue | abort
target:
  tags: [web]
  exclude_nodes: [web-maint-01]
vars:
  app_port: "8080"
  env_name: "prod"
steps:
  - id: ensure-nginx
    name: "Ensure nginx package is installed"
    action:
      kind: ensure
      check:
        kind: shell
        command: "command -v nginx >/dev/null 2>&1"
      action:
        kind: shell
        command: "apt-get update && apt-get install -y nginx"
        timeout: 3m
      max_retries: 1

  - id: upload-conf
    name: "Render and atomically publish nginx config"
    action:
      kind: template
      source: "./templates/nginx.conf.tmpl"
      dest: "/etc/nginx/conf.d/app.conf"
      vars:
        listen_port: "8080"
      mode: "0644"
      overwrite: true
      atomic: true

  - id: copy-static
    name: "Copy release manifest"
    when_tags: [frontend]
    action:
      kind: copy
      source: "./manifest.json"
      dest: "/srv/www/manifest.json"
      mode: "0644"
      overwrite: true
      atomic: true

  - id: verify-script
    name: "Run post-deploy check script"
    on_error: continue
    action:
      kind: script
      source: "./scripts/verify.sh"
      args: ["--strict"]
      work_dir: "/srv/www"
      env:
        APP_ENV: "prod"
      timeout: 30s
```

### 5 类封闭步骤动作（`action.kind`）

| `kind` | 必填字段 | 可选字段 | 说明 |
| --- | --- | --- | --- |
| `shell` | `command` | `profile`、`work_dir`、`env`、`timeout` | 在远端执行单条命令 |
| `script` | `source` | `symlink_policy`、`args`、`profile`、`work_dir`、`env`、`timeout` | 读取本地脚本并按启动配置在远端执行 |
| `copy` | `source`、`dest` | `symlink_policy`、`mode`（3/4 位八进制串如 `"0644"`）、`overwrite`、`atomic` | 将本地文件上传至远端目标路径 |
| `template` | `source`、`dest` | `symlink_policy`、`vars`、`mode`、`overwrite`、`atomic` | 渲染本地模板并上传至远端 |
| `ensure` | `check`、`action` | `max_retries` | 幂等状态收敛：`check` 失败时执行 `action` 并复查（禁止嵌套 `ensure`） |

### 错误策略（`on_error`）

- `fail_fast`：当前节点首个步骤失败后立即停止该节点后续步骤，其他节点继续执行。
- `continue`：记录失败并继续执行当前节点的后续步骤。
- `abort`：任一节点步骤失败后立即取消整批 Playbook 剩余任务。

### 校验与运行命令

```bash
# 1. 纯离线 AST / Schema 校验（不初始化 Engine、不触碰远端、输出规范 Digest）
xops playbook validate deploy.yaml
xops playbook validate deploy.yaml --json

# 2. 运行 Playbook（支持 --var、--target 覆写选择器、--concurrency、--timeout、--scoped-root）
xops playbook run deploy.yaml --var app_port=8081 --concurrency 3
xops play run deploy.yaml --target web-01 --scoped-root ./release-bundle --json

# 3. 从标准输入读取 Playbook（--stdin 或 -）
cat deploy.yaml | xops playbook validate --stdin --json
cat deploy.yaml | xops playbook run --stdin --policy strict
```

> 若 Playbook 运行报告中包含 `OutcomeUnknown` 步骤，CLI 将返回非零退出码并明确警示检查远端状态后再决定后续操作，严禁自动重试不确定变更。

## 2. 安全护栏策略（`PolicyProfile` & `policy.guardrail`）

XOps v2 通过**策略配置档（`PolicyProfile`）**与**护栏规则（`policy.guardrail`）**实现统一防线，可在 `~/.xops/config.yaml` 中设定默认值，并在每次调用时经 `--policy` 覆写：

| 策略配置档 | 默认归属 | 行为说明 |
| --- | --- | --- |
| `direct_operator` | CLI 默认 | 执行完整审计闭环与显式 `Deny` 拦截；不因常规风险阈值对直接人工 CLI 操作重复弹窗 |
| `strict` / `strict_operator` | 按需开启 | 启用完整风险阈值、`node_overrides`、受保护路径检查与审批挑战；审计写失败时向调用方报错但不永久锁死短命 CLI |
| `strict_agent` | MCP 默认 | 启用全量护栏与审批校验，且任何终态审计写失败（`AuditPostWriteError`）立即触发不可逆 **`Halted` 熔断态**，吊销全部活跃受管句柄并拒绝所有新请求 |

### 护栏配置示例（`~/.xops/config.yaml`）

```yaml
version: 2
policy:
  cli_default: direct_operator
  mcp_default: strict_agent
  guardrail:
    approval_threshold: moderate    # safe | moderate | dangerous | critical
    no_elicit_fallback: challenge   # deny（零值默认）| challenge（两步审批信封）
    audit_log: ~/.xops/audit.jsonl
    approval_ttl: 5m                # 范围 (0, 24h]
    protected_paths:
      - "/etc/**"
      - "/root/**"
      - "C:/Windows/**"
    node_overrides:
      "prod-*":
        approval_threshold: safe
        decision_floor: need_approval # allow | need_approval | deny
      "staging-*": moderate         # 标量简写，等价于仅设置 approval_threshold
```

- 命中 `protected_paths` 时风险级别至少提升至 `dangerous`。
- 节点通配符匹配规则遵循并半格折叠（多重命中自动取最严判定，与声明顺序无关）。
- `no_elicit_fallback: deny` 在非交互环境中遇到需审批操作直接拒绝；`challenge` 则签发带加密摘要（`envelope_digest`）与有效期（`approval_ttl`）的 `ApprovalEnvelope` 供客户端展示并二次提交核验（防重放、防目标篡改）。

## 3. 审计日志与 O(1) 跨进程崩溃对账（`xops audit`）

每次授权操作均按生命周期写入 `~/.xops/audit.jsonl`（每行规范 JSON/v2，经 `audit.jsonl.lock` 旁路锁保护），阶段包括 `denied`、`authorized` 与 `finalized`。

### O(1) 进程锁崩溃对账机制

- 每个运行中的 XOps 引擎进程在 `~/.xops/run/<ProcessInstanceID>.lock` 持有内核独占锁，并以只追加协议（`+<opID>` / `-<opID>`）追踪在途未闭合操作。
- **干净启动 O(1)**：若 `run/` 下没有已死亡进程的残留锁文件，启动阶段完全不扫描 `audit.jsonl`。
- **异常崩溃恢复**：当发现某进程被 `SIGKILL`/断电中止遗留的 `.lock` 文件时，通过非阻塞 `TryLock` 确认原进程已死亡，对比 `audit.jsonl` 补写 `outcome: aborted_by_crash` 记录，并在持锁态安全截断清空后删除残留锁文件。

### 审计查询与手工对账命令

```bash
# 查看最近 50 条审计记录（list 从头取，tail 从尾取）
xops audit tail --limit 20
xops audit list --phase finalized --outcome outcome_unknown --json
xops audit list --node web-01 --trace-id <trace_id>

# 按 OperationID 检视单次操作的完整生命周期轨迹
xops audit inspect <operation_id> --json

# 显式触发跨进程崩溃锁对账（CLI 引擎与 MCP Server 启动时亦会自动执行）
xops audit reconcile --json
```
