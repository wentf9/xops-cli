# MCP HTTP 与文件传输

通过 HTTP 模式，可以让局域网内的 Codex 或 Antigravity CLI 连接 XOps，查询和操作已配置的服务器。连接的客户端共用同一套节点、SSH 凭据和访问 Token。

## 启动服务

先完成 [主机与身份配置](hosts)，确认运行 XOps 的账户能够连接目标服务器。提前准备好 SSH 凭据、凭据库解锁方式和可信主机密钥；MCP 运行时不会弹出密码输入或解锁提示。

在 XOps 服务端生成 Token 并启动服务：

```bash
umask 077
openssl rand -hex 32 > "$HOME/.xops/mcp.token"
xops mcp serve --transport http --listen 0.0.0.0:8080 \
  --public-url http://192.168.1.10:8080 \
  --token-file "$HOME/.xops/mcp.token"
```

将 `192.168.1.10` 替换为客户端可访问的服务端地址。`--public-url` 只填写协议、主机和端口，不加 `/mcp`。未指定监听地址时，服务仅监听 `127.0.0.1:8080`；局域网接入需要设置 `--listen` 和 `--public-url`。

也可用 `--token-env XOPS_MCP_TOKEN` 从服务端环境变量读取 Token，与 `--token-file` 二选一。Token 长度须为 32–4096 字节且不含空白；Token 文件末尾可以有换行。妥善保存 Token，仅提供给需要连接此服务的客户端。

### 保存启动配置

将设置写入 XOps 配置文件的 `mcp` 部分后，可以直接运行 `xops mcp serve`：

```yaml
mcp:
  transport: http
  listen: 0.0.0.0:8080
  public_url: http://192.168.1.10:8080
  token_file: /home/operator/.xops/mcp.token
  state_dir: /home/operator/.xops/mcp-transfers
  stream_idle_timeout: 1m
  transfer_timeout: 2h
  max_file_bytes: 10737418240
  max_active_transfers: 4
  max_transfers_per_target: 2
```

替换示例中的地址和路径。命令行参数优先于配置文件；修改配置后重启服务。

`state_dir` 保存传输任务记录，默认位于配置文件同目录下的 `mcp-transfers`。使用仅服务账户可访问的本地目录，不要让多个服务同时使用，也不要在存在待处理任务时删除它。

## 连接 AI 客户端

客户端选择 **Streamable HTTP**，连接地址为 `http://192.168.1.10:8080/mcp`。不使用旧版 HTTP+SSE 的 `/sse` 地址。

### Codex

在启动 Codex 的客户端环境中设置 `XOPS_MCP_TOKEN`，值与服务端 Token 一致，然后添加配置：

```toml
[mcp_servers.xops]
url = "http://192.168.1.10:8080/mcp"
bearer_token_env_var = "XOPS_MCP_TOKEN"
startup_timeout_sec = 10
```

### Antigravity CLI

将以下内容合并到 `~/.gemini/config/mcp_config.json` 的 `mcpServers` 中，并替换地址和 Token：

```json
{
  "mcpServers": {
    "xops": {
      "serverUrl": "http://192.168.1.10:8080/mcp",
      "headers": {"Authorization": "Bearer REPLACE_WITH_SHARED_TOKEN"}
    }
  }
}
```

限制配置文件的访问权限。重新打开 CLI，或通过 `/mcp` 刷新并确认连接。

Antigravity CLI 1.2.11 可能自动取消 XOps 审批表单，导致需要审批的操作无法执行。遇到这种情况，请使用能够完成审批的客户端处理该操作。

### 确认文件和网络访问权限

文件传输还需要 AI 客户端执行本地命令。该命令环境必须能访问 XOps HTTP 地址，以及本地源文件和下载目录。按照客户端提示允许相应的文件和网络访问。

如果客户端在远程沙箱中运行，文件路径指向沙箱中的文件；桌面电脑上的文件需要先放入该环境。

## 上传和下载文件

可以让 AI 客户端完成准备任务、执行传输和检查结果。例如：“将本机的 `report.zip` 上传到节点 `web-1` 的 `/srv/uploads/report.zip`，不要覆盖已有文件。”

HTTP 文件传输分为两步：先通过 MCP 准备任务，再在客户端运行传输命令。准备工具不会直接读取或保存本地文件。

| 操作 | MCP 工具 |
| --- | --- |
| 准备上传任务 | `xops_prepare_upload` |
| 准备下载任务 | `xops_prepare_download` |
| 查询任务状态 | `xops_transfer_status` |
| 取消任务 | `xops_transfer_cancel` |

让客户端在准备上传时计算文件大小和 SHA-256，并使用目标服务器上的绝对路径。把准备工具返回的完整任务内容保存为 `upload-task.json` 或 `download-task.json`，其中包含传输地址和短期凭证；不要手动修改，也不要公开或提交到版本库。

### 使用传输辅助程序

在客户端安装 Python 3，并取得项目中的 `scripts/mcp/transfer.py`。以下示例从项目目录执行，任务 JSON 由前一步准备工具生成：

```bash
chmod 600 upload-task.json
python3 scripts/mcp/transfer.py upload --server http://192.168.1.10:8080 \
  --task upload-task.json --file './client file.bin'

chmod 600 download-task.json
python3 scripts/mcp/transfer.py download --server http://192.168.1.10:8080 \
  --task download-task.json --file './downloaded file.bin'
```

PowerShell 示例：

```powershell
py -3 scripts/mcp/transfer.py upload --server http://192.168.1.10:8080 --task upload-task.json --file '.\client file.bin'
py -3 scripts/mcp/transfer.py download --server http://192.168.1.10:8080 --task download-task.json --file '.\downloaded file.bin'
```

`--server` 填写服务端地址，不加 `/mcp`；`--file` 始终是客户端本地路径。Windows 上应将任务 JSON 保存在仅当前用户可访问的目录中。传输结束后删除任务 JSON。

辅助程序会校验大小和 SHA-256。上传成功显示 `completed`；下载成功显示 `localSaved: true`。下载默认不覆盖已有文件，确需覆盖时添加 `--overwrite-local`。私有 HTTPS 证书可用 `--ca-file` 指定可信 CA 文件。

### 文件要求

- 仅支持普通单文件；目录先在客户端打包，目标端不会自动解包。
- 不支持符号链接、特殊文件或断点续传。传输期间不要修改源文件。
- 上传默认不覆盖。需要覆盖时，在准备上传任务时明确指定；目标 SFTP 服务须支持原子替换。
- 上传后的文件权限为 `0600`（仅文件所有者可读写），不保留原文件的所有权、ACL 等元数据。
- 辅助程序的默认下载方式要求本地文件系统支持硬链接。若提示不支持，可更换下载目录后重新申请任务。

### 查询状态与取消

可以让客户端调用状态工具，也可使用已有任务文件查询：

```bash
python3 scripts/mcp/transfer.py status --server http://192.168.1.10:8080 \
  --task upload-task.json
```

| 状态 | 后续操作 |
| --- | --- |
| `ready` | 在任务有效期内运行传输命令 |
| `transferring`、`verifying`、`committing` | 等待完成，或查询最新状态；不要重复发送文件 |
| `completed` | 上传已完成 |
| `streamed` | 下载数据已发送，仍需确认客户端显示 `localSaved: true` |
| `failed`、`cancelled`、`expired` | 查看错误原因，处理后重新申请传输任务 |
| `unknown` | 上传结果不确定，先按下文核验，暂勿重传 |

取消时，让客户端调用 `xops_transfer_cancel` 并提供任务 ID。已经开始提交的上传可能无法停止，应继续查询最终状态。关闭客户端或断开网络不代表操作已取消。

如果准备任务的回复丢失，让客户端使用相同的请求 ID 和参数重试准备步骤，并使用新返回的任务内容。文件传输本身不应自动重试；上传超时后先查询状态，避免重复覆盖。

## 调整限制

可在 YAML 的 `mcp` 部分调整以下常用设置：

| 设置 | 默认值 | 配置键 |
| --- | --- | --- |
| 单文件大小 | 10 GiB | `max_file_bytes`（字节） |
| 同时传输数 | 4 | `max_active_transfers` |
| 单目标同时传输数 | 2 | `max_transfers_per_target` |
| 任务开始前有效期 | 5 分钟 | `transfer_start_window` |
| 无进展等待时间 | 1 分钟 | `stream_idle_timeout` |
| 单次传输最长时间 | 2 小时 | `transfer_timeout` |
| 普通工具最长执行时间 | 5 分钟 | `tool_timeout` |
| 上传提交等待时间 | 30 秒 | `commit_timeout` |
| 任务记录保留时间 | 24 小时 | `transfer_retention` |
| 待开始任务数 / 记录数 | 256 / 4096 | `max_ready_transfers` / `max_transfer_records` |

限制须为正数；记录保留时间须大于开始有效期、传输最长时间和提交等待时间之和。

收到繁忙提示时，等待正在执行的任务结束，再重试准备或开始传输。多个节点名称指向同一主机、端口和账户时，共用传输限额；同一路径不能同时上传。不同域名指向同一主机时，应自行避免并行覆盖同一文件。

辅助程序的 `--idle-timeout` 和 `--timeout` 可调整客户端等待时间。超时后不会自动重传；上传结果核验可能额外等待最多 45 秒。

上传请求体完整读取后，HTTP 读取空闲超时不再取消后续校验或提交准备；校验仍受传输总时限约束，进入提交后使用独立的 `commit_timeout`。请求体尚未读完时，读取空闲超时仍然生效。

## 处理异常任务

服务重启后，未开始的任务需要重新申请，中断的传输不会自动续传。出现 `unknown` 时，后续对同一路径的上传会被阻止，需要先核验结果。

先停止 XOps MCP 服务，再列出任务记录：

```bash
xops mcp recover --state-dir /home/operator/.xops/mcp-transfers
```

将 `TASK_ID` 替换为需要处理的任务 ID，核验目标文件：

```bash
xops mcp recover --state-dir /home/operator/.xops/mcp-transfers --id TASK_ID --verify
```

核验使用当前 `mcp.max_file_bytes` 上限，比较目标文件大小和摘要，不修改文件。确认目标内容及后续处理方式后，记录说明并解除上传限制：

```bash
xops mcp recover --state-dir /home/operator/.xops/mcp-transfers --id TASK_ID \
  --resolve-unknown --reason '已核验目标内容，允许后续新任务上传'
```

该操作不会重传或删除目标文件，原任务仍保留 `unknown` 状态及人工处理说明。如果报告中还有临时文件待清理，执行：

```bash
xops mcp recover --state-dir /home/operator/.xops/mcp-transfers --id TASK_ID --cleanup
```

若提示临时文件归属尚未确认，先核对远程文件，再通过 `--reason` 记录确认依据。不要仅凭文件名删除无法确认归属的文件。

## HTTPS 与连接排查

明文 HTTP 不加密 Token 或文件内容。需要 HTTPS 时，可通过反向代理提供服务，并将 `public_url` 设置为客户端实际访问的 HTTPS 地址。

代理应保留正确的 Host，关闭 `/mcp` 和文件传输接口的请求、响应缓冲，并允许长时间传输。不要为上传配置自动重试。

### Nginx 反向代理示例

以下示例由 Nginx 提供 HTTPS，XOps 与 Nginx 运行在同一台主机。先准备好 `mcp.example.com` 的 DNS 和受客户端信任的 TLS 证书，再让 XOps 仅监听本机地址，复用已生成的 Token：

```bash
xops mcp serve --transport http --listen 127.0.0.1:8080 \
  --public-url https://mcp.example.com \
  --token-file "$HOME/.xops/mcp.token"
```

`public_url` 必须是客户端实际访问的 HTTPS 来源地址，不加 `/mcp` 或其他路径前缀；XOps 用它生成文件传输地址，并设置默认允许的 Host 和 Origin。`X-Forwarded-Proto` 不能代替此配置。

将下面的 `server` 块保存到 Nginx 的 `http` 上下文加载的文件中，例如 `/etc/nginx/conf.d/xops-mcp.conf`。替换域名和证书路径：

```nginx
server {
    listen 443 ssl;
    server_name mcp.example.com;

    ssl_certificate     /etc/nginx/certs/mcp.example.com.fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/mcp.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # 与 XOps 默认的 10 GiB 单文件上限对应。
    client_max_body_size 10g;
    client_body_timeout 75s;
    send_timeout 75s;

    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Connection "";
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass_request_headers on;

    # 即时转发 MCP 流式响应和文件内容。
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    gzip off;
    proxy_next_upstream off;

    proxy_connect_timeout 5s;
    proxy_send_timeout 75s;
    # 上传可能直到完成才返回响应；覆盖默认 2 小时传输时限。
    proxy_read_timeout 7500s;

    location = /mcp {
        proxy_pass http://127.0.0.1:8080;
    }

    location ^~ /v1/transfers/ {
        proxy_pass http://127.0.0.1:8080;
    }

    location / {
        return 404;
    }
}
```

两个 `proxy_pass` 均不带 URI 部分，保留原始路径；不要只代理 `/mcp`、添加路径前缀或将 `/mcp` 重定向到 `/mcp/`。若 Nginx 与 XOps 位于不同容器或主机，应将上游地址改为 Nginx 能访问的 XOps 地址，并相应调整 XOps 的监听地址。

`Authorization` 必须透传请求原值：`/mcp` 使用共享 Token，文件传输接口使用准备任务返回的短期凭证，不能在代理中统一替换成固定 Token。`Origin`、`Mcp-Session-Id`、`MCP-Protocol-Version` 等请求头以及响应中的会话头默认保留；不要删除或重写它们。Streamable HTTP 不需要 WebSocket 的 `Upgrade` 配置。此示例使用单个 XOps 实例，MCP 会话和后续文件传输请求应到达同一实例。

`proxy_read_timeout` 是上游两次读取之间的等待时间，不是整次传输的总时限。示例使用 7500 秒，给默认两小时上传及提交留出余量；其余 75 秒超时略大于 XOps 默认一分钟空闲时限。XOps 和客户端自身的超时仍然生效。调整文件上限或超时时，应同步检查 Nginx、XOps 和客户端设置。

检查配置并重新加载：

```bash
sudo nginx -t && sudo systemctl reload nginx
curl --max-time 10 --include https://mcp.example.com/mcp
```

未携带 Token 的检查请求应返回 `401`，用于确认 TLS 和代理路由可用。随后将 MCP 客户端地址改为 `https://mcp.example.com/mcp`，传输辅助程序的 `--server` 改为 `https://mcp.example.com`，重新连接客户端并准备传输任务。若使用非默认 HTTPS 端口，例如 `8443`，需同时修改 `listen`、`public_url` 和客户端地址；`$http_host` 会保留该端口。

### 连接排查

| 问题 | 检查项 |
| --- | --- |
| `401` 或认证失败 | 客户端 Token 是否与服务端一致，配置或环境变量是否已生效 |
| `host_or_origin_denied` | `public_url` 是否正确；使用额外域名或来源时配置 `--allowed-hosts`、`--allowed-origins` |
| 能调用 MCP，但传输命令无法连接 | 运行本地命令的环境是否能访问局域网地址，是否已允许网络访问 |
| Nginx 返回 `413` | `client_max_body_size` 是否足够；同时检查 XOps 的 `max_file_bytes` |
| Nginx 返回 `502` / `504`，或流式响应延迟出现 | 上游地址、服务状态、代理超时和缓冲设置；上传中断后先查询任务状态，不要直接重传 |
| 任务已过期 | 重新申请任务，并在开始有效期内运行传输命令 |
| 凭据或主机密钥错误 | 在服务端运行 `xops credential doctor`，确认凭据可用并完成主机密钥确认 |

参数详情见 [MCP 命令参考](../reference/commands/xops-mcp)。
