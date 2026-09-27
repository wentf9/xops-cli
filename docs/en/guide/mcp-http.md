# MCP HTTP and file transfers

HTTP mode lets Codex or Antigravity CLI connect to XOps over a LAN to query and operate configured servers. Connected clients share the same nodes, SSH credentials and access token.

## Start the service

First configure [hosts and identities](hosts) and confirm that the account running XOps can connect to the target servers. Prepare SSH credentials, credential-store access and trusted host keys in advance; MCP does not display password or unlock prompts.

Generate a token and start the service on the XOps server:

```bash
umask 077
openssl rand -hex 32 > "$HOME/.xops/mcp.token"
xops mcp serve --transport http --listen 0.0.0.0:8080 \
  --public-url http://192.168.1.10:8080 \
  --token-file "$HOME/.xops/mcp.token"
```

Replace `192.168.1.10` with an address reachable from the clients. `--public-url` contains only the scheme, host and port, without `/mcp`. The default listener is `127.0.0.1:8080`; configure both `--listen` and `--public-url` for LAN access.

Alternatively, use `--token-env XOPS_MCP_TOKEN` to read the token from the server environment instead of `--token-file`. Tokens must contain 32–4096 bytes without whitespace; a token file may end with a newline. Keep the token private and share it only with clients that need access.

### Save startup settings

Add an `mcp` section to the XOps configuration file to start with just `xops mcp serve`:

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

Replace the example addresses and paths. Command-line flags override configuration settings. Restart the service after changing its configuration.

`state_dir` stores transfer records. It defaults to `mcp-transfers` beside the configuration file. Use a local directory accessible only to the service account. Do not share it between running services or delete it while tasks need attention.

## Connect an AI client

Select **Streamable HTTP** and use `http://192.168.1.10:8080/mcp`. The legacy HTTP+SSE `/sse` address is not supported.

### Codex

Set `XOPS_MCP_TOKEN` in the client environment used to launch Codex, using the same token as the server, then add this configuration:

```toml
[mcp_servers.xops]
url = "http://192.168.1.10:8080/mcp"
bearer_token_env_var = "XOPS_MCP_TOKEN"
startup_timeout_sec = 10
```

### Antigravity CLI

Merge this entry into `mcpServers` in `~/.gemini/config/mcp_config.json`, replacing the address and token:

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

Restrict access to the configuration file. Reopen the CLI or refresh through `/mcp` and check the connection.

Antigravity CLI 1.2.11 may automatically cancel XOps approval forms, preventing operations that require approval. If this happens, use a client that can complete the approval for that operation.

### Allow file and network access

File transfers also require the AI client to run local commands. That command environment needs access to the XOps HTTP address, local source files and download directories. Allow the necessary file and network access when prompted by the client.

If the client runs in a remote sandbox, local paths refer to files inside that sandbox. Copy desktop files into that environment first.

## Upload and download files

The AI client can prepare a task, run the transfer and check the result. For example: “Upload my local `report.zip` to `/srv/uploads/report.zip` on node `web-1`, without overwriting an existing file.”

HTTP transfers have two steps: prepare a task through MCP, then run a transfer command on the client. Preparation tools do not directly read or save local files.

| Action | MCP tool |
| --- | --- |
| Prepare an upload | `xops_prepare_upload` |
| Prepare a download | `xops_prepare_download` |
| Check task status | `xops_transfer_status` |
| Cancel a task | `xops_transfer_cancel` |

Have the client calculate the file size and SHA-256 when preparing an upload, and use an absolute path on the target server. Save the complete task content returned by the preparation tool as `upload-task.json` or `download-task.json`. It contains the transfer address and a short-lived credential; do not edit it manually, publish it or commit it to version control.

### Use the transfer helper

Install Python 3 on the client and obtain `scripts/mcp/transfer.py` from the project. Run these examples from the project directory, using task JSON created in the previous step:

```bash
chmod 600 upload-task.json
python3 scripts/mcp/transfer.py upload --server http://192.168.1.10:8080 \
  --task upload-task.json --file './client file.bin'

chmod 600 download-task.json
python3 scripts/mcp/transfer.py download --server http://192.168.1.10:8080 \
  --task download-task.json --file './downloaded file.bin'
```

PowerShell examples:

```powershell
py -3 scripts/mcp/transfer.py upload --server http://192.168.1.10:8080 --task upload-task.json --file '.\client file.bin'
py -3 scripts/mcp/transfer.py download --server http://192.168.1.10:8080 --task download-task.json --file '.\downloaded file.bin'
```

`--server` is the server address without `/mcp`; `--file` is always a client-local path. On Windows, keep task JSON in a directory accessible only to the current user. Delete task JSON after the transfer.

The helper checks file size and SHA-256. Successful uploads report `completed`; successful downloads report `localSaved: true`. Downloads refuse existing destinations by default; add `--overwrite-local` when replacement is intended. Use `--ca-file` to specify a trusted CA file for private HTTPS certificates.

### File requirements

- Only ordinary single files are supported. Archive directories on the client first; the target does not extract them automatically.
- Symbolic links, special files and resumable transfers are not supported. Do not modify the source file during a transfer.
- Uploads refuse overwrite by default. Request replacement explicitly when preparing the task; the target SFTP service must support atomic replacement.
- Uploaded files have mode `0600` (readable and writable only by their owner). Original ownership, ACLs and other metadata are not preserved.
- The helper's default download mode requires local hard-link support. If it reports that this is unavailable, choose another download directory and prepare a new task.

### Check status or cancel

Ask the client to call the status tool, or query with an existing task file:

```bash
python3 scripts/mcp/transfer.py status --server http://192.168.1.10:8080 \
  --task upload-task.json
```

| Status | What to do |
| --- | --- |
| `ready` | Run the transfer command before the task expires |
| `transferring`, `verifying`, `committing` | Wait or check status again; do not resend the file |
| `completed` | The upload is complete |
| `streamed` | Download data has been sent; still check that the client reports `localSaved: true` |
| `failed`, `cancelled`, `expired` | Read the error, address its cause and prepare a new task |
| `unknown` | The upload outcome is uncertain; verify it as described below before retrying |

To cancel, ask the client to call `xops_transfer_cancel` with the task ID. An upload that has started committing may no longer be stoppable; check its final status. Closing the client or disconnecting the network does not confirm cancellation.

If a preparation response is lost, have the client retry preparation with the same request ID and arguments, then use the newly returned task content. Do not automatically replay file transfers. Check status after an upload timeout to avoid overwriting twice.

## Adjust limits

Configure these common settings in the YAML `mcp` section:

| Setting | Default | Configuration key |
| --- | --- | --- |
| File size | 10 GiB | `max_file_bytes` (bytes) |
| Simultaneous transfers | 4 | `max_active_transfers` |
| Simultaneous transfers per target | 2 | `max_transfers_per_target` |
| Time allowed to start a task | 5 minutes | `transfer_start_window` |
| Wait without progress | 1 minute | `stream_idle_timeout` |
| Maximum transfer duration | 2 hours | `transfer_timeout` |
| Maximum ordinary tool duration | 5 minutes | `tool_timeout` |
| Upload commit wait | 30 seconds | `commit_timeout` |
| Task record retention | 24 hours | `transfer_retention` |
| Pending tasks / retained records | 256 / 4096 | `max_ready_transfers` / `max_transfer_records` |

Limits must be positive. Record retention must exceed the combined start window, maximum transfer duration and commit wait.

If the service reports that it is busy, wait for active tasks to finish before retrying preparation or starting the transfer. Node aliases for the same host, port and account share transfer limits; uploads to the same path cannot run simultaneously. When different hostnames point to the same server, avoid uploading to the same file in parallel.

The helper's `--idle-timeout` and `--timeout` options adjust client waiting times. Timeouts do not trigger automatic retransmission; checking an upload outcome may take up to another 45 seconds.

## Handle uncertain or interrupted tasks

After a service restart, prepare new tasks for transfers that had not started. Interrupted transfers do not resume automatically. An `unknown` task blocks further uploads to that destination until its outcome is checked.

Stop the XOps MCP service, then list its transfer records:

```bash
xops mcp recover --state-dir /home/operator/.xops/mcp-transfers
```

Replace `TASK_ID` with the task to inspect and verify the target file:

```bash
xops mcp recover --state-dir /home/operator/.xops/mcp-transfers --id TASK_ID --verify
```

Verification uses the current `mcp.max_file_bytes` limit and compares the target's size and digest without modifying it. After confirming the target content and deciding how to proceed, record an explanation and permit future uploads:

```bash
xops mcp recover --state-dir /home/operator/.xops/mcp-transfers --id TASK_ID \
  --resolve-unknown --reason 'Target content checked; allow a future new upload'
```

This does not retransmit or delete the destination. The original task retains its `unknown` status and the operator's explanation. If the report also lists a temporary file pending cleanup, run:

```bash
xops mcp recover --state-dir /home/operator/.xops/mcp-transfers --id TASK_ID --cleanup
```

If temporary-file ownership is unconfirmed, inspect the remote file first, then use `--reason` to record the basis for confirming ownership. Do not delete an unverified file solely because its name looks familiar.

## HTTPS and connection troubleshooting

Plain HTTP does not encrypt the token or file content. To use HTTPS, place the service behind a reverse proxy and set `public_url` to the HTTPS address clients actually use.

The proxy should preserve the correct Host, disable request and response buffering for `/mcp` and transfer endpoints, and allow long transfers. Do not configure automatic retries for uploads.

| Problem | What to check |
| --- | --- |
| `401` or authentication failure | Client and server tokens match; configuration or environment changes have taken effect |
| `host_or_origin_denied` | `public_url` is correct; configure `--allowed-hosts` and `--allowed-origins` for additional domains or origins |
| MCP works, but the transfer command cannot connect | The local command environment can reach the LAN address and has network permission |
| Task expired | Prepare a new task and run the transfer command within its start window |
| Credential or host-key error | Run `xops credential doctor` on the server, restore credential access and confirm the host key |

See the [MCP command reference](../reference/commands/xops-mcp) for details.
