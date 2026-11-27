# SFTP 与 SCP 文件传输

XOps v2 的文件与传输体系区分**本地 `os.Root` 强沙箱原子语义**与**远端 SFTP v3 协议语义**，提供并行分片可续传 `xops scp`、15 个脚本友好单步 `xops sftp` 子命令以及交互式 SFTP Shell。

## 1. 并行可续传文件传输（`xops scp`）

`xops scp` 要求源与目标必须一端为本机路径、另一端为 `[user@]host:<remote_path>`：

```bash
# 上传单个本地文件到远端目录或精确文件路径
xops scp ./release.tar.gz web-01:/srv/releases/
xops scp --no-clobber --perm 0644 ./app.conf web-01:/etc/app/app.conf

# 递归上传目录（并行分片 + 断点续传 + SHA-256 摘要校验 + 保留权限/时间戳）
xops scp -r -p --resume --concurrency 4 --chunk-size 1048576 ./dist web-01:/srv/app/

# 下载远端文件或目录到本机（默认自动锚定至 ScopedRootFS 沙箱）
xops scp web-01:/var/log/app.log ./app.log
xops scp -r --local-root ./downloads --max-files 500 --max-bytes 1073741824 web-01:/srv/artifacts ./artifacts

# 校验端到端 SHA-256 摘要并输出 JSON 报告
xops scp --expected-digest sha256:<hex> --json web-01:/srv/release.bin ./release.bin
```

### `xops scp` 核心标志与安全约束

| 标志 | 说明 |
| --- | --- |
| `-P <port>` / `-l` / `-i` / `-J` / `-o` / `-F` | 标准 OpenSSH 连接选项（注意端口为大写 `-P`） |
| `-p` / `--preserve` | 保留文件修改时间（上传同时保留权限位） |
| `-r` / `--recursive` | 递归传输目录（递归上传强制 `--symlink-policy=reject` 并走 `ScopedRootFS` 沙箱） |
| `--resume` | 开启基于摘要校验的断点续传 |
| `--no-clobber` | 目标已存在时拒绝覆盖 |
| `--expand-into-dir[=bool]` | 上传目标为已存在远端目录时是否自动展开文件名（默认 `true`） |
| `--symlink-policy <policy>` | 软链策略：`reject`（默认最严）\| `contained_relative` \| `follow_operator_source`（下载仅许 `reject` 或 `contained_relative`） |
| `--local-root <dir>` | 显式指定本地 `ScopedRootFS` 沙箱根目录 |
| `--perm <octal>` | 显式设置远端文件八进制权限（`0001..0777`） |
| `--chunk-size` / `--concurrency` | 并行分片大小（字节）与并发分片工作数 |
| `--max-files` / `--max-bytes` | 递归传输文件数量与总字节数硬上限 |
| `--expected-digest <sha256>` | 验证内容 SHA-256 摘要，不匹配则失败关闭 |

## 2. 单步远端 SFTP 子命令（`xops sftp <op>`）

无需打开交互终端或依赖远端 Shell，直接执行原子远端文件操作（全部支持 `--lang <en|zh>`、`--json` 与 `--policy`，且支持置于子命令动作词之前，如 `xops sftp --lang zh ls web-01 /srv/app`）：

```bash
# 目录列举、元数据与软链检查
xops sftp ls web-01 /srv/app --json
xops sftp stat web-01 /srv/app/app.ini
xops sftp stat --follow-symlinks web-01 /srv/app/current
xops sftp realpath web-01 /srv/app/current
xops sftp readlink web-01 /srv/app/current

# 有界读取（read / cat）
xops sftp cat --max-bytes 65536 web-01 /srv/app/app.ini

# 原子写入（从本地文件或 stdin "-" 写入；支持 --perm、--no-clobber、--create-parents）
xops sftp write --file ./app.ini --perm 0644 --create-parents web-01 /srv/app/app.ini
printf 'mode=prod\n' | xops sftp write --file - --no-clobber web-01 /srv/app/mode.env

# FSTAT 锚定文本补丁（若远端文件在读后被并发篡改将触发 remote_anchor_mismatch / patch_conflict）
xops sftp patch --old "debug=true" --new "debug=false" web-01 /srv/app/app.ini
xops sftp patch --old "v1" --new "v2" --all web-01 /srv/app/app.ini

# 目录与元数据维护
xops sftp mkdir --perm 0755 web-01 /srv/app/releases/v2
xops sftp mv --no-clobber web-01 /srv/app/app.ini.new /srv/app/app.ini
xops sftp chmod web-01 0640 /srv/app/app.ini
xops sftp rm web-01 /srv/app/tmp.bak
xops sftp rmdir web-01 /srv/app/empty-dir

# 恢复中断的双代 WAL 流式传输日志（不传参数时扫描全部日志，--prune 可清理旧世代）
xops sftp recover --json
xops sftp recover --prune web-01 <transfer_id>
```

## 3. 交互式 SFTP Shell（`xops sftp <target>`）

直接传入目标主机（可选 `--dir <remote_dir>` 或 `<target>:<remote_dir>`）进入交互式 SFTP Shell：

```bash
xops sftp web-01
xops sftp --dir /srv/app web-01
xops sftp web-01:/srv/app
```

> 交互式 SFTP Shell 不支持 `--json`（脚本自动化请使用上述单步子命令），并自动继承 `--lang <en|zh>` / `XOPS_LANG` 渲染内置帮助、状态与审批错误提示（如 `xops sftp --lang zh web-01`）。执行单条慢传输命令时按 `Ctrl+C` 仅取消当前命令并安全返回 `sftp> ` 提示符，不会强杀整个会话。

### 交互式 SFTP Shell 内置命令

| 分类 | 命令与用法 |
| --- | --- |
| **导航** | `pwd`、`cd [remote-path]`、`ls [-l] [-a] [remote-path]`、`lpwd`、`lcd <local-path>`、`lls [-l] [-a] [local-path]` |
| **传输与原子写入** | `put [-r] [-n] [--resume] [-p] <local> [remote]`、`get [-r] [-n] [--resume] [-p] <remote> [local]`、`cat <remote>`、`write [-n] [-p] <remote> <text>`、`mv\|rename [-n] <old> <new>`、`mkdir [-m <octal>] <remote>`、`rm <remote>`、`rmdir <remote>` |
| **元数据与探查** | `chmod <octal-mode> <remote>`、`chtimes <mtime> <remote>`（或 `chtimes <atime> <mtime> <remote>`，支持 RFC3339 与 Unix 时间戳）、`stat [-L] <remote>`（默认跟随软链）、`lstat <remote>`（不跟随软链）、`realpath <remote>`、`readlink <remote>` |
| **控制** | `help [command]`（或 `?`）、`exit` / `quit` / `bye` |

## 4. 诚实安全与原子语义边界

- **本机侧（`core/osfs` `*os.Root`）**：下载落盘与递归目录上传全程锁定在不可越界的 `os.Root` 沙箱内，通过临时文件写入 + 刷盘 + 旁路锁协调原子替换，彻底阻断路径穿越与软链逃逸。
- **远端侧（SFTP v3 协议边界）**：写与补丁路径采用非截断打开 + `SSH_FXP_FSTAT` 文件类型与 `(dev, ino)` 锚定比对，随后通过同目录临时文件 + OpenSSH `posix-rename@openssh.com` 原子替换目标；若远端 SFTP 服务不支持 `posix-rename` 扩展或并发修改导致锚点变化，会明确报错而非静默损坏。
