# 安装与初始化

## 1. 安装

从 [GitHub Releases](https://github.com/wentf9/xops-cli/releases) 下载对应操作系统与架构的二进制文件：
- **Linux / macOS**：将 `xops` 放入 `PATH` 目录（如 `/usr/local/bin`）。
- **Windows**：将 `xops.exe` 所在目录加入 `PATH`，或在 PowerShell 中直接运行 `./xops.exe`。

Linux / macOS 可通过 Bash 一键安装（amd64 / arm64，无需管理员权限）：

```bash
curl -fsSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash

# 指定安装目录
curl -fsSL https://raw.githubusercontent.com/wentf9/xops-cli/master/install.sh | bash -s -- --install-dir "$HOME/tools/xops"
```

Windows 也可在 PowerShell 5.1+ 中一键安装最新发布版（x64 / ARM64，无需管理员权限）：

```powershell
irm https://raw.githubusercontent.com/wentf9/xops-cli/master/install.ps1 | iex

# 需要自定义目录时，下载脚本后传参执行：
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/wentf9/xops-cli/master/install.ps1 -OutFile install.ps1
.\install.ps1 -InstallDir "$HOME\tools\xops"
```

脚本自动识别系统架构，将程序安装到 `%LOCALAPPDATA%\Programs\xops\xops.exe` / `$HOME/.local/bin/xops`，并将目录加入用户及当前 shell 的 PATH。其他已打开的终端需要重启后才能直接运行 `xops`。重复安装会更新程序；若程序正在运行，请先关闭再重试。

也可以从源码编译（需要 **Go 1.26+**，Makefile 原生支持 Linux、macOS 与 Windows CMD / PowerShell / Git Bash）：

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
./bin/xops --help
```

在 Windows 上运行 `make build` 会生成 `bin/xops.exe`；在其他平台可通过 `make windows` 交叉编译 Windows 版本。如需指定 Go 工具目录，可传入 `make GOPATH_BIN=/path/to/bin build`；设置 `GOPATH_BIN=` 则跳过自动探测并沿用当前 `PATH`。

## 2. 导入现有配置或直接连接

如果你平时使用 `~/.ssh/config`，运行 `xops init` 即可导入所有不含通配符的 `Host` 配置（仅读取本地文件，不发起网络连接，重复运行也不会覆盖已有节点）：

```bash
xops init
xops host list
```

也可指定其他 OpenSSH 配置文件，或仅创建空白的 `~/.xops/xops_config.yaml`：

```bash
xops init --ssh-config ~/.ssh/config.work
xops init --skip-ssh-import
```

不运行 `xops init` 也可以直接连接主机。首次连接时核对主机密钥指纹，输入 `yes` 确认（注意：若遇到指纹变更警告，请先核实目标服务器是否重装或更换过密钥，切勿当作普通首次连接直接放行）：

```bash
xops ssh user@192.0.2.10
```

SSH 握手和身份认证通过后，XOps 会自动保存该节点，并将验证成功的密码或私钥口令加密存入本机 `~/.xops/credentials/`，下次连接无需重复输入。保存策略与备份方式见[凭据存储](./credentials)。

## 3. 常用下一步

| 场景 | 命令示例 | 详细文档 |
| --- | --- | --- |
| 打开终端界面管理主机、查看监控和日志 | `xops tui` | [终端管理界面](./tui) |
| 从 CSV 批量导入主机并打标签 | `xops host import hosts.csv --tag web` | [主机与身份](./hosts) |
| 按标签对多台主机并行执行命令或脚本 | `xops exec --tag web -c 'uptime'` | [命令执行](./exec) |
| 上传/下载文件或打开交互式 SFTP | `xops scp ./app.tar.gz web-01:~/tmp/` | [SFTP 与文件传输](./sftp) |
| 使用 YAML 编排多步骤部署或启动 MCP 服务 | `xops play deploy.yaml` | [Playbook 与 MCP](./automation) |

CLI 支持 `--lang zh` 和 `--lang en` 切换语言。文档跟随 `master` 分支更新，已安装版本的支持选项以 `xops <command> --help` 为准。
