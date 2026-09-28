# 安装与初始化

## 安装

从 [GitHub Releases](https://github.com/wentf9/xops-cli/releases) 下载对应操作系统与架构的程序。Linux/macOS 将 `xops` 放入 PATH；Windows 将 `xops.exe` 所在目录加入 PATH，也可在 PowerShell 中使用 `./xops.exe`。

源码构建需要 **Go 1.26+**（Makefile 原生支持 Linux、macOS 与 Windows CMD / PowerShell / Git Bash 环境）：

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
./bin/xops --help
```

在 Windows 系统上，`make build` 会自动生成 `bin/xops.exe`；亦可在任意平台上通过 `make windows` 交叉编译 Windows 产物。

可用 `make GOPATH_BIN=/path/to/bin build` 指定 Go 工具目录；设置 `GOPATH_BIN=` 会跳过 Go 工具目录的自动探测，并保留现有 `PATH`。

## 初始化配置

```bash
xops init
xops host list
```

`init` 创建 `~/.xops/xops_config.yaml`，默认导入 `~/.ssh/config` 中不含通配符的 Host，不连接服务器；重复运行不会覆盖已有节点。

```bash
xops init --ssh-config ~/.ssh/config.work
xops init --skip-ssh-import
```

新安装默认使用离线加密凭据库，首次保存验证成功的密码时自动创建库和密钥文件。保存策略和备份方法见[凭据存储](./credentials)。

## 第一次连接

```bash
xops ssh user@192.0.2.10
```

新主机需要核对密钥指纹。通过可信渠道核对后输入 `yes`；不认可则输入 `no`。不要把更换指纹错误当成普通确认提示处理。

CLI 支持 `--lang zh` 和 `--lang en`。本文档跟随 master 维护，可能包含未发布改动；安装版本的参数以 `xops <command> --help` 为准。
