# 安装与初始化

## 安装

从 [GitHub Releases](https://github.com/wentf9/xops-cli/releases) 下载对应操作系统与架构的程序。Linux/macOS 将 `xops` 放入 PATH；Windows 将 `xops.exe` 所在目录加入 PATH，也可在 PowerShell 中使用 `./xops.exe`。

源码构建需要 **Go 1.26+**：

```bash
git clone https://github.com/wentf9/xops-cli.git
cd xops-cli
make build
./bin/xops --help
```

Windows 交叉构建使用 `make windows`，产物为 `bin/xops.exe`。

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

新配置使用 Schema v2，默认凭据存储为 `file`（encrypted-file + key-file），首次保存时准备离线库，不创建旧版 `secret.key`。完整体验仍在实施中，请阅读[凭据存储](./credentials)。

## 第一次连接

```bash
xops ssh user@192.0.2.10
```

新主机需要核对密钥指纹。通过可信渠道核对后输入 `yes`；不认可则输入 `no`。不要把更换指纹错误当成普通确认提示处理。

CLI 支持 `--lang zh` 和 `--lang en`。本文档跟随 master 维护，可能包含未发布改动；安装版本的参数以 `xops <command> --help` 为准。
