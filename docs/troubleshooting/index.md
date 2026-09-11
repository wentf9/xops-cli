# 故障排查

## system 存储不可用

先运行 `xops credential doctor`。Linux 需要 `secret-tool`、用户 D-Bus 和 Secret Service。缺少工具时 Ubuntu/Debian 可安装 `libsecret-tools`。服务未运行时，先启动桌面密钥环服务。

doctor 禁止自动启动服务；交互式迁移 dry-run 通过 `secret-tool` 可能激活服务，因此首次 doctor 失败而 dry-run 后通过并不矛盾。读取检查通过不代表具有写权限。

## 新主机指纹提示无法提交

使用包含 Windows 提示修复的构建。普通文本提示应显示输入，Enter 提交，退格可编辑；密码不回显是正常行为。`context canceled` 表示操作被取消，不能单独证明网络认证失败。

## SFTP exec 返回后吞掉首字符

使用包含 Windows stdin 交接修复的构建。验证 `exec date` 返回后输入 `pwd`，首字符应保留，也不应报 `read stdin failed: EOF`。异常仍存在时记录操作系统、终端和 XOps 版本。

## exec -x 出现提示符和命令回显

当前实现直接通过 SSH exec 请求执行命令，普通和 sudo/su 命令均不向外层 shell 注入命令。旧版本需更新。远端启动脚本主动打印的内容不会被过滤。

## 报告问题

提供命令结构、版本、系统/终端类型、预期结果和已脱敏错误。不要提交密码、私钥、解锁材料或完整生产配置。

## 旧 Linux 内核报 identify vault mount / function not implemented

部分 CentOS 7 的 3.10 内核不支持 `statx`。当前构建优先使用 `statx` 的挂载 ID；不支持该调用或字段时，改从已打开句柄对应的 `/proc/self/fdinfo/<fd>` 读取 `mnt_id`，保留跨挂载校验。

需要可访问的 procfs 和有效的 `mnt_id`。无法可靠获取挂载身份时仍会报错，不会仅凭设备号放行。离线库还需要文件锁、原子发布和同步操作，挂载 ID 探测通过不代表所有维护操作已经验证。
