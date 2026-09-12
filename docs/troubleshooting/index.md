# 故障排查

## 密码无法保存

运行 `xops credential doctor` 检查凭据存储，确认配置目录、凭据库目录及密钥文件的访问权限。`doctor` 通过只表示读取检查通过，不代表可以写入。

如果使用了 `--remember never`，或配置中的 `credential.remember_prompted` 为 `never`，输入的密码仅用于当次连接。自动保存失败时，已认证的交互连接仍可使用；修复问题后重新连接以保存凭据。

## 系统密钥库不可用或锁定

Linux 的 `system` 后端需要 `secret-tool`、用户 D-Bus 会话和 Secret Service。Ubuntu/Debian 缺少工具时可安装 `libsecret-tools`。先启动并解锁桌面密钥环，再运行 `xops credential doctor`。

从 SSH、计划任务或其他用户会话运行时，可能无法访问桌面的密钥库。无人值守任务可以使用默认 key-file 离线库；已有凭据更换存储时请按[迁移指南](../guide/migration)操作。

## 离线库密钥丢失或维护中断

不要重新生成密钥覆盖旧文件。已有库必须使用原解锁材料；请从备份找回密钥。维护中断时保留库和相关文件，按照[离线库指南](../guide/offline-store)使用 `resume` 继续操作或从备份恢复。

## 主机指纹提示无法提交

在可交互终端中运行命令。普通文本提示应显示输入，按 Enter 提交，退格可编辑；密码不回显是正常行为。核对指纹后输入 `yes`，拒绝则输入 `no`。

Windows 上仍无法提交时，请更新 XOps 后重试，并记录终端类型。`context canceled` 表示操作被取消；若未主动取消，请记录完整的已脱敏错误以便排查。

## SFTP 命令返回后输入异常

等待远端命令结束并返回 SFTP 提示符后，再输入下一条命令。Windows 上若出现首字符丢失或 `read stdin failed: EOF`，请更新 XOps 后重试。问题仍存在时，请记录操作系统、终端、XOps 版本和触发步骤。

连接中断会让 SFTP shell 退出并返回失败状态。恢复网络后，重新运行 `xops sftp <节点>` 连接。

## exec -x 出现额外输出

`exec -x` 执行结束后返回本地终端。命令自身和远端登录启动脚本打印的提示仍会显示。请检查远端 Bash 启动文件，确认输出是否来自登录横幅或自定义脚本。完整交互 shell 请使用 `xops ssh`。

## 旧 Linux 内核提示 identify vault mount / function not implemented

请先更新 XOps。部分旧内核不支持离线库首选的挂载信息查询方式，XOps 会尝试通过 `/proc/self/fdinfo` 读取。容器或受限环境中，请确认 procfs 可访问并提供 `mnt_id` 信息。

运行 `xops credential store probe file` 检查目标目录的文件操作支持情况。若仍失败，请提供内核版本、文件系统类型及挂载方式。不要通过删除凭据库或密钥尝试修复。

## 节点不明确或配置修改冲突

地址或别名匹配多个节点时，使用 `xops host list` 查看并改用准确的节点 ID。配置编辑发生冲突时，重新读取最新配置，确认其他终端的修改后再编辑，避免覆盖他人的更改。

## 报告问题

请提供命令结构、XOps 版本、操作系统和终端类型、预期结果及已脱敏错误。不要提交密码、私钥、解锁材料或完整生产配置。可在 [GitHub Issues](https://github.com/wentf9/xops-cli/issues) 报告问题。
