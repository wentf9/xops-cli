# 离线凭据库兼容性

离线库共用 v1 格式和事务协议，通过原生适配层支持 Linux、Windows 和 macOS 的 amd64/arm64 平台。不依赖 Secret Service、D-Bus、pass 或外部凭据管理器；主口令 KDF 由 XOps 自身启动的私有子进程执行。

## 验证矩阵

| 环境 | 验证范围 |
| --- | --- |
| Linux amd64：Ubuntu 24.04 | 原生单元测试、真实 KDF、维护与进程崩溃恢复 |
| Linux ARM64：Ubuntu 24.04 | 同上 |
| CentOS 7：3.10 内核、XFS、amd64 | 实机临时库端到端操作与真实 KDF |
| Windows amd64 | 原生 ACL、文件锁、维护与进程崩溃恢复 |
| Windows ARM64 | 原生 CI 单独覆盖；Go 不支持该目标的 race detector |
| macOS ARM64 / Intel | 原生 ACL、文件锁、真实 KDF、维护与进程崩溃恢复 |

最新运行记录见 [原生兼容性工作流](https://github.com/wentf9/xops-cli/actions/workflows/offline-compatibility.yml)。构建成功不等于原生验证通过；托管 CI 的进程崩溃恢复也不等于真实断电验收。

## 初始化前的能力检查

```bash
xops credential store probe file
xops credential store init file
xops credential store inspect file --verify
```

`probe` 显式创建并清理一个临时私有目录，检查排他文件发布、覆盖重命名、排他目录发布、文件锁和同步调用。目标已存在时检查目标文件系统，并对已初始化库持有锁；目标不存在时检查父目录。它不初始化库、不生成 key-file、不读取凭据内容。doctor 的默认只读检查不会执行这些写探测。

## 平台差异

- Linux：优先 statx 获取挂载 ID，旧内核回退到 proc fdinfo；普通覆盖使用 POSIX rename。
- macOS：使用原生排他重命名和完整文件同步；额外 ACL 数据授权不会被 POSIX 权限位掩盖。
- Windows：使用私有 ACL、拒绝 reparse point、原生文件锁及 write-through 发布；允许复用已经配置的只读密钥文件。
- KDF：Linux 支持 cgroup v1/v2 内存观察；Windows 使用 kill-on-close Job Object；macOS 监视父进程退出。

## 必须保留的边界

文件系统仍须提供可靠的权限、锁、原子发布与持久化语义。Linux 排他发布不支持时会明确拒绝，不以“先判断存在、再覆盖”的竞态操作替代。符号链接、危险 ACL 或不安全权限仍会被拒绝。

存储介质损坏或内核文件系统 I/O 卡死时，context 不能保证立即打断系统调用。网络/FUSE 文件系统及真实断电场景需额外部署验收；不得把一次 probe 成功理解为对未来故障或全部存储介质的保证。

本轮原生验证已通过：[CI 34571151620](https://github.com/wentf9/xops-cli/actions/runs/34571151620)，对应提交 `0d7d574`。
