# 离线凭据库文件系统兼容性记录

- 日期：2026-09-10
- 访问策略：移除文件系统类型白名单
- 验证范围：ext4、XFS、Btrfs
- 结果：完整回归和 42 个 KVM 断电恢复点通过

## 实现变更

删除 fstatfs magic 和 mountinfo 文件系统名称判定。初始化与已有库打开均不按
类型拒绝访问。部署环境负责保证锁、原子发布及文件/目录同步的可靠性。

安全逐级打开、0700/0600 权限、所有者、文件类型、设备号、挂载 ID（优先 statx，旧内核使用 /proc/self/fdinfo） 和
库内同挂载检查保持有效。flock、RENAME_NOREPLACE 和同步操作继续执行，
操作不受支持或失败时返回明确错误。文件格式和加密算法保持不变。

## 验证矩阵

环境为 Linux 7.2.2 / amd64，Go 1.27.1，golangci-lint 2.13.2。使用独立
512 MiB 测试镜像。格式化工具包含 mkfs.xfs 7.1.1 和 mkfs.btrfs 7.1。

| 文件系统 | 离线与恢复正反例 | 四包 integration race | KVM 断电恢复 |
| --- | --- | --- | --- |
| ext4 | 通过 | 通过 | 14/14 |
| XFS | 通过 | 通过 | 14/14 |
| Btrfs，包含子卷 | 通过 | 通过 | 14/14 |

四包为 credentialfile、kdfhelper、pkg/config 和 cmd。TMPDIR/GOTMPDIR 指向
选定文件系统，Btrfs 使用独立测试子卷。离线演练使用 network=none 和空 PATH。

恢复验证先读取原引用及原值，再执行新凭据写入。条目缺失和密文篡改反例正确失败。
现有 XFS 目录直接运行 CLI 演练通过，无须建立 ext4 文件系统。

tmpfs 初始化、打开和公开值演练通过，用于确认访问策略不依赖类型白名单；
该结果不构成持久性保证。跨设备/挂载拒绝和错误路径句柄回收有独立回归覆盖。

## 断电覆盖

三种文件系统均验证以下 14 个断电点：

| 操作 | 位置 | 数量 |
| --- | --- | --- |
| reencrypt | building 阶段记录完成 | 1 |
| reencrypt | budget file-sync、publish、dir-sync | 3 |
| reencrypt | item publish、verified 阶段记录完成 | 2 |
| reencrypt | CURRENT file-sync、publish、dir-sync | 3 |
| reencrypt | commit 归档 | 1 |
| prune | unlink、unlink-sync、rmdir、prune-archive | 4 |

每次重启检查 Resume、原值、新 ItemID 写入及 Prune。QEMU 使用无网络、cache=none
的 virtio 测试盘。结果覆盖 guest 断电，不覆盖物理控制器或 SSD 掉电。

## 设施与检查

[容器脚本](../../../../scripts/validation/run-container.sh)按 ext4/xfs/btrfs 参数选择测试镜像；
参数范围仅定义测试矩阵。容器串行启动，避免 loop 设备节点创建时序影响测试设施。

[KVM 驱动](../../../../scripts/validation/verify_powercut.py)通过 --filesystem 选择目标类型。
guest 使用对应类型挂载独立磁盘；XFS 模块与 guest 内核版本匹配。

```sh
python3 scripts/validation/verify_powercut.py --filesystem xfs \
  --kernel <kernel-image> --initrd <initramfs-image> --output <evidence-directory>
```

全仓 build/test/race、普通及 integration/vaultpowercut lint、五个 Python
驱动测试通过。容器内因委派权限不足跳过的 cgroup 测试不计入通过结果；
KDF 限额与回收依据[原生部署验收](offline-encrypted-credential-store-deployment.md)。

文件系统适配未改变加密、预算或恢复协议。[格式与接口 v1 已冻结](../design/offline-encrypted-credential-store-v1-freeze.md)。
