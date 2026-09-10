# 离线凭据库原生部署验收

- 日期：2026-09-10
- 验证对象：Linux 桌面环境、Linux 无桌面环境及隔离 KVM
- 结果：原生部署、离线恢复和 KDF 资源验证通过

## 环境

| 环境 | 存储与隔离 | 已验证内容 |
| --- | --- | --- |
| CachyOS Linux 7.2.2，amd64 | 独立 ext4 测试盘；Docker 网络隔离 | 离线演练、恢复正反例、四包 integration race |
| Ubuntu 24.04，Linux 6.8，amd64，4 GiB RAM | 原生 ext4；独立 mount/network namespace | 无桌面运行、离线演练、恢复正反例、四包 integration race |
| KVM，2 vCPU、512 MiB RAM | 独立 ext4 virtio 测试盘；无网络 | 14 个 guest 断电恢复点 |

CLI 与原值校验器使用 Go 1.27.1、CGO_ENABLED=0 构建。测试驱动使用
golangci-lint 2.13.2、Python 标准库和公开测试材料。文件系统验证范围已扩展为
ext4、XFS、Btrfs，详见[兼容性记录](offline-encrypted-credential-store-filesystems.md)。

## 离线与恢复结果

桌面和无桌面环境均验证了以下结果：

- network_isolated=true，external_helper_path=empty。
- 主口令 KDF 在无网络、无外部 helper 的环境中完成。
- 备份恢复使用新 DEK，代次按 1 → 2 → 3 递增。
- 恢复后按原引用读取并比对公开原值，随后执行新写入、重加密和清理。
- 归档内容保持不变。
- 恢复条目缺失和密文篡改反例均在原值校验处失败。

网络隔离通过独立 namespace 实现，宿主网络配置保持不变。无桌面环境的
namespace 创建使用提权进程，普通读写与集成测试使用非特权账户。

## KDF 资源与生命周期

128 MiB cgroup 验收采用无 race 的真实 CLI，并覆盖派生成功、超量测试 helper
被终止、OOM 错误分类和私有子组回收。并发与生命周期测试单独启用 race。

race 测试程序的额外开销可触发 128 MiB 上限，不能作为生产 CLI 的资源预算依据。
systemd 父 service 的 Memory peak 不包含独立 KDF 子组，不能用于推断 CLI 峰值 RSS。

测试进程设置 umask 077，避免可被组写入的测试目录触发密钥路径权限检查。
生产路径检查和资源限额保持不变。

## 断电验证

[host 驱动](../../scripts/validation/verify_powercut.py)、
[guest init](../../scripts/validation/vm-init.sh)和
[测试入口](../../internal/credentialfile/powercut_integration_test.go)完成跨启动恢复验证。
故障注入入口仅在 integration,vaultpowercut 测试标签下编译。

1. 在新测试盘初始化库、保存公开原值并重加密，正常同步关机形成基线。
2. 每个用例复制基线，在指定文件操作完成后暂停。
3. host 终止并回收独立 QEMU 进程，丢弃 guest 内核和页缓存。
4. 重启同一测试盘，执行 Resume、原值比较、新 ItemID 写入和 Prune。

已覆盖 building、预算同步与发布、条目发布、verified、CURRENT 发布、commit
归档及清理操作。磁盘使用 cache=none,aio=threads。

## 验证设施

原生测试使用 [Dockerfile](../../scripts/validation/Dockerfile) 和
[容器脚本](../../scripts/validation/run-container.sh)。测试包保留各包所需的相对
工作目录、固定向量和示例配置。静态 CLI 在空 PATH 下运行；glibc 仅供 race
测试程序使用，Python 仅用于驱动演练。

VM initramfs 包含 /init 和 /lab/powercut.test。guest 内核提供 ext4、virtio、
devtmpfs 支持；其他测试文件系统按兼容性记录加载对应模块。驱动创建独立文件磁盘，
每阶段限时 70 秒，日志上限 4 MiB，异常时终止并回收测试 QEMU。

## 验证边界

原生 Linux 文件调用、进程退出和 KVM 断电分别形成独立证据。guest 断电不替代
物理设备掉电验证。测试数据隔离于生产配置和凭据；网络或特殊文件系统未做专项适配。
