# 离线凭据库冻结审查记录

- 日期：2026-09-10
- 审查结果：通过
- 格式与接口：v1 已冻结
- 审查范围：磁盘格式、私有 KDF 帧、配置、CLI/JSON 契约及相关身份、资源和恢复行为

## 已关闭缺陷

### 后端身份去重

后端去重键由 JSON 字符串改为保留原始字节的结构化键。原 JSON 编码将不同的
无效 UTF-8 字节替换为 U+FFFD，导致不同 StoreID、库路径或 key_file 路径复用
同一后端。结构化键包含身份、路径、期限、缓存和交互策略。

TestEncryptedBackendPreservesRawIdentityAndPaths 覆盖三类原始字节差异，
TestEncryptedBackendSeparatesSessionPolicies 覆盖策略隔离。修复前三类反例失败，
修复后三轮 race 和完整配置/调用链 integration race 通过。

### 契约文档同步

- 密钥文件权限说明统一为当前账户或 root 所有、0400/0600 的独立 32 字节普通文件。
- ErrUnsupported 说明统一为平台、必要文件操作或跨挂载边界限制，不表示类型白名单。
- KDF 说明记录固定入口、96 MiB 启动预检和已验收的 128 MiB cgroup 硬限额。
- 16 字节公共前缀限定于 meta/item/CURRENT/budget；state/manifest 使用独立编码。

## 审查结果

| 审查项 | 实现与证据 | 结论 |
| --- | --- | --- |
| ID 1..1024 字节、哈希文件名、导入/迁移契约 | format/codec.go、item.go；TestMaximumItemIdentifiersAndPayload、TestEncryptedReferenceBounds；原始字节去重回归；导入和迁移测试 | 通过 |
| ExpiresAt 与幂等值比较 | format/item.go 的精确 i64 纳秒检查；TestExpirySignedExtremes、TestFileStoreBudgetAndExpiryBoundaries、TestMaintenanceExpiredAndUnknownRevision；Put/读回比较使用 ConstantTimeCompare | 通过 |
| 分层版本、固定套件与精确字节 | format/meta.go、item.go、control.go、transaction.go、manifest.go；kdfhelper/protocol.go；完整独立向量重新生成后逐字节一致 | 通过 |
| GCM/HKDF/HMAC 工程安全界限 | 阶段 A 安全评估、TestEngineeringSecurityBudget；未修改算法、标签、nonce 或使用量上限 | 通过，保留原分析假设 |
| 预算耐久预留、恢复和清理 | 预算预留先于 Seal；TestMaintenanceBuildingBudgetUndercount、CommittedBudgetInvalid、ArchivedBudgetInvalid、PruneRejectsUnreliableBudget、来源证书及源清单测试 | 通过 |
| 模式转换、源/目标材料与 resume | TestMaintenanceWrappingModeConversion、TestMaintenanceNonInteractiveAndOverlap、TestMaintenanceTransferResumeAndWrongMarker；CLI clone/restore/operation 选择测试 | 通过 |
| 生命周期、取消与缓存失效 | Runtime 租约/epoch、共享解锁、idle timer；runtime regression、TestKDFParentDeathKillsWorker、Runner failure boundaries、goleak/race | 通过 |
| 文件系统兼容性与耐久性 | 保留句柄/设备/mount ID 检查；ext4/XFS/Btrfs 四包回归及 42 个 KVM 断电点，见文件系统验收记录 | 通过；不作为类型白名单 |
| KDF 内存与超时 | 原生真实 CLI 128 MiB cgroup 派生、OOM 分类/回收；单 KDF 与八库队列； integration 指向无 race 候选 CLI | 通过 |
| Linux system 非交互读取 | 无 Unlock/Prompt 路径、明确本地总线、deadline/取消、连接与会话关闭；锁定/重锁/无秘密错误/畸形值测试及无桌面主机普通 exec 实测 | 通过 |
| 平台边界 | Linux amd64 运行证据完整；其他平台仍返回 unsupported API；交叉编译不当作原生支持 | 通过，不扩展平台承诺 |


## 独立向量与格式验证

Python cryptography/libargon2 生成结果与固定 vectors.json 逐字节一致。
固定语料 SHA-256：

```text
0991874cd848a7f6a6be96fef4d2d8843fed277e4d0c08e50284a6d188551ced
```

磁盘格式、加密算法、标签、nonce 长度、使用量上限和 KDF 帧保持一致。
三组 fuzz 各运行约 10 秒，执行次数分别为：

| 目标 | 执行次数 | 结果 |
| --- | --- | --- |
| Containers | 101070 | 通过 |
| RecoveryFormats | 956706 | 通过 |
| Protocol | 1134403 | 通过 |

有限 fuzz 运行不构成穷尽证明。密码学结论沿用[工程安全评估](../design/offline-encrypted-credential-store-security.md)中的假设。

## 编译与运行验证

- 全仓 build、test、race 通过。
- credentialfile、kdfhelper、pkg/config、cmd 四包 integration race 通过。
- 普通及 integration/vaultpowercut lint 通过。
- Windows amd64、Darwin arm64 交叉编译通过，仅验证 unsupported API 组合完整。
- 无 race 的实际 CLI 在网络隔离和空 PATH 下完成 KDF、备份恢复、原引用/原值比较及后续写入，归档保持不变。

128 MiB 资源测试通过 XOPS_TEST_CLI_PATH 使用无 race 的实际 CLI；测试驱动启用
race。该方式区分生产资源预算和竞态检测附加开销，生产限额保持不变。

```sh
umask 077
XOPS_TEST_CLI_PATH=<absolute-candidate-cli> GORACE=atexit_sleep_ms=0 \
  go test -tags=integration -race ./internal/credentialfile ./internal/kdfhelper \
  ./pkg/config ./cmd -count=1 -timeout=240s
```

## 证据边界

文件系统、预算、事务、清理及 KDF 实现的验证依据包括[原生部署验收](offline-encrypted-credential-store-deployment.md)
和[三种文件系统共 42 个 KVM 断电恢复点](offline-encrypted-credential-store-filesystems.md)。
后端去重修复使用配置/调用链回归及实际 CLI 演练验证。

工程复核不替代第三方安全认证。CI 已接入离线凭据配置与命令业务集成测试，
不执行存储可靠性矩阵，其结果不能单独证明全部部署验证完成。冻结范围与兼容性规则见
[v1 冻结记录](../design/offline-encrypted-credential-store-v1-freeze.md)。
