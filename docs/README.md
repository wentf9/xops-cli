# XOps 设计文档

本目录记录需要跨包协作、分阶段实施或长期维护的架构决策与设计。

## 凭据持久化

- [ADR-0001：凭据持久化采用可插拔后端与引用模型](adr/0001-credential-persistence-backends.md)
- [ADR-0002：内置离线加密凭据库（v1 已冻结）](adr/0002-offline-encrypted-credential-store.md)
- [离线加密凭据库详细设计](design/offline-encrypted-credential-store.md)
- [离线凭据库格式与 KDF 协议 v1（已冻结）](design/offline-encrypted-credential-store-format.md)
- [离线凭据库格式与接口 v1 冻结记录](design/offline-encrypted-credential-store-v1-freeze.md)
- [离线加密凭据库实施进度](plans/offline-encrypted-credential-store-implementation.md)
- [离线凭据库阶段 A 密码学安全评估](design/offline-encrypted-credential-store-security.md)
- [凭据持久化详细设计](design/credential-persistence.md)
- [凭据持久化实施计划](plans/credential-persistence-implementation.md)
- [阶段 7：显式迁移、恢复与 finalize](credential-migration.md)

## 跨平台验证

- [macOS 兼容性验证指南](macos-verification.md)

## 离线库验收

离线库已完成 A–F 实现、部署验证和格式/接口 v1 冻结。各方案的实现状态与验证结果
分别记录于实施进度和验收文档。

- [离线加密凭据库使用与恢复](offline-encrypted-credentials.md)
- [离线库阶段 F 发布验收记录](plans/offline-encrypted-credential-store-release.md)
- [离线库原生部署与 KVM 断电验收](plans/offline-encrypted-credential-store-deployment.md)
- [离线库文件系统策略与兼容性验证](plans/offline-encrypted-credential-store-filesystems.md)
- [离线库冻结前最终工程审查](plans/offline-encrypted-credential-store-freeze-review.md)
