# 历史开发文档归档

本目录统一保存原先散落于 `docs/` 根目录及 ADR、设计、实施计划目录的开发文档。
原文的设计决策、实施状态与验证结论予以保留；归档不代表已废弃，也不表示历史验证结论自动适用于当前所有版本或平台。

当前使用指南与双语文档维护方式见[开发入口](../index.md)及[文档维护](../docs.md)。
本归档以中文原文为主，作为开发资料在 GitHub 上阅读，不纳入双语用户手册的页面对齐检查。

## 架构决策与测量依据

- [ADR-0001：凭据持久化后端与引用模型](adr/0001-credential-persistence-backends.md)
- [ADR-0002：离线加密凭据库](adr/0002-offline-encrypted-credential-store.md)
- [受限资源环境 KDF 测量](adr/0002-kdf-measurement.md)

## 设计与协议

- [凭据持久化设计](design/credential-persistence.md)
- [离线加密凭据库设计](design/offline-encrypted-credential-store.md)
- [离线库格式与 KDF 协议](design/offline-encrypted-credential-store-format.md)
- [离线库格式与接口 v1 冻结记录](design/offline-encrypted-credential-store-v1-freeze.md)
- [离线库安全评估](design/offline-encrypted-credential-store-security.md)

## 实施与验收

- [凭据持久化实施计划](plans/credential-persistence-implementation.md)
- [离线库实施进度](plans/offline-encrypted-credential-store-implementation.md)
- [离线库部署与断电验收](plans/offline-encrypted-credential-store-deployment.md)
- [文件系统兼容性验证](plans/offline-encrypted-credential-store-filesystems.md)
- [冻结前工程审查](plans/offline-encrypted-credential-store-freeze-review.md)
- [发布验收记录](plans/offline-encrypted-credential-store-release.md)

## 操作说明与专项记录

- [凭据命令审计](credential-command-audit.md)
- [凭据迁移与恢复](credential-migration.md)
- [离线加密凭据库操作与恢复](offline-encrypted-credentials.md)
- [macOS 原生验证](macos-verification.md)
- [交互式 exec 行为](interactive-exec.md)

## 跨平台整改记录

- [平台适配实现与验证边界](offline-platform-compatibility.md)
