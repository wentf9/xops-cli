# XOps 设计文档

本目录记录需要跨包协作、分阶段实施或长期维护的架构决策与设计。

## 凭据持久化

- [ADR-0001：凭据持久化采用可插拔后端与引用模型](adr/0001-credential-persistence-backends.md)
- [ADR-0002（提议）：内置离线加密凭据库](adr/0002-offline-encrypted-credential-store.md)
- [凭据持久化详细设计](design/credential-persistence.md)
- [凭据持久化实施计划](plans/credential-persistence-implementation.md)
- [阶段 7：显式迁移、恢复与 finalize](credential-migration.md)

## 跨平台验证

- [macOS 兼容性验证指南](macos-verification.md)

当前文档描述的是待实施方案，不代表相关代码已经完成。开始实现前，应先确认 ADR
中的决策门，并保持结构重构、行为变更和兼容性清理分别提交。
