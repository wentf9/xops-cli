# 历史开发文档归档

本目录统一保存 XOps v1 演进期间的架构决策、设计方案、实施计划、治理基线、专项验证记录，以及已停用的早期英文开发文档镜像与 v2.2 英文草案。

原文的设计决策、实施状态与验证结论予以保留，仅作客观历史资料只读参考；归档文档不代表当前 XOps v2 的生产架构、代码路径或跨平台验证范围，严禁将旧版结构回流至 XOps v2 代码库。

当前活跃的 XOps v2 开发文档与工程规范请参见：

- [工程宪法与 AI 协作规范（AGENTS.md）](../../../AGENTS.md)
- [参与开发（XOps v2）](../index.md)
- [XOps v2 全新架构定稿规范（Architecture RFC v2.3.3）](../v2-architecture-rfc.md)
- [XOps v2 全新架构分阶段实施计划（Implementation Plan）](../v2-implementation-plan.md)
- [XOps v2 本地多平台测试与私有 CI 搭建指南](../v2-local-multiplatform-ci.md)
- [文档维护指南](../docs.md)

本归档不参与用户文档站点构建，也不纳入双语用户手册的页面对齐检查。

---

## 一、v1 架构治理与防漂移基线（`v1/governance/`）

原 `docs/development/governance/` 下的 v1 代码治理文档（基线 `b15df20`，作为 XOps v2 清场重构前的问题诊断与领域规则只读参考）：

- [XOps CLI 代码地图（v1）](v1/governance/architecture-map.md)
- [建议优先掌握的 4 条关键链路（v1）](v1/governance/flows.md)
- [XOps CLI 架构不变量、隐式契约与防漂移治理基线（v1）](v1/governance/invariants.md)
- [XOps 功能归属速查（v1）](v1/governance/ownership.md)
- [XOps 改动验证矩阵（v1）](v1/governance/validation-matrix.md)

## 二、v1 专项设计与实施文档（`v1/`）

原 `docs/development/` 根目录下的 v1 专项设计、实施与诊断文档：

### SSH 连接、多路复用、执行与诊断

- [OpenSSH 连接多路复用永久设计规范](v1/openssh-multiplexing-design.md)
- [SSH 多解释器执行与兼容性设计](v1/ssh-execution-compatibility.md)
- [SSH 执行兼容性实施计划](v1/ssh-execution-implementation.md)
- [SSH 解释器与启动方言自动探测设计](v1/ssh-execution-probe-design.md)
- [SSH 执行环境探针实施记录](v1/ssh-execution-probe-implementation.md)
- [SSH OTP 与 `keyboard-interactive` 登录设计方案](v1/ssh-otp-keyboard-interactive-design.md)
- [SSH 分级诊断](v1/ssh-diagnostics.md)
- [SCP 分级诊断](v1/scp-diagnostics.md)
- [原生可取消输出](v1/native-cancelable-output.md)

### MCP 演进与公共核心解耦

- [公共代码与 MCP 接口解耦设计](v1/shared-core-decoupling.md)
- [MCP Streamable HTTP 与文件流转发设计](v1/mcp-http-transfer-design.md)
- [MCP 极简全能型工具架构重构设计方案](v1/mcp-minimal-tools-design.md)
- [基于 FreeBSD 实机验证的 MCP 改进方案](v1/mcp-freebsd-validation-plan.md)

### 凭据体验与离线库兼容性

- [离线凭据库兼容性](v1/compatibility.md)
- [凭据零配置体验设计](v1/credential-experience-design.md)
- [凭据体验实施计划](v1/credential-experience-plan.md)
- [凭据体验更新说明草案](v1/credential-experience-release.md)

## 三、早期 ADR、凭据持久化设计与验收记录

原先归集于本目录的早期 ADR、设计规范、实施计划与验收记录：

### 架构决策与测量依据（`adr/`）

- [ADR-0001：凭据持久化后端与引用模型](adr/0001-credential-persistence-backends.md)
- [ADR-0002：离线加密凭据库](adr/0002-offline-encrypted-credential-store.md)
- [ADR-0002：受限资源环境 KDF 测量](adr/0002-kdf-measurement.md)

### 设计与协议（`design/`）

- [凭据持久化详细设计](design/credential-persistence.md)
- [内置离线加密凭据库详细设计](design/offline-encrypted-credential-store.md)
- [离线凭据库格式与 KDF 协议 v1](design/offline-encrypted-credential-store-format.md)
- [离线凭据库格式与接口 v1 冻结记录](design/offline-encrypted-credential-store-v1-freeze.md)
- [离线凭据库阶段 A 密码学安全评估](design/offline-encrypted-credential-store-security.md)

### 实施与验收（`plans/`）

- [凭据持久化实施计划](plans/credential-persistence-implementation.md)
- [离线加密凭据库实施进度](plans/offline-encrypted-credential-store-implementation.md)
- [离线凭据库原生部署验收](plans/offline-encrypted-credential-store-deployment.md)
- [离线凭据库文件系统兼容性记录](plans/offline-encrypted-credential-store-filesystems.md)
- [离线凭据库冻结审查记录](plans/offline-encrypted-credential-store-freeze-review.md)
- [离线加密凭据库发布验收记录](plans/offline-encrypted-credential-store-release.md)

### 操作说明与专项记录

- [阶段 8 命令凭据接入核对](credential-command-audit.md)
- [凭据显式迁移（阶段 7）](credential-migration.md)
- [离线加密凭据库操作与恢复](offline-encrypted-credentials.md)
- [macOS 跨平台兼容性验证指南](macos-verification.md)
- [交互式命令执行](interactive-exec.md)
- [平台适配实现与验证边界（Offline vault platform compatibility）](offline-platform-compatibility.md)

## 四、已停用的英文开发文档镜像与早期 v2.2 英文草案（`v1-en/`）

原 `docs/en/development/` 目录的完整历史归档。依据 [AGENTS.md](../../../AGENTS.md) 第 5 节（开发文档不再要求维护英文双语版本，仅保证简体中文文档准确完整即可），英文开发文档镜像及过时的早期 v2.2 英文草案（已被简体中文 v2.3.3 终稿取代）统一归档于此：

### 早期入口与过时的 v2.2 英文草案

- [Development (Legacy Entry)](v1-en/index.md)
- [Writing documentation (Legacy)](v1-en/docs.md)
- [XOps v2 Clean-Slate Architecture Specification (Draft v2.2, superseded)](v1-en/v2-architecture-rfc.md)
- [XOps v2 Clean-Slate Phased Implementation Plan (Draft v2.2, superseded)](v1-en/v2-implementation-plan.md)

### v1 英文架构治理基线（`v1-en/governance/`）

- [XOps CLI Architecture Map (v1, EN)](v1-en/governance/architecture-map.md)
- [Four Core Execution and Persistence Flows (v1, EN)](v1-en/governance/flows.md)
- [Architectural Invariants, Explicit Contracts & Anti-Drift Baseline (v1, EN)](v1-en/governance/invariants.md)
- [XOps Ownership Quick Reference (v1, EN)](v1-en/governance/ownership.md)
- [XOps Change Validation Matrix (v1, EN)](v1-en/governance/validation-matrix.md)

### v1 英文专项设计与实施镜像

- [OpenSSH Connection Multiplexing Design (EN)](v1-en/openssh-multiplexing-design.md)
- [SSH Interpreter and Execution Compatibility Design (EN)](v1-en/ssh-execution-compatibility.md)
- [SSH Execution Compatibility Implementation Plan (EN)](v1-en/ssh-execution-implementation.md)
- [SSH Interpreter and Launch Dialect Automated Probing Design (EN)](v1-en/ssh-execution-probe-design.md)
- [SSH Execution Probing Implementation Record (EN)](v1-en/ssh-execution-probe-implementation.md)
- [SSH OTP and `keyboard-interactive` Login Design (EN)](v1-en/ssh-otp-keyboard-interactive-design.md)
- [Leveled SSH diagnostics (EN)](v1-en/ssh-diagnostics.md)
- [SCP diagnostic levels (EN)](v1-en/scp-diagnostics.md)
- [Native cancelable output (EN)](v1-en/native-cancelable-output.md)
- [Shared core and MCP interface decoupling (EN)](v1-en/shared-core-decoupling.md)
- [MCP Streamable HTTP and file streaming design (EN)](v1-en/mcp-http-transfer-design.md)
- [Minimalist All-in-One MCP Tool Architecture Refactoring Design (EN)](v1-en/mcp-minimal-tools-design.md)
- [MCP Improvement Plan Based on Live FreeBSD Validation (EN)](v1-en/mcp-freebsd-validation-plan.md)
- [Offline vault compatibility (EN)](v1-en/compatibility.md)
- [Zero-configuration credential experience (EN)](v1-en/credential-experience-design.md)
- [Credential experience implementation plan (EN)](v1-en/credential-experience-plan.md)
- [Credential experience release-note draft (EN)](v1-en/credential-experience-release.md)
