# 参与开发（XOps v2）

XOps v2 采用 **Go 1.27+**（`CGO_ENABLED=0`）与三模块 Go Workspace（[`go.work`](../../go.work)）：

- 根 CLI 模块（[`go.mod`](../../go.mod)）：纯叶层国际化词库 `internal/i18n`、本机宿主适配器 `internal/host/**`、入站入口 `internal/entry/**` 与唯一组合根 `cmd/xops`；
- 六边形核心模块（[`core/go.mod`](../../core/go.mod)）：无宿主假设的核心契约、运行期与领域模型（含纯数据延迟本地化绝对叶包 `core/domain/i18n`）；
- 自建静态分析器模块（[`tools/xopsvet/go.mod`](../../tools/xopsvet/go.mod)）：10 大正交架构/安全/并发/国际化编译器护栏。

全仓开发与架构约束以仓库根目录的 **[工程宪法与 AI 协作规范（AGENTS.md）](../../AGENTS.md)** 为最高事实源，严禁引入 v1 兼容垫片或长期 `replace`。

## 本地验证门禁

全仓统一通过单一事实源脚本 [`scripts/ci/verify.go`](../../scripts/ci/verify.go)（外层不设 `GOWORK=off`，由脚本按模块控制隔离环境）执行验证；修改代码或文档后，提交 PR 前请按改动范围运行对应门禁：

```bash
# 1. 全量三模块构建、xopsvet 护栏、golangci-lint 与竞态测试（等价于 make verify）
go run ./scripts/ci/verify.go --stage=all

# 2. Windows / macOS 跨平台交叉编译、跨平台 xopsvet 与交叉 Lint（等价于 make cross）
go run ./scripts/ci/verify.go --stage=cross

# 3. 确定性仿真门禁 DST（等价于 make dst）
go run ./scripts/ci/verify.go --stage=dst

# 4. 正式发布前锁定 core Tag 的三模块全量 GOWORK=off 验收（等价于 make verify-release）
go run ./scripts/ci/verify.go --stage=all --gowork-off

# 5. CI 变更分类脚本单测与用户文档双语一致性校验
python3 -m unittest discover -s scripts -p test_ci_changes.py -v
npm run docs:check
```

交叉编译与静态检查不等于目标平台原生测试通过；Windows、macOS 与 FreeBSD 平台特性以原生环境执行结果为准（搭建方案见[本地多平台测试与私有 CI 指南](./v2-local-multiplatform-ci.md)）。

## 活跃开发文档（XOps v2）

根据 [AGENTS.md](../../AGENTS.md) 第 7 节约定，开发文档统一使用简体中文维护，不纳入面向用户的双语站点构建：

- [工程宪法与 AI 协作规范（AGENTS.md）](../../AGENTS.md)
- [XOps v2 全新架构定稿规范（Architecture RFC）](./v2-architecture-rfc.md)
- [XOps v2 全新架构分阶段实施计划（Implementation Plan）](./v2-implementation-plan.md)
- [XOps v2 本地多平台测试与私有 CI 搭建指南](./v2-local-multiplatform-ci.md)
- [文档维护指南](./docs.md)

## 历史文档归档

早期 v1 设计/治理/实施记录及已停用的英文开发文档镜像统一归档于 `docs/development/archive/`，仅作客观历史资料只读参考（不代表 XOps v2 当前架构契约，严禁向 v2 回流旧架构结构）：

- [历史开发文档归档总索引](./archive/README.md)
