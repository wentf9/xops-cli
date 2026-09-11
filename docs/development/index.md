# 参与开发

Go 版本要求为 **1.26+**。修改逻辑时同步测试和相关文档，提交 PR 前运行：

```bash
go build ./...
go test ./...
golangci-lint run ./...
```

复用包负责包装并传递错误，由 CLI 层呈现。网络操作需超时，资源与 goroutine 需要确定的退出路径。Windows 特性不能仅凭交叉编译宣称运行验证通过。

## 架构与历史资料

历史开发文档统一归集于 `docs/development/archive/`，以下链接打开 GitHub：

- [历史开发文档总索引](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/README.md)
- [凭据后端 ADR](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/adr/0001-credential-persistence-backends.md)
- [离线库 ADR](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/adr/0002-offline-encrypted-credential-store.md)
- [凭据实现设计](https://github.com/wentf9/xops-cli/blob/master/docs/development/archive/design/credential-persistence.md)

历史实施记录反映当时的验证范围，不自动代表当前所有平台已经验证。文档贡献流程见[文档维护](./docs)。
