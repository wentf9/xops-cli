# 离线加密凭据库发布验收记录

- 日期：2026-09-10
- 格式与接口：v1 已冻结
- 验收状态：部署验证与冻结审查通过
- 发布状态：未发布

## 验收结果

| 验收项 | 结果 | 证据 |
| --- | --- | --- |
| 独立格式向量 | 通过 | Python cryptography/libargon2 生成结果与固定向量逐字节一致 |
| 格式与协议边界 | 通过 | 长度、整数边界、未知套件、身份替换、认证失败及三组 fuzz |
| 文件系统兼容性 | 通过 | ext4、XFS、Btrfs 四包 integration race；Btrfs 包含子卷场景 |
| 离线单二进制 | 通过 | 无网络接口和路由、空 PATH、真实主口令 KDF 与 key-file 操作 |
| 备份恢复 | 通过 | 停写归档、隔离工作副本、新代次恢复、原引用与原值核对 |
| 恢复反例 | 通过 | 恢复条目缺失或密文篡改时，原值校验失败并停止后续写入 |
| KDF 资源与回收 | 通过 | 原生 CLI 在 128 MiB cgroup 下派生，覆盖 OOM 分类和子进程回收 |
| KVM 断电恢复 | 通过 | 三种文件系统各 14 个断电点，共 42 项 |
| 工程审查 | 通过 | 预算清理、原始字节身份去重、模式转换和非交互读取缺陷已关闭 |
| 编译、测试与静态检查 | 通过 | build、test、race、普通及 integration/vaultpowercut lint |
| 格式与接口冻结 | 完成 | v1 格式、KDF 帧、配置字段、CLI 选项和 JSON 契约已记录 |
| Windows/macOS 构建 | 通过 | 仅交叉编译；离线库未提供原生运行支持 |

## 验证设施

- [离线演练脚本](../../scripts/verify_offline_vault.py)：驱动真实 CLI，检查空 PATH、网络隔离、归档不变和恢复后写入。
- [原值校验器](../../scripts/offline-vault-verify/main.go)：通过原配置引用调用 Get，比较公开测试值，不输出秘密。
- [恢复反例测试](../../scripts/test_offline_vault_drill.py)：覆盖成功恢复、条目删除和密文篡改。
- [原生容器验证](../../scripts/validation/run-container.sh)：在指定测试文件系统中执行离线演练与四包 integration race。
- [KVM 驱动](../../scripts/validation/verify_powercut.py)：在受控断电点终止测试 VM，重启测试盘并验证恢复。

Python、测试校验器和容器工具仅用于验收，不属于 XOps 运行依赖。

## 已关闭缺陷

| 缺陷 | 修复与验证 |
| --- | --- |
| Prune 仅校验预算 MAC，未核对条目数量 | 首次清理与 Resume 清理均检查预算下限；异常保留旧修订和事务 |
| 恢复演练先写入新凭据，可能掩盖条目丢失 | 恢复后先按原引用读取并比对原值；缺失和篡改反例正确失败 |
| 后端去重键经 JSON 编码丢失原始字节 | 改用结构化键，区分 StoreID、库路径、密钥路径及会话策略 |
| Linux 非交互调用拒绝读取已解锁系统凭据 | 使用 Secret Service 直接读取，不调用 Unlock/Prompt；普通 exec 连接验证通过 |

## 复验命令

```sh
go build ./...
go test ./...
GORACE=atexit_sleep_ms=0 go test -race ./... -timeout=240s
golangci-lint run ./...
golangci-lint run --build-tags=integration,vaultpowercut ./...
```

KDF 硬限额测试使用无 race 的实际 CLI，测试驱动继续启用 race：

```sh
umask 077
XOPS_TEST_CLI_PATH=<absolute-candidate-cli> GORACE=atexit_sleep_ms=0 \
  go test -tags=integration -race ./internal/credentialfile ./internal/kdfhelper \
  ./pkg/config ./cmd -count=1 -timeout=240s
```

两组 lint 串行执行。GORACE 设置只移除测试子进程的退出等待，不关闭竞态检测。
cgroup 测试因权限不足而跳过时，不计为硬限额验收通过。

## 证据范围

文件系统类型不作为访问白名单，部署环境负责存储可靠性。KVM 结果覆盖 guest
内核与页缓存丢失，不构成物理控制器、SSD 固件或设备易失缓存的掉电保证。
交叉编译不等于平台原生支持，工程复核不等于第三方安全认证。

- [原生部署验收](offline-encrypted-credential-store-deployment.md)
- [文件系统兼容性验证](offline-encrypted-credential-store-filesystems.md)
- [冻结审查](offline-encrypted-credential-store-freeze-review.md)
- [v1 冻结记录](../design/offline-encrypted-credential-store-v1-freeze.md)
