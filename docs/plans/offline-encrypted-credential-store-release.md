# 阶段 F 发布验收记录

日期：2026-09-10。状态：本地验收与发布材料已完成，正式发布条件尚未全部满足。
本记录不代表已提交、推送、打标签或发布，也不替代第三方安全认证。

## 环境与证据边界

- Go 1.26.7，linux/amd64。
- Linux 6.18.35.2-microsoft-standard-WSL2，本地真实 ext4 文件系统。
- 使用私有临时目录、公开测试秘密及公开测试密钥；没有访问 vpsc 或真实凭据。
- 文件层使用实际 Linux 系统调用，覆盖文件权限、稳定锁、rename、fsync 和真实
  子进程退出。WSL2 结果不是独立发行版/物理部署机器的验证，也不是断电保证。

| 验收项 | 本轮结果 | 证据或限制 |
| --- | --- | --- |
| 用户指南与命令边界 | 完成 | [使用与恢复指南](../offline-encrypted-credentials.md) |
| 当前 Linux/ext4 文件事务 | 本地通过 | 文件层和维护 integration race；含子进程退出与错误注入 |
| 离线单二进制 | 通过 | 新网络 namespace 中无外部接口/路由；子命令 PATH 为空；真实 key-file 与主口令 KDF |
| 停写备份与恢复演练 | 通过 | 完整配置/库/密钥归档，隔离工作副本恢复到新根，新代次，原归档内容未变 |
| 恢复后正常调用 | 通过 | Service Put/read-back/CAS/Delete，随后重加密、prune 和认证检查 |
| 非支持文件系统 | 通过反例 | tmpfs 返回 unsupported，未创建目标库 |
| 独立工程代码复核 | 已完成并关闭发现 | 独立 agent 只读复核完整后端及 helper、迁移密钥保护；见下文 |
| build/test/race/lint | 通过 | 下列本地命令；没有用跳过的测试替代原生验证 |
| Windows/macOS | 未声明支持 | 阶段 E CLI 交叉编译通过；仅提供 unsupported API，无本轮原生运行证据 |
| 非 WSL 部署环境 | 待完成 | 需在实际 Linux amd64/ext4 部署目标重复验收 |
| 真实断电实验 | 未执行 | 当前环境无隔离 VM 工具；进程退出不能替代断电实验 |
| 格式冻结与正式发布 | 待最终验收 | 本轮不扩展支持矩阵，不改变格式字节，不打标签或发布 |

## 可重复离线演练

[scripts/verify_offline_vault.py](../../scripts/verify_offline_vault.py) 使用 Python 标准库
驱动实际 XOps 二进制。Python 和 `scripts/offline-vault-verify` 均为测试驱动器，不是 XOps 运行依赖。
校验器通过原配置引用调用实际 Get，常量时间比较公开测试值，不打印秘密。脚本在临时目录
创建公开测试材料，结束后删除该目录；不会使用用户配置或服务器。

本轮构建使用 `CGO_ENABLED=0 go build -o <work>/xops ./cmd/cli`。受测二进制 SHA-256：

```
cd214b60bace9f4c2f5131cd63495fe43f258f669edea6094b65fb1eba559302
```

由于全部实现尚未提交，哈希仅对应本轮工作树构建，不是发布版本标识。

在支持无特权 user/mount/network namespace 的 Linux 上，可执行以下步骤。绑定
挂载仅发生在新 mount namespace 中，使测试 /tmp 保持 ext4 且所有者正确，不更改
宿主机挂载或网络配置；拒绝以关闭主机网络的方式模拟离线。

```sh
release_work=$(mktemp -d /tmp/xops-release.XXXXXX)
CGO_ENABLED=0 go build -o "$release_work/xops" ./cmd/cli
CGO_ENABLED=0 go build -o "$release_work/verifier" ./scripts/offline-vault-verify
cp scripts/verify_offline_vault.py "$release_work/drill.py"
unshare --user --map-root-user --mount --net /bin/sh -c \
  'mount --bind "$1" /tmp && exec /usr/bin/python3 /tmp/drill.py --binary /tmp/xops --verifier /tmp/verifier --require-isolation' \
  sh "$release_work"
```

namespace 不可用时应记录未执行，不能去掉隔离要求后仍声称已验证离线。脚本成功
输出包含以下事实：network_isolated=true、external_helper_path=empty、
password_kdf_offline=true、archive_unchanged=true；本轮代次依次为 1 → 2 → 3。
恢复内部逐条认证并读回比较，同时校验备份配置所需引用。脚本还在备份前记录原引用，
恢复后用独立校验器读取原引用、比对原值，再允许新凭据写入，避免轮换掩盖数据丢失。
报告要求 original_reference_verified=true 和 original_value_verified=true，记录校验器
的二进制哈希；此演练不使用 CLI 输出秘密。

固定格式向量文件 SHA-256：

```
0991874cd848a7f6a6be96fef4d2d8843fed277e4d0c08e50284a6d188551ced
```

## 独立复核发现与修复

独立 agent 复核固定 KDF 参数、密钥包裹和条目身份绑定、清零/取消/helper 回收、
恢复双端认证与锁后重检、清理证书及源标记、迁移文件别名保护。它发现 Prune 仅认证
当前预算 MAC，未核对当前条目数量，可能在可检测的 undercount 状态删除旧修订。

已修复为：首次 Prune 在创建意图前检查当前预算与可变条目集合；Resume 清理路径
在删除前重复检查。异常保留旧修订和已有意图。原独立 overlay 复现与新增首次调用/
Resume 回归经两轮 race 通过；独立复核确认该发现关闭，未发现其他有证据的阻塞问题。
此结论限于工程复核范围，不等同第三方密码学认证。

## 本地验证命令

```sh
go build ./...
go test ./...
GORACE=atexit_sleep_ms=0 go test -race ./... -timeout=240s
golangci-lint run ./...
golangci-lint run --build-tags=integration ./...
GORACE=atexit_sleep_ms=0 go test -tags=integration -race \
  ./internal/credentialfile ./internal/kdfhelper ./pkg/config ./cmd -count=1 -timeout=240s
git diff --check
```

两组 lint 必须串行运行，避免进程锁冲突。GORACE 设置仅去除测试子进程的默认退出
等待，不禁用竞态检测；正式 CLI 超时保持不变。Prune 新增回归另执行三轮 race。

## 正式发布前剩余工作

1. 在实际 Linux amd64/ext4 部署目标重复上述验证，记录内核、挂载与存储环境。
2. 在可销毁的隔离 VM/测试盘评估断电场景，覆盖预算预留、CURRENT 发布、事务归档
   和清理；不得在运行中的 vpsc 或唯一备份上实验。
3. 汇总部署证据后完成格式冻结与最终验收，再按用户明确指令提交、推送或发布。

## 发布演练误报修复

原脚本在恢复后直接 set 新凭据，无法识别恢复出的条目缺失。现已加入独立 Get/
原引用/原值核对，失败即停止，不进入轮换和 prune。公开测试值只在进程内比较。
XOps 命令仍在空 PATH、网络隔离下独立运行；校验器由测试驱动器单独调用，不能把
校验器称为 XOps 运行依赖。

正例和两个反例位于 `scripts/test_offline_vault_drill.py`：真实 restore 成功后注入
条目删除或密文篡改，必须在原值校验处失败。可在同一 namespace 中运行：

```sh
cp scripts/verify_offline_vault.py "$release_work/verify_offline_vault.py"
cp scripts/test_offline_vault_drill.py "$release_work/test_offline_vault_drill.py"
unshare --user --map-root-user --mount --net /bin/sh -c \
  'mount --bind "$1" /tmp && exec /usr/bin/python3 /tmp/test_offline_vault_drill.py --binary /tmp/xops --verifier /tmp/verifier' \
  sh "$release_work"
```

原先不含独立原值校验的 passed 记录不能单独作为备份可恢复的充分证据；当前完整
演练及故障反例已重新执行。部署环境与断电验证的待完成状态保持不变。

本轮校验器与 XOps 从同一工作树构建，校验器 SHA-256：
`ed05f7d8ba91cf740ca7c254a86d807ec47554762cf9d3a7210f237bc381c8f7`。
更新后的网络隔离演练报告 original_reference_verified=true、
original_value_verified=true、archive_unchanged=true；正例和两个故障反例均通过。
全仓 build/test/lint 及校验器三轮 race 通过。该哈希同样不是已发布版本标识。
