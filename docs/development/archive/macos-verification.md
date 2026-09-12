# macOS 跨平台兼容性验证指南

本文档为无 macOS 物理机环境下的开发者提供阶段四（凭据持久化系统后端）的 macOS 兼容性验收方案，覆盖自动化 CI 验证、真实 Keychain 关键场景断言、本地 KVM 容器虚拟化以及交叉编译检查。

---

## 1. 阶段四 macOS 关键验收场景与实现

根据 [`docs/development/archive/plans/credential-persistence-implementation.md`](plans/credential-persistence-implementation.md) 与 [`docs/development/archive/design/credential-persistence.md`](design/credential-persistence.md) 第 16 节的架构设计，macOS 平台凭据系统基于原生 Security Framework C API，并严格通过以下真实场景验收：

| 验收场景 | 关键风险与行为要求 | 自动化覆盖与测试断言 |
| :--- | :--- | :--- |
| **独立测试钥匙串与搜索列表恢复 (优先注册保底)** | 避免污染或破坏宿主会话登录钥匙串；在任何配置变更前优先读取原值并注册还原清理（`t.Cleanup` / `trap`），测试钥匙串创建成功后立即注册删除清理；退出时安全销毁并**完整恢复包含空格路径的原始 Keychain 搜索列表** | `verify_native_platform.sh` 与 `setupIsolatedDarwinKeychain` 在状态变更前尽早注册还原逻辑，精准解析引号、动态创建专属测试钥匙串并在 `trap`/`Cleanup` 严格还原搜索列表与默认库 |
| **禁用用户界面交互 (Fail-Closed 杜绝挂起)** | 在允许弹窗的 macOS 桌面/会话中，受限条目或钥匙串可能触发 GUI 授权弹窗并无限期等待用户点击，导致调用挂起超时 | 受控 Helper 子进程初始化时强制调用 Apple `SecKeychainSetUserInteractionAllowed(0)`，严格断言返回值并在出错时立即失败退出；单测覆盖设置失败拦截 |
| **多 Keychain 目标库锁定精准分类 (正反向隔离与 Helper 授权)** | 搜索列表中包含多个 Keychain 时，必须先在已解锁库中定位目标条目所属的具体库；若目标库已解锁但因 ACL/签名被拒绝访问，绝不可因搜索列表中存在其他无关锁定库而误判为 `locked`，必须严格返回 `denied`；只有当条目未在已解锁库中找到且存在锁定库时才映射为 `locked`；原生多库测试必须由 helper 自身创建或显式授权，避免默认创建者 ACL 导致初次读取受阻 | `darwinLocateItemInSearchList` 遍历定位具体钥匙串，消除无关库污染；单测与真实集成测试（`TestDarwinNativeSystemStore_MultiKeychainLockClassification`、`TestDarwinNativeSystemStore_MultiKeychainTargetUnlockedACLDeniedWithUnrelatedLocked`、脚本 Step E.1 & E.1.2）覆盖正反向场景，且测试条目均显式授权实际 helper 杜绝未授权 ACL 假失败 |
| **非 not-found 原生错误严格保留分类 (杜绝吞咽误报)** | 遍历钥匙串搜索列表定位条目时，**严格仅将 `errSecItemNotFound (-25300)` 视为未匹配**并继续检索；若遇到 ACL 拒绝（`errSecAuthFailed`）、交互限制（`errSecInteractionNotAllowed`）或系统 I/O 故障（`errSecIO -36`），严禁吞咽忽略并误报为 `not-found`，必须如实记录并在未定位到条目时正确映射为 `denied` 或 `unavailable` | `darwinLocateItemInSearchList` 收集 `firstErr`，`darwinActionGet/Store/Erase` 在未命中时优先判定 `errStatus`；单测 `TestDarwinNativeHelper_FindIOErrorNotReportedAsNotFound` 注入 `errSecIO` 并严格断言返回 `unavailable` 且绝非 `not-found` |
| **搜索列表锁定库 Fail-Closed 写入防护 (防止条目遮蔽 Shadowing)** | 执行 `store` 写入前，严格区分“确认不存在”与“无法检查”；当搜索列表中存在锁定的次级钥匙串时，无法确认该凭据是否已存在于锁定库中。若盲目向默认钥匙串添加新条目，会静默创建同名凭据并遮蔽锁定库中的原凭据。系统在存在锁定库时必须严格失败关闭（Fail-Closed）并返回 `ErrCredentialStoreLocked`（`code: "locked"`） | `darwinActionStore` 在 `foundItem.hasLocked` 为真时立即阻断添加并返回 `code: "locked"`；单测 `TestDarwinNativeHelper_StoreFailsClosedWhenSearchListHasLockedKeychain`、集成测试 `TestDarwinNativeSystemStore_MultiKeychainLockClassification` 与脚本 Step E.1.2.1 严格断言返回 `ErrCredentialStoreLocked` 并确认默认库中未产生遮蔽条目 |
| **二进制保真度 (无额外换行/零文本转码)** | 验证原始二进制、控制字符 `\x00` 与尾随换行 `\n`，杜绝任何 `TrimRight` 截断或十六进制自动转码 | 单元与集成测试均写入 `\n\n\x00\x01\x02\xff` 并逐字节断言完全一致 |
| **覆盖写入 (In-place Update)** | 当写入已存在条目时触发 `errSecDuplicateItem (-25299)`，受控 Helper 必须重试并调用 `SecKeychainItemModifyAttributesAndData`，且读回内容必须断言为新值而非旧值 | 写入初始秘密后覆盖写入新秘密，严格断言读回内容匹配新值且不等于旧值 |
| **钥匙串锁定与状态判定** | 遵循 Apple 官方 `SecBase.h` 定义，当返回 `errSecAuthFailed (-25293)` 或 `errSecInteractionNotAllowed (-25308)` 时，通过目标钥匙串 `SecKeychainGetStatus` 检测状态；若钥匙串已锁定（`status & 1 == 0`），严格映射为 `ErrCredentialStoreLocked`（`code: "locked"`） | `TestDarwinNativeSystemStore_RealKeychainLockUnlock` 实际锁定独立钥匙串并严格断言 `ErrCredentialStoreLocked`；Mock 测试验证状态位精准判定 |
| **钥匙串解锁恢复** | 钥匙串由锁定转为解锁后，读写操作应立即无损恢复 | 通过 `security unlock-keychain` 解锁后立即执行读取并断言成功 |
| **签名变化、ACL 拒绝与只读判定** | 严格遵循官方错误码：`-25292` 为 `errSecReadOnly` 映射为 `read-only`；在钥匙串处于解锁状态时，若发生权限拒绝/签名不匹配返回 `errSecAuthFailed` / `errSecInteractionNotAllowed`，精准映射为 `denied`（`ErrCredentialAccessDenied`） | `TestDarwinNativeSystemStore_RealKeychainACLAccessDenied` 真实写入 `-T /usr/bin/false` 限制条目并断言 `ErrCredentialAccessDenied`；`verify_native_platform.sh` 覆盖 ACL 拒绝验证；单测覆盖只读与签名拒绝映射 |
| **删除效果严格断言** | `erase` / `Delete` 之后，必须再次读取该条目并严格断言返回 `ErrCredentialNotFound`，杜绝删除空操作误判成功 | 执行删除后再次调用 `get`，严格断言退出码非 0 且返回 `not-found` |
| **运行中超时与取消 (In-Flight Timeout/Cancel)** | 针对正在阻塞执行的原生子进程（而非调用前取消），在子进程内部注入真实阻塞信号文件（`XOPS_TEST_SYSTEM_HELPER_BLOCK_SIGNAL`），父进程确认子进程进入阻塞后再触发取消/超时，严格断言 `context.DeadlineExceeded` 与 `context.Canceled` 并回收进程树 | `TestDarwinNativeSystemStore_InFlightTimeoutAndCancel` 启动受控 Helper 实际阻塞，断言取消后进程安全退出且拒绝普通 API 错误混入 |
| **Mock 与原生初始化状态隔离** | Mock 打桩测试严禁污染或破坏原生 API 初始化标志（`sync.Once`），防止因测试执行顺序或 CI `-shuffle=on` 引发空指针崩溃 | `system_darwin.go` 采用 `darwinKeychainAPI` 结构体解耦，Mock 通过 `setDarwinMockAPI` 独立接管，原生加载逻辑与函数指针绝对隔离 |
| **钥匙串还原与资源清理零吞咽** | 测试过程中对默认钥匙串还原、搜索列表重置和测试钥匙串删除的每一步执行结果严格检查，严禁吞咽错误（杜绝 `_ =` 与 `|| true`），防止遗留脏配置 | 单测与校验脚本对 `default-keychain`、`list-keychains`、`delete-keychain` 的退出状态全程校验，若还原失败立即告警并导致退出失败 |

---

## 2. 方案一：GitHub Actions 自动化 CI 与交互式 SSH 调试（推荐）

项目在 [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml) 中配置了 `macos-test` 自动化任务，运行于 GitHub 官方提供的 `macos-latest`（Apple Silicon 环境）上。

### 2.1 自动执行流程
每次推送至 `master` 或提交 PR 时，GitHub Actions 会自动：
1. 检出代码并配置 Go 环境；
2. 编译所有包：`go build ./...`；
3. 运行含数据竞争检测的全量单元测试：`go test -race -shuffle=on -count=1 ./...`（自动执行 `system_darwin_test.go` 中的真实 API 往返、运行中超时/取消、签名访问拒绝及独立钥匙串锁/解锁集成测试）；
4. 执行原生平台验收脚本：[`./scripts/verify_native_platform.sh`](../../../scripts/verify_native_platform.sh)，该脚本动态创建独立测试钥匙串，执行带超时边界的真实凭据写入、更新读回、锁定拒绝、解锁恢复及删除后 not-found 断言。

### 2.2 故障排查与 tmate 交互式 SSH 远程终端
当 CI 测试失败或需要登录 macOS 终端手动单步调试时，可以通过 GitHub Web 界面的 **Run workflow** 手动触发流水线，并勾选：
- `Run with tmate SSH session on failure: true`

当任务失败时，`action-tmate` 步骤会暂停并在 GitHub Actions 运行日志中打印 SSH 连接命令：
```bash
ssh xxxxxxxx@sfo2.tmate.io
```
复制该命令即可直接在本地终端连入该 macOS 虚拟机，使用终端定位 Keychain 或系统 API 调用问题。

---

## 3. 方案二：本地 KVM 容器虚拟化（Docker-OSX）

对于无网络或需离线反复快速验证的场景，仓库在 `deploy/macos-vm/` 下提供了基于 QEMU/KVM 加速的 Docker-OSX 配置，宿主机无需安装完整 Hackintosh，直接通过 Docker 容器化运行真实 macOS 系统。

### 3.1 前置条件与工具链要求
- **系统环境**：Linux 宿主机且 CPU 开启硬件虚拟化支持（`/dev/kvm` 存在并可读写）。
- **软件依赖**：`docker` 与 `docker compose`（或 `docker-compose`）。
- **硬件资源**：空闲内存 $\ge 8\text{ GB}$，可用磁盘空间 $\ge 25\text{ GB}$。
- **客体工具链**：根据项目编码规范，macOS 客体环境需安装 **Go 1.26+**。脚本提供了自动化检查与安装功能（`make macos-vm-setup-go`）。
- **镜像版本说明**：默认使用官方活跃维护的 `sickcodes/docker-osx:latest` 基础镜像（上游已下架旧版 `:auto` 预制镜像）。容器首次启动时会自动拉取 Apple 官方恢复介质并初始化 OpenCore 引导环境；也可通过挂载已有持久化磁盘镜像加速冷启动。

### 3.2 常用 Make 命令

在项目根目录下，提供了便捷的 Makefile 快捷命令：

```bash
# 1. 检查宿主机 KVM、Docker、内存、磁盘空间及专用 SSH 密钥
make macos-vm-check

# 2. 启动本地 macOS 虚拟机容器 (前台保持 stdin/tty 驻留，避免退出循环)
make macos-vm-up

# 3. 查看虚拟机运行状态与健康检查
make macos-vm-status

# 4. 轮询等待虚拟机客体 SSH 服务就绪并自动建立公钥免密授权 (智能区分端口连通与认证就绪)
make macos-vm-wait

# 5. SSH 连接登录虚拟机交互终端 (使用预配置的客体账户)
make macos-vm-ssh

# 6. 在虚拟机客体内检查/自动安装 Go 1.26+ 工具链
make macos-vm-setup-go

# 7. 严格镜像同步当前代码至虚拟机 (~/xops-cli，带 --delete 自动清理已删除文件)
make macos-vm-sync

# 8. 纯净同步并在虚拟机内运行完整原生验证脚本
make macos-vm-test

# 9. 停止并清理虚拟机容器
make macos-vm-down
```

### 3.3 容器驻留、生命周期与认证保障
- **防闪退配置**：[`deploy/macos-vm/docker-compose.yml`](../../../deploy/macos-vm/docker-compose.yml) 显式配置了 `stdin_open: true` 与 `tty: true`，防止后台守护进程在关闭 stdin 时触发容器无限重启。
- **健康检查与智能等待**：配置了 TCP `10022` 端口的健康检查；`manage.sh wait-ready` 先探测 TCP 端口就绪，随后区分服务未启动与密码/公钥认证未就绪，并自动通过 Python PTY 完成首次公钥分发，打通完全无人值守的免密通道。
- **端口连通与客体状态辨析**：宿主机 `50922` 端口是由 QEMU 用户态网络栈（SLiRP）在容器内监听并转发至客体 `22` 端口。初次冷启动使用全新格式化的空白虚拟磁盘（`mac_hdd_ng.img`）时，系统处于 macOS 恢复安装器（BaseSystem）阶段，此时客体操作系统尚未写入磁盘，客体内部尚未运行 SSH 服务，因此连接会被切断（Connection closed by remote host）。若需本地完整离线运行，可通过 VNC（端口 `5999`）进入恢复环境完成首次系统安装，或直接挂载已预装的磁盘镜像。
- **源码严格镜像同步**：[`deploy/macos-vm/manage.sh`](../../../deploy/macos-vm/manage.sh) 同步时强制应用 `rsync --delete`（或 tar 清空覆盖），避免因分支切换或文件重命名产生的新旧源码混合残留。

---

## 4. 方案三：本地快速交叉编译检查

在日常编码与重构过程中，可在本地 Linux 终端执行交叉编译，提前拦截平台专有代码（如 `internal/credentialhelper/system_darwin.go`）的语法、Build Tag 及类型匹配错误：

```bash
# 验证 macOS Intel (amd64) 编译
GOOS=darwin GOARCH=amd64 go build ./...

# 验证 Apple Silicon (arm64) 编译
GOOS=darwin GOARCH=arm64 go build ./...

# 验证 macOS 测试集编译
GOOS=darwin go test -c ./internal/credentialhelper -o /dev/null
```
