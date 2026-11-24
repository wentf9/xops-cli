// Package pathalg 提供 XOps v2 纯函数领域核使用的路径、软链接、Unicode 折叠碰撞与受保护路径代数。
//
// 本包恪守 100% 纯数学与零副作用铁律（严禁导入 os、path/filepath、net、sync、sync/atomic、reflect 或 context；
// 仅依赖纯标准库与白名单数学包 golang.org/x/text/unicode/norm），提供以下职责正交、全字段私有且零值失败关闭的抽象：
//   - RemoteName / RemotePath：POSIX 远端目录项名与规范化远端路径代数（零 path/filepath 混用）；
//   - ValidateLocalComponent：跨 Linux/macOS/Windows 统一执行的单本地路径分量安全校验；
//   - LocalRootedDest：面向 ScopedRootFS（*os.Root）的严格沙箱相对目标路径；
//   - LocalDir：面向 ScopedRootFS.WithRoot 的本地目录根标识（纯字符串数学支持 POSIX 与 Windows 盘符路径）；
//   - LocalSourcePath：面向 OperatorReadFS.WithOperatorRead 的操作员显式本地只读源路径；
//   - SymlinkPolicy 与策略 (b) 链式纯数学解析器：限制下载软链接严格留在根目录内且无折叠碰撞；
//   - Unicode NFC/NFD 规范化与跨 OS（macOS APFS/HFS+、Windows NTFS）大小写/规范化折叠碰撞检测；
//   - ProtectedPathMatcher：OS 无关 UTF-8 受保护路径匹配器，支持 *、**、?、[...]、精确/前缀/祖先检查、
//     NFC 规范化与 Win32 扩展设备/回环管理共享/ADS 规范化，并返回确定性命中规则集合供 ApprovalFSM 识别
//     Protected-A -> Protected-B 重定向升级。
//
// 所有持久化或跨协议序列化的值对象均以值接收者实现 encoding.TextAppender 与 encoding.TextMarshaler，
// 并以指针接收者实现 encoding.TextUnmarshaler，原生支持 Go 1.27 encoding/json/v2 与 YAML 确定性往返。
package pathalg

import "errors"

const (
	// MaxComponentBytes 是单个路径分量允许的最大 UTF-8 字节长度（对齐 POSIX NAME_MAX 与 NTFS/APFS 255 单元上限）。
	MaxComponentBytes = 255
	// MaxRemotePathBytes 是远端 POSIX 路径与沙箱相对路径允许的最大 UTF-8 字节长度（对齐 POSIX PATH_MAX）。
	MaxRemotePathBytes = 4096
	// MaxLocalPathBytes 是本地目录或操作员本地源路径允许的最大 UTF-8 字节长度（兼容 Windows 长路径上限）。
	MaxLocalPathBytes = 32768
	// MaxSymlinkHops 是链式相对软链接纯数学解析允许的最大展开跳数（对齐 POSIX SYMLOOP_MAX）。
	MaxSymlinkHops = 40
	// MaxSymlinkSteps 是链式相对软链接解析允许的最大总步数，阻断指数级链式放大攻击。
	MaxSymlinkSteps = 4096
)

// ErrInvalidComponent 表示单个本地文件名/目录分量违反跨平台安全规则。
var ErrInvalidComponent = errors.New("pathalg: 无效的本地路径分量")

// ErrInvalidRemoteName 表示单个远端 POSIX 目录项名称为空、含 '/'、为 '.'/'..' 或含控制/Bidi 字符。
var ErrInvalidRemoteName = errors.New("pathalg: 无效的远端名称")

// ErrInvalidRemotePath 表示远端 POSIX 路径为空、超长、含非法 UTF-8 或含控制/Bidi 字符。
var ErrInvalidRemotePath = errors.New("pathalg: 无效的远端路径")

// ErrInvalidLocalDest 表示面向 ScopedRootFS 的沙箱相对目标路径非法或存在逃逸风险。
var ErrInvalidLocalDest = errors.New("pathalg: 无效的本地沙箱目标路径")

// ErrInvalidLocalDir 表示面向 ScopedRootFS.WithRoot 的本地根目录路径非法或存在穿越风险。
var ErrInvalidLocalDir = errors.New("pathalg: 无效的本地根目录路径")

// ErrInvalidLocalSource 表示面向 OperatorReadFS.WithOperatorRead 的本地源路径非法。
var ErrInvalidLocalSource = errors.New("pathalg: 无效的本地只读源路径")

// ErrInvalidSymlinkPolicy 表示软链接策略未识别、格式无效或不允许当前操作。
var ErrInvalidSymlinkPolicy = errors.New("pathalg: 无效的软链接策略")

// ErrUnsafeSymlink 表示符号链接目标或链式解析违反安全策略（如绝对路径、逃逸根目录、环路或碰撞）。
var ErrUnsafeSymlink = errors.New("pathalg: 不安全的符号链接")

// ErrNameCollision 表示两个不同名称或路径经 Unicode NFC/NFD 与跨 OS 大小写折叠后发生碰撞。
var ErrNameCollision = errors.New("pathalg: 路径名称存在 Unicode 或大小写折叠碰撞")

// ErrInvalidUTF8 表示输入字符串包含非法 UTF-8 字节序列。
var ErrInvalidUTF8 = errors.New("pathalg: 无效的 UTF-8 编码")

// ErrInvalidProtectedRule 表示受保护路径规则或匹配器未初始化、语法无效或包含非法字符。
var ErrInvalidProtectedRule = errors.New("pathalg: 无效的受保护路径规则")

// ErrInvalidGlob 表示 UTF-8 通配符模式存在未闭合字符类或非法字符范围。
var ErrInvalidGlob = errors.New("pathalg: 无效的通配符模式")

// ErrNilReceiver 表示在 nil 指针接收者上调用反序列化方法。
var ErrNilReceiver = errors.New("pathalg: 反序列化目标接收者不能为 nil")
