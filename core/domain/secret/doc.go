// Package secret 提供 XOps v2 纯函数领域核的机密借用容器（SecretBox）、凭据引用标识（Ref）
// 及 Go 1.27 runtime/secret 实验性硬件/运行时擦除作用域钩子。
//
// 本包恪守以下安全与架构不变量（ADR-011 / ADR-014 / ADR-016）：
//   - 100% 零 sync 与零 sync/atomic：SecretBox 为单协程作用域借用容器，由调用方在闭包边界内独占访问；
//   - 零值失败关闭：SecretBox 同时具备正向有效门控 valid 与销毁标记 wiped，Ref 零值恒无效；
//   - 故意零序列化接口：SecretBox 不实现任何 Text/JSON/Binary 编解码接口，使 encoding/json/v2 原生返回 SemanticError；
//   - 入站与明文消费权限分离：WithBytes 仅标注 //xops:syncclosure 与 //xops:borrowed（严禁 //xops:secretuse），
//     SecretBox.Use 仅允许 5 个白名单包调用，常量时间比对 Equal 免除测试夹具的明文消费需求；
//   - 独占标准库 "runtime/secret" 导入权限（通过 goexperiment.runtimesecret 构建标签隔离）。
package secret

import "errors"

// ErrSecretInvalid 表示 SecretBox 为 nil 或未通过 WithBytes 初始化的无效零值。
var ErrSecretInvalid = errors.New("secret: SecretBox 无效或未初始化")

// ErrSecretWiped 表示 SecretBox 已被 Wipe 清零销毁，禁止再次访问明文。
var ErrSecretWiped = errors.New("secret: SecretBox 已销毁清零")

// ErrNilCallback 表示传入 WithBytes 或 SecretBox.Use 的作用域回调函数为 nil。
var ErrNilCallback = errors.New("secret: 作用域回调函数不能为 nil")

// ErrInvalidRef 表示凭据引用 Ref 的 store 或 item 标识为空、超长或包含非法字符。
var ErrInvalidRef = errors.New("secret: 无效的凭据引用 Ref")

// ErrNilReceiver 表示在 nil 指针接收者上调用反序列化方法。
var ErrNilReceiver = errors.New("secret: 反序列化目标接收者不能为 nil")
