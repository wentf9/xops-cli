// Package secrettaint 实现 XOps v2 机密隔离与明文污点追踪静态分析器。
//
// 本分析器在编译期强制执行三项机密安全边界：
//   - 规则 1：禁止 secret.SecretBox（含指针、切片、容器、别名与泛型包装）进入
//     Event / Audit / Plan / Error / error 实现类型 / //xops:dto / 序列化标签结构体字段，
//     并禁止其作为实参传入日志、错误格式化、序列化及事件/审计汇点（含 any 擦除变量）；
//   - 规则 2：对 SecretBox.Use 与 //xops:secretuse 回调形参 plain 及其直接衍生值
//     （切片、bytes.Clone、slices.Clone、string/[]byte 强转、copy、append、fmt.Sprint*、
//     编码与缓冲写入等）执行局部污点流追踪，拦截流入汇点或逃逸出局部借用作用域，
//     同时对 len/cap/clear、字节谓词及合法加密/认证消费方零误报；
//   - 规则 3：将 SecretBox.Use 与 //xops:secretuse 的调用与引用严格封锁于白名单包
//     （core/domain/secret、internal/host/vault 与 core/internal/sshnet/dial，不含外置 _test）。
package secrettaint

import (
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// secretUseFact 用于跨包传递 //xops:secretuse 明文机密回调函数契约。
type secretUseFact struct{}

// AFact 标记 secretUseFact 为 go/analysis 跨包分析事实。
func (*secretUseFact) AFact() {}

// String 返回事实的简短标识（用于 analysistest 核验）。
func (*secretUseFact) String() string { return "secretuse" }

// NewAnalyzer 创建并返回 secrettaint 机密边界与明文污点静态分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:      "secrettaint",
		Doc:       "检查 SecretBox 禁用类型边界、Use/secretuse 局部明文污点流及明文消费包白名单",
		FactTypes: []analysis.Fact{(*secretUseFact)(nil)},
		Run:       run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPackage(pass.Pkg.Path())
	facts := collectAndExportSecretFacts(pass)
	checkSecretBoxTypeAndSinkBan(pass)
	checkSecretUseWhitelist(pass, pkgInfo, facts)
	checkSecretTaintFlows(pass, facts)
	return nil, nil
}
