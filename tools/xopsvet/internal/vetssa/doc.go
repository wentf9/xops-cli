// Package vetssa 为 xopsvet 的 6 个数据流与防擦除分析器提供共享 SSA 引擎（基于 passes/buildssa）。
//
// 本包物理封装 golang.org/x/tools/go/ssa 底层细节，并明文强制执行 6 项实证编译器不变量：
//  1. 泛型实例化包装器解包（兼容 Pkg == nil，统一取 Origin() 与 Object().Origin()）及 *ssa.MultiConvert 覆盖；
//  2. CallSiteResolver 统一归一化包函数、普通方法、$thunk 方法表达式、$bound 方法值与接口 IsInvoke() 槽位；
//  3. range-over-func yield（Synthetic == "range-over-func yield"）安全建模，严禁强转 Syntax() 为 *ast.FuncLit；
//  4. 局部新鲜切片识别（含常量容量 Slice(Alloc{"makeslice"})）与写后子切片反向溯源至根分配；
//  5. 全量 ssa.CallInstruction（含 Defer/Go）、多层 FreeVar/Loop Phi 溯源、及 pkg.init 按指令 ResolvePos 判测试；
//  6. CheckNoErasure 覆盖 MakeInterface/ChangeInterface/ChangeType/TypeAssert 与全量 TypesInfo.Instances（含 any 约束），
//     使用不入接口方法与签名的 vetutil.ContainsValueType，并支持 AllowMakeInterface 精确豁免钩子。
package vetssa
