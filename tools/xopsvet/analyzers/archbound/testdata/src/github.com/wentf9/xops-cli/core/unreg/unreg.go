package unreg // want "未登记的 core/ 包路径"

// ZeroImportUnregistered 验证零 import 的未登记 core/* 包同样被 fail-closed 拦截（AB-6）。
func ZeroImportUnregistered() int { return 42 }
