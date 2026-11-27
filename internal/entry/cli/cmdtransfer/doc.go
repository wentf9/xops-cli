// Package cmdtransfer 实现 XOps v2 的 SCP 并行分片传输与 SFTP 交互/单步远端文件命令族
// （`scp` / `sftp`）。
//
// 核心架构与安全不变量：
//   - 严守双模态本地文件系统隔离：CLI 仅传递 pathalg 强类型路径给 core/engine，绝不调用裸 os.Open/os.Getwd；
//   - 远端路径 100% 走 pathalg.ParseRemotePath，零 path/filepath 调用（满足 xopsvet/osboundary）；
//   - 交互式 SFTP Shell 仅通过 AppConfig.RunSFTPShell 回调注入，未注入时严格失败关闭；
//   - 全包 0 init()、0 可变包级 var、0 裸 go、0 os.Exit、0 //nolint:。
package cmdtransfer

import (
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func requireTransferClient(runner clikit.SessionRunner) (clikit.TransferClient, error) {
	c, ok := runner.(clikit.TransferClient)
	if !ok {
		return nil, i18n.EF(clikit.ErrUnsupportedRunner, i18n.KeyCLICapabilityRequired, i18n.Str("capability", "TransferClient"))
	}
	return c, nil
}
