// Package sftpshell 实现 XOps v2 极薄交互式 SFTP Shell 入站入口层（ADR-001 / ADR-016 / Plan P5-T2）。
//
// 核心架构边界与安全不变量：
//   - 严守依赖单向性：仅依赖 core/{domain/...,events,conc,engine} 与 Go 标准库，
//     物理零 internal/host/**、零 core/osfs、零 core/ports、零 path/filepath 导入；
//   - 远端/本机路径代数隔离：远端路径全程使用 pathalg.RemotePath 与 POSIX path 包，
//     本机目录便利操作（lpwd/lcd/lls）基于 pathalg.LocalDir 与可选注入的 LocalFS 回调实现，0 osboundary 违例；
//   - 单命令取消与恢复：通过 core/conc.Nursery（RunScoped/RunWait）监督传输进度流与单命令中断通道，
//     取消在途上传/下载后完整排空协程并安全恢复至交互提示符，绝不撕毁整个 SFTP 会话（外层会话取消或门控 Halted 除外）；
//   - 原子写与远端元数据操作：全面对接 core/engine 的 SCPUpload/SCPDownload/WriteRemoteFile/RenameRemoteFile
//     （SFTP v3 posix-rename@openssh.com）、MkdirRemoteAll、RemoveRemoteFile/RemoveRemoteDir、ChmodRemote/ChtimesRemote/StatRemoteFile。
package sftpshell
