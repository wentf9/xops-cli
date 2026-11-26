// Package winpipe 为 core/osfs 提供私有 Windows 命名管道全双工重叠 I/O 连接封装（ADR-007 / P4-T4）。
//
// 本包仅对 core/osfs 内部可见，用于在 Windows 平台替代 os.NewFile 封装 FILE_FLAG_OVERLAPPED
// 命名管道句柄，彻底消除 Go internal/poll.(*FD).addOffset 在并发全双工 Read/Write 下的竞态。
package winpipe
