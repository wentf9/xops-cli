package sftp

const (
	DefaultConcurrentFiles = 5
	DefaultThreadsPerFile  = 64
	DefaultChunkSize       = 32 * 1024
	DefaultResumeMinSize   = 1024 * 1024
	DefaultTempSuffix      = ".xops-tmp"
)

// TransferConfig 定义传输配置
type TransferConfig struct {
	ConcurrentFiles int   // 同时传输的文件数
	ThreadsPerFile  int   // 单个文件的并发分块数
	ChunkSize       int64 // 分块大小
	EnableResume    bool
	ResumeMinSize   int64
	TempSuffix      string
	Force           bool
}

func DefaultConfig() TransferConfig {
	return TransferConfig{
		ConcurrentFiles: DefaultConcurrentFiles,
		ThreadsPerFile:  DefaultThreadsPerFile,
		ChunkSize:       DefaultChunkSize,
		EnableResume:    true,
		ResumeMinSize:   DefaultResumeMinSize,
		TempSuffix:      DefaultTempSuffix,
		Force:           false,
	}
}

// ProgressCallback 进度回调，n 为本次增量传输的字节数
// 此函数必须是并发安全的
type ProgressCallback func(n int64)

// FileTransferProgress contains progress details for an individual file within a transfer.
type FileTransferProgress struct {
	Path        string // File path or relative path
	Size        int64  // Total file size in bytes
	Transferred int64  // Bytes transferred so far for this file
	Increment   int64  // Bytes transferred in this step
}

// FileProgressCallback is invoked as chunks of an individual file are transferred.
// This callback must be thread-safe as multiple files may be transferred concurrently.
type FileProgressCallback func(p FileTransferProgress)
