package ssh

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
)

// OutputMode 定义远程命令输出的收集策略。
// 注意：零值 OutputModeString 保持全量内存收集，这是为了向后兼容原有行为。
// 对于可能产生巨大输出的命令，调用方应显式指定其他模式以避免 OOM。
type OutputMode int

const (
	OutputModeString     OutputMode = iota // 默认，全量收集到内存（向后兼容）
	OutputModeRingBuffer                   // 环形缓冲，仅保留最后 N 字节
	OutputModeStream                       // 流式即时输出，不在内存中累积
	OutputModeFile                         // 直接写入文件，绕过内存
)

// outputWriter 是一个并发安全的 io.Writer，根据 OutputMode 选择不同的数据处理策略。
// 它替代了原先的 synchronizedWriter，解决了大输出场景下的 OOM 问题。
type outputWriter struct {
	mu           sync.Mutex
	mode         OutputMode
	buf          *bytes.Buffer
	ringBuf      []byte
	ringPos      int  // 环形缓冲区的写入位置
	ringLen      int  // 环形缓冲区中有效数据的长度
	ringMaxBytes int  // 环形缓冲区的最大容量
	truncated    bool // 标记是否发生了数据截断

	streamWriter io.Writer // 流式模式的目标 Writer
	streamPrefix []byte    // 流式模式的每行前缀
	isNL         bool      // 流式模式：上次写入是否以换行结尾

	outFile *os.File // 文件模式的目标文件
}

func newOutputWriter(config *RunConfig) *outputWriter {
	w := &outputWriter{
		mode:         config.OutMode,
		ringMaxBytes: config.RingMaxBytes,
		streamWriter: config.StreamWriter,
		streamPrefix: []byte(config.StreamPrefix),
		outFile:      config.OutFile,
		isNL:         true,
	}
	switch {
	case w.mode == OutputModeString || (w.mode == OutputModeRingBuffer && w.ringMaxBytes <= 0):
		// ringMaxBytes 无效时降级为全量收集
		w.mode = OutputModeString
		w.buf = new(bytes.Buffer)
	case w.mode == OutputModeRingBuffer:
		w.ringBuf = make([]byte, w.ringMaxBytes)
	}
	return w
}

func (w *outputWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n = len(p)

	switch w.mode {
	case OutputModeString:
		_, _ = w.buf.Write(p)
	case OutputModeRingBuffer:
		w.writeRing(p)
	case OutputModeStream:
		if w.streamWriter != nil {
			if len(w.streamPrefix) > 0 {
				w.writePrefixStream(p)
			} else {
				_, _ = w.streamWriter.Write(p)
			}
		}
	case OutputModeFile:
		if w.outFile != nil {
			_, _ = w.outFile.Write(p)
		}
	}
	return n, nil
}

// writeRing 将数据写入环形缓冲区。当数据量超过容量时，自动丢弃最旧的数据。
// 必须在持有 mu 锁的情况下调用。
func (w *outputWriter) writeRing(p []byte) {
	if len(p) == 0 {
		return
	}

	// 如果写入的数据本身就超过整个缓冲区容量，只保留最后 ringMaxBytes 字节
	if len(p) > w.ringMaxBytes {
		w.truncated = true
		copy(w.ringBuf, p[len(p)-w.ringMaxBytes:])
		w.ringPos = 0
		w.ringLen = w.ringMaxBytes
		return
	}

	// 标记截断：新数据写入会导致旧数据被覆盖
	if w.ringLen+len(p) > w.ringMaxBytes {
		w.truncated = true
	}

	// 写入数据到环形缓冲区
	for len(p) > 0 {
		space := w.ringMaxBytes - w.ringPos
		n := copy(w.ringBuf[w.ringPos:], p[:min(len(p), space)])
		w.ringPos = (w.ringPos + n) % w.ringMaxBytes
		if w.ringLen < w.ringMaxBytes {
			w.ringLen = min(w.ringLen+n, w.ringMaxBytes)
		}
		p = p[n:]
	}
}

// writePrefixStream 在流式输出中为每一行添加主机前缀。
// 必须在持有 mu 锁的情况下调用。
func (w *outputWriter) writePrefixStream(p []byte) {
	for len(p) > 0 {
		if w.isNL {
			_, _ = w.streamWriter.Write(w.streamPrefix)
			w.isNL = false
		}
		idx := bytes.IndexByte(p, '\n')
		if idx == -1 {
			_, _ = w.streamWriter.Write(p)
			break
		}
		_, _ = w.streamWriter.Write(p[:idx+1])
		w.isNL = true
		p = p[idx+1:]
	}
}

// String 返回收集到的输出内容。
// 对于 Stream 和 File 模式，返回空字符串（数据已直接发送到目标）。
func (w *outputWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch w.mode {
	case OutputModeString:
		return w.buf.String()
	case OutputModeRingBuffer:
		return w.ringString()
	default:
		return ""
	}
}

// ringString 从环形缓冲区提取有序内容。
// 必须在持有 mu 锁的情况下调用。
func (w *outputWriter) ringString() string {
	if w.ringLen == 0 {
		return ""
	}

	var result []byte
	if w.truncated {
		result = append(result, []byte(fmt.Sprintf("... [Output truncated, exceeded %d bytes]\n", w.ringMaxBytes))...)
	}

	if w.ringLen < w.ringMaxBytes {
		// 缓冲区未满，数据从 0 开始连续存放
		result = append(result, w.ringBuf[:w.ringLen]...)
	} else {
		// 缓冲区已满且发生过回绕，ringPos 指向最旧数据
		result = append(result, w.ringBuf[w.ringPos:]...)
		result = append(result, w.ringBuf[:w.ringPos]...)
	}
	return string(result)
}

// LockedWriter 是一个并发安全的 io.Writer 包装器。
// 用于多个 goroutine 向同一目标（如 os.Stdout）写入时，保证写操作的原子性。
type LockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

// NewLockedWriter 创建一个并发安全的 Writer 包装器。
func NewLockedWriter(mu *sync.Mutex, w io.Writer) *LockedWriter {
	return &LockedWriter{mu: mu, w: w}
}

func (lw *LockedWriter) Write(p []byte) (n int, err error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}
