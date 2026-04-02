package ssh

import (
	"io"
	"os"
)

// fallbackCopyStdinTo 是不支持 poll 时的兜底实现，使用 io.Copy。
// cancel 调用后 goroutine 不能立即退出，会等到下一次 stdin 有输入才结束，
// 存在极低概率首个字符被吞的问题。
func fallbackCopyStdinTo(dst io.Writer) (cancel func(), done <-chan struct{}) {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		_, _ = io.Copy(dst, os.Stdin)
	}()
	return func() {}, ch
}
