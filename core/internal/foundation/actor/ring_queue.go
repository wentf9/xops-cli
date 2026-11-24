package actor

// ringQueue 是一个非线程安全的无界泛型环形切片队列，
// 专供 DualActor 在极薄互斥锁保护下承载零阻塞控制通道消息，避免定长通道满溢造成反压死锁。
type ringQueue[T any] struct {
	buf   []T
	head  int
	count int
}

const (
	ringInitCap   = 8
	ringShrinkMin = 64
)

func (q *ringQueue[T]) push(v T) {
	if q.count == len(q.buf) {
		q.grow()
	}
	tail := (q.head + q.count) % len(q.buf)
	q.buf[tail] = v
	q.count++
}

func (q *ringQueue[T]) pop() (T, bool) {
	var zero T
	if q.count == 0 {
		return zero, false
	}
	v := q.buf[q.head]
	// 及时清零槽位，避免已出队元素中的指针长期滞留内存无法被 GC 回收。
	q.buf[q.head] = zero
	q.head = (q.head + 1) % len(q.buf)
	q.count--
	if len(q.buf) > ringShrinkMin && q.count <= len(q.buf)/4 {
		q.resize(len(q.buf) / 2)
	}
	return v, true
}

// popAll 将队列中当前全部元素按 FIFO 顺序批量取出并清空队列。
// 返回值复用调用方传入的 dst 底层切片（若容量足够）以降低高频批处理时的分配开销。
func (q *ringQueue[T]) popAll(dst []T) []T {
	if q.count == 0 {
		return dst[:0]
	}
	out := dst[:0]
	if cap(out) < q.count {
		out = make([]T, 0, q.count)
	}
	out = q.appendOrdered(out)
	clear(q.buf)
	q.head = 0
	q.count = 0
	if len(q.buf) > ringShrinkMin {
		q.buf = make([]T, ringShrinkMin)
	}
	return out
}

func (q *ringQueue[T]) appendOrdered(dst []T) []T {
	firstLen := min(q.count, len(q.buf)-q.head)
	dst = append(dst, q.buf[q.head:q.head+firstLen]...)
	if q.count > firstLen {
		dst = append(dst, q.buf[:q.count-firstLen]...)
	}
	return dst
}

func (q *ringQueue[T]) len() int {
	return q.count
}

// reset 以严格零堆分配方式清零所有槽位并释放底层缓冲区，
// 专供 DualActor panic 恢复路径清理滞留指针，避免异常或 OOM 场景下的二次切片分配。
func (q *ringQueue[T]) reset() {
	clear(q.buf)
	q.buf = nil
	q.head = 0
	q.count = 0
}

func (q *ringQueue[T]) grow() {
	newCap := max(ringInitCap, len(q.buf)*2)
	q.resize(newCap)
}

func (q *ringQueue[T]) resize(newCap int) {
	next := make([]T, newCap)
	if q.count > 0 {
		firstLen := min(q.count, len(q.buf)-q.head)
		copy(next, q.buf[q.head:q.head+firstLen])
		if q.count > firstLen {
			copy(next[firstLen:], q.buf[:q.count-firstLen])
		}
		clear(q.buf)
	}
	q.buf = next
	q.head = 0
}
