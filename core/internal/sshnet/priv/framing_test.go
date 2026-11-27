package priv

import (
	"bytes"
	"context"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/ports"
)

// TestSecondaryReadyFlusher_SimultaneousReadyAndCancelFlushesPrefix 确定性验证：
// 当主控流已触发 markReady() 且 ctx 同时取消时，即使 select 选中 ctx.Done() 分支，
// runSecondaryReadyFlusher 也必须完整刷出就绪前已暂存字节且后续写入严格保持 FIFO（零首包丢失）。
func TestSecondaryReadyFlusher_SimultaneousReadyAndCancelFlushesPrefix(t *testing.T) {
	defer goleak.VerifyNone(t)
	bg := context.Background()
	for i := range 200 {
		state := newSharedHandshakeState(ports.PrivilegeMethodSudo, handshakeTokens{
			prompt: "[xops-priv-prompt-test]",
			ready:  "[xops-priv-ready-test]",
		}, 0)
		var dst bytes.Buffer
		sec := newStreamScanner(state, &dst, false)
		if err := sec.feed(bg, []byte("chunk-1\n")); err != nil {
			t.Fatalf("iter %d: feed(chunk-1): %v", i, err)
		}
		if dst.Len() != 0 {
			t.Fatalf("iter %d: 就绪前不应写入 dst，实际=%q", i, dst.String())
		}
		ctx, cancel := context.WithCancel(bg)
		state.markReady()
		cancel()

		runSecondaryReadyFlusher(ctx, state, sec)
		if sec.preDiscarded {
			t.Fatalf("iter %d: 已就绪状态下严禁将暂存前缀标记为丢弃", i)
		}
		if dst.String() != "chunk-1\n" {
			t.Fatalf("iter %d: readyCh 与 ctx.Done 同时就绪时必须刷出 chunk-1，实际=%q", i, dst.String())
		}
		if err := sec.feed(bg, []byte("chunk-2\n")); err != nil {
			t.Fatalf("iter %d: feed(chunk-2): %v", i, err)
		}
		if dst.String() != "chunk-1\nchunk-2\n" {
			t.Fatalf("iter %d: 后续字节必须严格 FIFO 衔接，实际=%q", i, dst.String())
		}
	}
}

// TestSecondaryReadyFlusher_PostDiscardNeverProducesFIFOGap 确定性验证：
// 若 ctx.Done() 在就绪前已触发 discardPreReadyIfPending() 丢弃 chunk-1，即使此后主控流处理在途
// readyTok 将 readyFlag 置为 true，次流后续收到的 chunk-2/chunk-3 也绝不可写入 dst（杜绝中段 FIFO 断层），
// 而应全部转入诊断缓冲。
func TestSecondaryReadyFlusher_PostDiscardNeverProducesFIFOGap(t *testing.T) {
	defer goleak.VerifyNone(t)
	bg := context.Background()
	state := newSharedHandshakeState(ports.PrivilegeMethodSudo, handshakeTokens{
		prompt: "[xops-priv-prompt-test]",
		ready:  "[xops-priv-ready-test]",
	}, 0)
	var dst bytes.Buffer
	sec := newStreamScanner(state, &dst, false)
	if err := sec.feed(bg, []byte("chunk-1\n")); err != nil {
		t.Fatalf("feed(chunk-1): %v", err)
	}
	ctx, cancel := context.WithCancel(bg)
	cancel()

	runSecondaryReadyFlusher(ctx, state, sec)
	if !sec.preDiscarded || dst.Len() != 0 {
		t.Fatalf("未就绪取消必须丢弃 chunk-1 且不写 dst: preDiscarded=%v dst=%q", sec.preDiscarded, dst.String())
	}

	// 模拟在途 readyTok 随后抵达使 readyFlag 变真，随后次流继续收到后续分片与 EOF。
	state.markReady()
	if err := sec.feed(bg, []byte("chunk-2\n")); err != nil {
		t.Fatalf("feed(chunk-2): %v", err)
	}
	if err := sec.feed(bg, []byte("chunk-3\n")); err != nil {
		t.Fatalf("feed(chunk-3): %v", err)
	}
	if err := sec.flushTailOnEOF(bg); err != nil {
		t.Fatalf("flushTailOnEOF: %v", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("chunk-1 已丢弃后严禁向 dst 写入后续分片产生 FIFO 断层，实际 dst=%q", dst.String())
	}
	if got := state.diagText(); got != "chunk-1\nchunk-2\nchunk-3\n" {
		t.Fatalf("已丢弃路径全部字节应有序记入诊断缓冲，实际=%q", got)
	}
}
