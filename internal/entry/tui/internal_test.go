package tui

import (
	"context"
	"slices"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestInternal_LineBufferedLogWriterAndResetActiveStreams(t *testing.T) {
	var emitted []string
	w := &lineBufferedLogWriter{
		ctx:    context.Background(),
		target: "app-01",
		emit: func(msg tea.Msg) {
			if cm, ok := msg.(LogChunkMsg); ok {
				emitted = append(emitted, cm.Text)
			}
		},
	}
	if _, err := w.Write([]byte("part1-")); err != nil {
		t.Fatalf("Write part1: %v", err)
	}
	if len(emitted) != 0 {
		t.Fatalf("半行分片不应提前拆行发送: got=%v", emitted)
	}
	if _, err := w.Write([]byte("part2\r\nline2\ntrailing")); err != nil {
		t.Fatalf("Write part2: %v", err)
	}
	if !slices.Equal(emitted, []string{"part1-part2", "line2"}) {
		t.Fatalf("换行拼接异常: got=%v", emitted)
	}
	w.flush()
	if !slices.Equal(emitted, []string{"part1-part2", "line2", "trailing"}) {
		t.Fatalf("flush 尾行异常: got=%v", emitted)
	}

	m := NewModel(ModelOptions{})
	m.applyStreamState(StreamStateMsg{Kind: "metrics", Target: "app-01", Active: true, Seq: 3})
	m.applyStreamState(StreamStateMsg{Kind: "logs", Target: "app-01", Active: true, Seq: 2})
	if !m.MetricsActive() || !m.LogsActive() {
		t.Fatalf("流状态应为活跃")
	}
	m.resetActiveStreams()
	if m.MetricsActive() || m.LogsActive() || m.metricsSeq != 0 || m.logsSeq != 0 {
		t.Fatalf("resetActiveStreams 未清零状态: metrics=%v/%d logs=%v/%d", m.MetricsActive(), m.metricsSeq, m.LogsActive(), m.logsSeq)
	}
}
