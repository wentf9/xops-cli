package sshexec

import (
	"sync"
	"sync/atomic"
	"testing"
)

type nonReentrantWriteCloser struct {
	t            *testing.T
	active       atomic.Int32
	writeEntered chan struct{}
	releaseWrite chan struct{}
	mu           sync.Mutex
	writes       [][]byte
}

func (w *nonReentrantWriteCloser) Write(p []byte) (int, error) {
	if w.active.Add(1) != 1 {
		w.t.Errorf("concurrent stdin.Write detected")
	}
	defer w.active.Add(-1)
	if len(p) > 1 {
		close(w.writeEntered)
		<-w.releaseWrite
	}
	w.mu.Lock()
	w.writes = append(w.writes, append([]byte(nil), p...))
	w.mu.Unlock()
	return len(p), nil
}

func (w *nonReentrantWriteCloser) Close() error { return nil }

func TestPTYSessionSerializesConcurrentStdinWrites(t *testing.T) {
	stdin := &nonReentrantWriteCloser{
		t:            t,
		writeEntered: make(chan struct{}),
		releaseWrite: make(chan struct{}),
	}
	pty := &ptySession{stdin: stdin}

	writeDone := make(chan error, 1)
	go func() {
		_, err := pty.Write([]byte("echo hi\n"))
		writeDone <- err
	}()
	<-stdin.writeEntered

	sigDone := make(chan error, 1)
	go func() {
		sigDone <- pty.Signal("EOF")
	}()

	close(stdin.releaseWrite)
	if err := <-writeDone; err != nil {
		t.Fatalf("pty.Write failed: %v", err)
	}
	if err := <-sigDone; err != nil {
		t.Fatalf("pty.Signal(EOF) failed: %v", err)
	}
	stdin.mu.Lock()
	defer stdin.mu.Unlock()
	if len(stdin.writes) != 2 || string(stdin.writes[0]) != "echo hi\n" || len(stdin.writes[1]) != 1 || stdin.writes[1][0] != 0x04 {
		t.Fatalf("unexpected stdin write sequence: %q", stdin.writes)
	}
}
