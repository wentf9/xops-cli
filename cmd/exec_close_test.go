package cmd

import (
	"errors"
	"sync"
	"testing"
)

type execErrorWriter struct {
	err error
}

func (w execErrorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

type execErrorCloser struct {
	err error
}

type execConnectorCloser struct {
	err error
}

func (c execConnectorCloser) CloseAll() error {
	return c.err
}

func TestPrintTaskResultReturnsOutputError(t *testing.T) {
	wantErr := errors.New("output closed")
	o := NewExecOptions()
	o.stdout = execErrorWriter{err: wantErr}

	err := o.printTaskResult(t.Context(), execHostTask{host: "host-1"}, "output", nil, &sync.Mutex{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("printTaskResult() error = %v, want wrapped output error", err)
	}
}

func (c execErrorCloser) Close() error {
	return c.err
}

func TestJoinExecLogCloseErrorPreservesBothErrors(t *testing.T) {
	operationErr := errors.New("command failed")
	closeErr := errors.New("close failed")
	err := operationErr

	joinExecLogCloseError(&err, execErrorCloser{err: closeErr}, "host-1", "host-1.log")
	if !errors.Is(err, operationErr) {
		t.Fatalf("joined error lost operation error: %v", err)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("joined error lost close error: %v", err)
	}
}

func TestJoinConnectorCloseErrorPreservesBothErrors(t *testing.T) {
	operationErr := errors.New("command failed")
	closeErr := errors.New("close failed")
	err := operationErr

	joinConnectorCloseError(&err, execConnectorCloser{err: closeErr})
	if !errors.Is(err, operationErr) {
		t.Fatalf("joined error lost operation error: %v", err)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("joined error lost close error: %v", err)
	}
}
