package cmd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
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

type execTempNodeDeleter struct {
	errByNode map[string]error
	deleted   []string
}

type execTestStore struct{}

func (execTestStore) Load() (*config.Configuration, error) { return nil, nil }

func (execTestStore) Save(*config.Configuration) error { return nil }

func TestShouldTrackTemporaryNodeRequiresSuccessfulDurableCreation(t *testing.T) {
	tests := []struct {
		name     string
		mutation config.NodeMutation
		err      error
		want     bool
	}{
		{name: "durable creation", mutation: config.NodeMutation{Ref: config.NodeRef{ID: "temporary"}, Outcome: config.MutationOutcome{Applied: true, Durable: true}}, want: true},
		{name: "applied but undurable", mutation: config.NodeMutation{Ref: config.NodeRef{ID: "temporary"}, Outcome: config.MutationOutcome{Applied: true}}, err: errors.New("sync configuration"), want: false},
		{name: "unapplied failure", mutation: config.NodeMutation{Ref: config.NodeRef{ID: "temporary"}}, err: errors.New("write configuration"), want: false},
		{name: "missing reference", mutation: config.NodeMutation{Outcome: config.MutationOutcome{Applied: true, Durable: true}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldTrackTemporaryNode(tt.mutation, tt.err); got != tt.want {
				t.Fatalf("shouldTrackTemporaryNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

type execReentrantTempNodeDeleter struct {
	options *ExecOptions
}

func (d execReentrantTempNodeDeleter) DeleteNodeAtRefContext(context.Context, config.NodeRef) (config.MutationOutcome, error) {
	d.options.addTempNode(config.NodeRef{ID: "created-during-cleanup"})
	return config.MutationOutcome{Applied: true, Durable: true}, nil
}

func (d *execTempNodeDeleter) DeleteNodeAtRefContext(_ context.Context, ref config.NodeRef) (config.MutationOutcome, error) {
	d.deleted = append(d.deleted, ref.ID)
	return config.MutationOutcome{}, d.errByNode[ref.ID]
}

func TestPrintTaskResultReturnsOutputError(t *testing.T) {
	wantErr := errors.New("output closed")
	o := NewExecOptions()
	o.stdout = execErrorWriter{err: wantErr}

	err := o.printTaskResult(execHostTask{host: "host-1"}, "output", nil, &sync.Mutex{})
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

func TestCleanUnusedTempNodesReturnsAndRetainsFailedCleanup(t *testing.T) {
	deleteErr := errors.New("persistent store unavailable")
	o := NewExecOptions()
	o.addTempNode(config.NodeRef{ID: "remove"})
	o.addTempNode(config.NodeRef{ID: "retry"})
	deleter := &execTempNodeDeleter{errByNode: map[string]error{"retry": deleteErr}}

	err := o.cleanUnusedTempNodes(deleter)
	if !errors.Is(err, deleteErr) {
		t.Fatalf("cleanUnusedTempNodes() error = %v, want wrapped delete error", err)
	}

	o.tempNodesMu.Lock()
	defer o.tempNodesMu.Unlock()
	if len(o.tempNodes) != 1 || o.tempNodes["retry"].ID != "retry" {
		t.Fatalf("pending temporary nodes = %#v, want only retry", o.tempNodes)
	}
}

func TestCleanUnusedTempNodesDoesNotHoldLockDuringDelete(t *testing.T) {
	o := NewExecOptions()
	o.addTempNode(config.NodeRef{ID: "pending"})
	done := make(chan error, 1)

	go func() {
		done <- o.cleanUnusedTempNodes(execReentrantTempNodeDeleter{options: o})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cleanUnusedTempNodes() failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleanUnusedTempNodes() held tempNodesMu while deleting")
	}

	o.tempNodesMu.Lock()
	defer o.tempNodesMu.Unlock()
	if o.tempNodes["created-during-cleanup"].ID != "created-during-cleanup" {
		t.Fatalf("temporary node created during cleanup was lost: %#v", o.tempNodes)
	}
}

func TestCleanUnusedTempNodesDoesNotDeleteChangedNode(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.10", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "root"})
	cfg.Nodes.Set("temporary", models.Node{HostRef: "host", IdentityRef: "identity"})
	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, execTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	o := NewExecOptions()
	o.addTempNode(repository.View().NodeRefs["temporary"])
	if _, err := repository.UpdateNodeTagsContext(t.Context(), []string{"temporary"}, []string{"kept"}, true); err != nil {
		t.Fatalf("UpdateNodeTags() error = %v", err)
	}

	err = o.cleanUnusedTempNodes(repository)
	if !errors.Is(err, config.ErrConfigConflict) {
		t.Fatalf("cleanUnusedTempNodes() error = %v, want ErrConfigConflict", err)
	}
	if _, exists := repository.GetNode("temporary"); !exists {
		t.Fatal("temporary cleanup deleted a node changed by another writer")
	}
}
