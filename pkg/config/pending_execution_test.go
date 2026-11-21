package config

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestConfirmPendingExecutionUsesOneTransactionAndPreservesAuthVersion(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatal(err)
	}
	var nodeID string
	var before ConnectionSnapshot
	if err := repo.WithPendingNode(t.Context(), pendingTestOptions(2222), func(lease PendingLease) error {
		nodeID = lease.NodeID()
		var rErr error
		before, rErr = repo.ResolveConnection(nodeID)
		if rErr != nil {
			t.Fatal(rErr)
		}
		execution, pending := repo.PendingNodeExecution(nodeID)
		if !pending || execution != nil || store.saves != 0 {
			t.Fatal("pending execution leaked to disk")
		}
		login := false
		probe := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterSh, LaunchDialect: ssh.LaunchPOSIX, Login: &login}
		execLease := lease.(PendingExecutionLease)
		if err := execLease.ConfirmWithExecution(t.Context(), probe); err != nil {
			t.Fatal(err)
		}
		*probe.Login = true
		node, saved := repo.GetNode(nodeID)
		if !saved || node.Execution == nil || *node.Execution.Login || store.saves != 1 {
			t.Fatal("execution was not isolated and saved with enrollment in one transaction")
		}
		after, err := repo.ResolveConnection(nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if *before.UpdateRef != *after.UpdateRef {
			t.Fatal("execution enrollment changed credential field versions")
		}
		if _, pending := repo.PendingNodeExecution(nodeID); pending {
			t.Fatal("confirmed connection stayed pending")
		}
		if err := execLease.ConfirmWithExecution(t.Context(), &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}); err != nil {
			t.Fatal(err)
		}
		node, _ = repo.GetNode(nodeID)
		if node.Execution.Interpreter != ssh.InterpreterSh || store.saves != 1 {
			t.Fatal("late probe overwrote already-confirmed node")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmPendingExecutionRejectsInvalidRecommendation(t *testing.T) {
	repo, store := pendingDiskRepository(t)
	if err := repo.WithPendingNode(t.Context(), pendingTestOptions(2222), func(lease PendingLease) error {
		execLease := lease.(PendingExecutionLease)
		err := execLease.ConfirmWithExecution(t.Context(), &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchCmd})
		if !errors.Is(err, ssh.ErrExecutionValidation) {
			t.Fatalf("invalid probe recommendation accepted: %v", err)
		}
		assertPendingConnectionInvisible(t, repo, store, lease.NodeID())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
