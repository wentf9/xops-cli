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
	prepared, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2222))
	if err != nil {
		t.Fatal(err)
	}
	before, err := repo.ResolveConnection(prepared.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	execution, pending := repo.PendingNodeExecution(prepared.NodeID)
	if !pending || execution != nil || store.saves != 0 {
		t.Fatal("pending execution leaked to disk")
	}
	login := false
	probe := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterSh, LaunchDialect: ssh.LaunchPOSIX, Login: &login}
	if err := repo.ConfirmNodeWithExecutionContext(t.Context(), prepared.NodeID, probe); err != nil {
		t.Fatal(err)
	}
	*probe.Login = true
	node, saved := repo.GetNode(prepared.NodeID)
	if !saved || node.Execution == nil || *node.Execution.Login || store.saves != 1 {
		t.Fatal("execution was not isolated and saved with enrollment in one transaction")
	}
	after, err := repo.ResolveConnection(prepared.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if *before.UpdateRef != *after.UpdateRef {
		t.Fatal("execution enrollment changed credential field versions")
	}
	if _, pending := repo.PendingNodeExecution(prepared.NodeID); pending {
		t.Fatal("confirmed connection stayed pending")
	}
	if err := repo.ConfirmNodeWithExecutionContext(t.Context(), prepared.NodeID, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}); err != nil {
		t.Fatal(err)
	}
	node, _ = repo.GetNode(prepared.NodeID)
	if node.Execution.Interpreter != ssh.InterpreterSh || store.saves != 1 {
		t.Fatal("late probe overwrote already-confirmed node")
	}
}

func TestConfirmPendingExecutionRejectsInvalidRecommendation(t *testing.T) {
	repo, store := pendingDiskRepository(t)
	prepared, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2222))
	if err != nil {
		t.Fatal(err)
	}
	err = repo.ConfirmNodeWithExecutionContext(t.Context(), prepared.NodeID, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchCmd})
	if !errors.Is(err, ssh.ErrExecutionValidation) {
		t.Fatalf("invalid probe recommendation accepted: %v", err)
	}
	assertPendingConnectionInvisible(t, repo, store, prepared.NodeID)
}
