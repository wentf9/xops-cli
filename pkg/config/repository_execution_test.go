package config

import (
	"errors"
	"reflect"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestRepositoryExecutionUpdateIsConditionalAndIsolated(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), store)
	if err != nil {
		t.Fatal(err)
	}
	before, host, identity, err := repo.Resolve("web-server")
	if err != nil {
		t.Fatal(err)
	}
	ref := repo.View().NodeRefs["web-server"]
	login := false
	execution := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX, Login: &login}
	if err := repo.UpdateNodeExecutionAtRefContext(t.Context(), ref, execution); err != nil {
		t.Fatal(err)
	}
	*execution.Login = true
	execution.Interpreter = ssh.InterpreterSh
	node, afterHost, afterIdentity, err := repo.Resolve("web-server")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(host, afterHost) || !reflect.DeepEqual(identity, afterIdentity) || node.HostRef != before.HostRef || node.IdentityRef != before.IdentityRef {
		t.Fatal("execution update changed host or identity")
	}
	if node.Execution.Interpreter != ssh.InterpreterBash || *node.Execution.Login {
		t.Fatal("execution update retained caller-owned mutable fields")
	}
	if err := repo.UpdateNodeExecutionAtRefContext(t.Context(), ref, nil); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("stale probe overwrote newer execution: %v", err)
	}
	current := repo.View().NodeRefs["web-server"]
	if err := repo.UpdateNodeExecutionAtRefContext(t.Context(), current, &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchCmd}); !errors.Is(err, ssh.ErrExecutionValidation) {
		t.Fatalf("invalid execution accepted: %v", err)
	}
}
