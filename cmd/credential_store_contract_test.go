package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/internal/credentialfile"
	"github.com/wentf9/xops-cli/internal/credentialfile/format"
)

// These expectations are the published interface contract. New optional flags
// are allowed, but existing names, types and defaults must remain compatible.
func TestFrozenOfflineCommandOptions(t *testing.T) {
	for op, names := range map[string][]string{
		"init": {}, "inspect": {"verify"}, "rewrap": {"unlock", "key-file"},
		"reencrypt": {}, "resume": {"unlock", "key-file", "from", "source-unlock", "source-key-file", "source-store", "operation"},
		"restore": {"from", "source-unlock", "source-key-file", "backup-config"},
		"clone":   {"to"}, "prune": {"apply"},
	} {
		t.Run(op, func(t *testing.T) {
			command := newOfflineStoreCommand(op)
			if command.Use != op+" <storeID>" {
				t.Fatalf("changed command usage: %s", command.Use)
			}
			if command.Args(command, nil) == nil || command.Args(command, []string{"a", "b"}) == nil || command.Args(command, []string{"a"}) != nil {
				t.Fatal("StoreID argument contract changed")
			}
			for _, name := range append(names, "json") {
				wantType, wantDefault := "string", ""
				if name == "json" || name == "verify" || name == "apply" {
					wantType, wantDefault = "bool", "false"
				}
				flag := command.Flags().Lookup(name)
				if flag == nil || flag.Value.Type() != wantType || flag.DefValue != wantDefault {
					t.Fatalf("changed flag contract: %s", name)
				}
			}
			deadline := command.Flags().Lookup("maintenance-timeout")
			if op != "inspect" && (deadline == nil || deadline.Value.Type() != "duration" || deadline.DefValue != "30m0s") {
				t.Fatal("maintenance deadline contract changed")
			}
			for _, name := range []string{"force", "password", "master-password"} {
				if command.Flags().Lookup(name) != nil {
					t.Fatalf("unsafe flag added: %s", name)
				}
			}
		})
	}
}

func TestFrozenOfflineJSONPreservesPartialCommit(t *testing.T) {
	err := &credentialfile.DurabilityError{Op: "maintenance", Applied: true, Durable: false, Cause: errors.Join(context.DeadlineExceeded, errors.New("private diagnostic"))}
	result := storeCommandResult{Code: offlineErrorCode(err), Op: "reencrypt", Outcome: credentialfile.MaintenanceResult{
		OperationID: "public-operation", Revision: 3, Generation: 2, Stage: format.Published, Applied: true, Durable: false, Changed: false,
	}}
	data, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	// Decode as a consumer to pin names and distinguish publication, durability
	// and cleanup even when the command returns a deadline error.
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded["code"]) != `"timeout"` || string(decoded["op"]) != `"reencrypt"` {
		t.Fatal("error/result contract changed")
	}
	var outcome map[string]json.RawMessage
	if err := json.Unmarshal(decoded["outcome"], &outcome); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"operation_id": `"public-operation"`, "revision": "3", "generation": "2", "stage": "4", "applied": "true", "durable": "false", "changed": "false"} {
		if string(outcome[key]) != want {
			t.Fatalf("changed outcome %s: %s", key, outcome[key])
		}
	}
	if _, ok := decoded["inspection"]; ok {
		t.Fatal("absent inspection should be omitted")
	}
	if _, ok := decoded["revisions"]; ok {
		t.Fatal("empty cleanup plan should be omitted")
	}
}
