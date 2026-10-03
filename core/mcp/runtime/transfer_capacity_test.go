package runtime

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/state"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
)

func TestUploadCommitKeepsItsAdmissionSlotAtCapacity(t *testing.T) {
	for _, limit := range []int{1, 2} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			f := setupPublicationWithAdmission(t, nil, false, state.Options{MaxActive: limit}, true)
			server := publicationHTTP(t, f)
			if limit == 2 {
				view, err := f.coordinator.Resolve(f.ctx, ports.ResolveRequest{Selectors: []string{"node"}})
				if err != nil {
					t.Fatal(err)
				}
				binding, err := ports.Bind(view, "other-operation", "xops_ssh_run", "hostname")
				if err != nil {
					t.Fatal(err)
				}
				permit, err := f.coordinator.Enter(f.ctx, ports.Admission{OperationID: "unrelated", Phase: ports.Execute, Snapshot: view, Binding: binding})
				if err != nil {
					t.Fatal(err)
				}
				defer closeTransferTestResource(t, permit)
			}
			for index := range 2 {
				input := uploadBoundaryInput(fmt.Sprintf("capacity-%d", index), fmt.Sprintf("/capacity-%d", index), []byte("payload"))
				input.NodeID = "node"
				prepared := prepareTransferTest(t, f.client, "xops_prepare_upload", input)
				response, body := transferTestRequest(t, server, prepared.Method, prepared.URL, prepared.Headers, bytes.NewBufferString("payload"))
				if response.StatusCode != http.StatusOK {
					t.Fatalf("upload at capacity failed: HTTP %d: %s", response.StatusCode, body)
				}
				status := transferTestStatus(t, server, prepared)
				if status.State != transfer.Completed || status.CleanupPending {
					t.Fatalf("commit did not complete cleanly: %+v", status)
				}
			}
		})
	}
}

func TestFailedUploadReleasesAdmissionBeforeTemporaryCleanup(t *testing.T) {
	f := setupPublicationWithAdmission(t, nil, false, state.Options{MaxActive: 1}, true)
	server := publicationHTTP(t, f)
	input := uploadBoundaryInput("bad-content", "/failed", []byte("expected"))
	input.NodeID = "node"
	p := prepareTransferTest(t, f.client, "xops_prepare_upload", input)
	response, _ := transferTestRequest(t, server, p.Method, p.URL, p.Headers, bytes.NewBufferString("mismatch"))
	if response.StatusCode == http.StatusOK {
		t.Fatal("mismatched content succeeded")
	}
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Failed || status.CleanupPending {
		t.Fatalf("failed stream retained its cleanup slot: %+v", status)
	}
}
