package playbook

import (
	"errors"
	"testing"
)

func TestFailStepResultPreservesOperationAndCleanupErrors(t *testing.T) {
	operationErr := errors.New("upload failed")
	cleanupErr := errors.New("close failed")

	result := failStepResult(StepResult{Status: StatusFailed, Err: operationErr}, cleanupErr)
	if result.Status != StatusFailed {
		t.Fatalf("status = %s, want %s", result.Status, StatusFailed)
	}
	if !errors.Is(result.Err, operationErr) {
		t.Fatalf("result error lost operation error: %v", result.Err)
	}
	if !errors.Is(result.Err, cleanupErr) {
		t.Fatalf("result error lost cleanup error: %v", result.Err)
	}
}

func TestFailStepResultTurnsSuccessfulStepIntoFailure(t *testing.T) {
	cleanupErr := errors.New("close failed")

	result := failStepResult(StepResult{Status: StatusChanged}, cleanupErr)
	if result.Status != StatusFailed {
		t.Fatalf("status = %s, want %s", result.Status, StatusFailed)
	}
	if !errors.Is(result.Err, cleanupErr) {
		t.Fatalf("result error = %v, want cleanup error", result.Err)
	}
}
