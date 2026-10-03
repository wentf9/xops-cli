package guardrail

import "context"

type operationIDKey struct{}

// OperationID returns the ID assigned by the guardrail to an admitted handler.
func OperationID(ctx context.Context) string {
	id, _ := ctx.Value(operationIDKey{}).(string)
	return id
}
