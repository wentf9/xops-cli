package credential

import "context"

type nonInteractiveKey struct{}

// WithoutInteraction marks a request as forbidden from opening any credential
// or unlock prompt. Backends must reject requests they cannot serve silently.
func WithoutInteraction(ctx context.Context) context.Context {
	return context.WithValue(ctx, nonInteractiveKey{}, true)
}

// InteractionDisabled reports the request's non-interactive access policy.
func InteractionDisabled(ctx context.Context) bool {
	disabled, _ := ctx.Value(nonInteractiveKey{}).(bool)
	return disabled
}
