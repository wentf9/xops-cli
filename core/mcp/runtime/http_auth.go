package runtime

import (
	"context"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

// authenticateHTTP bounds deployment-owned verification independently of the
// protocol's request and control lanes. Holding a slot across next.ServeHTTP
// would let an SSE stream or a waiting tool prevent control authentication.
func (r *Runtime) authenticateHTTP(next http.Handler) http.Handler {
	options := &auth.RequireBearerTokenOptions{AllowMissingExpiration: true}
	if r.http.TokenVerifier == nil {
		return auth.RequireBearerToken(r.verifyHTTPToken, options)(next)
	}
	verifiers := make(chan struct{}, r.http.MaxRequests)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !acquireHTTPAdmission(w, verifiers, "authentication_limit") {
			return
		}
		release := sync.OnceFunc(func() { <-verifiers })
		// The middleware may reject a malformed header without calling verify.
		defer release()
		verify := func(ctx context.Context, token string, req *http.Request) (*auth.TokenInfo, error) {
			// Release on success, rejection or backend error, before the SDK
			// writes a response or admits/parses the authenticated protocol call.
			defer release()
			return r.verifyHTTPToken(ctx, token, req)
		}
		auth.RequireBearerToken(verify, options)(next).ServeHTTP(w, req)
	})
}
