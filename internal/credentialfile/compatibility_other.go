//go:build (!linux && !darwin && !windows) || (!amd64 && !arm64)

package credentialfile

import (
	"context"
	"runtime"
)

func ProbeCompatibility(context.Context, string) (CompatibilityReport, error) {
	return CompatibilityReport{Platform: runtime.GOOS + "/" + runtime.GOARCH}, ErrUnsupported
}
