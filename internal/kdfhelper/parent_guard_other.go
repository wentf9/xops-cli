//go:build (linux || windows) && (amd64 || arm64)

package kdfhelper

// Linux uses Pdeathsig and Windows uses a kill-on-close job object.
func startParentGuard() (func(), error) { return func() {}, nil }
