//go:build darwin && (amd64 || arm64)

package kdfhelper

import "os/exec"

func preparePrivateProcess(*exec.Cmd) (func() error, error) { return func() error { return nil }, nil }
func attachPrivateProcess(*exec.Cmd) error                  { return nil }
