//go:build !unix

package ssh

func holdSocketDirLockForTest(_ string, fn func() error) error {
	return fn()
}
