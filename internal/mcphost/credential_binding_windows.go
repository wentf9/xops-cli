//go:build windows

package mcphost

import "os"

func openRegularCertFile(certPath string) (*os.File, os.FileInfo, bool, error) {
	info, err := os.Stat(certPath)
	if err != nil {
		return nil, nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, true, nil
	}
	f, err := os.Open(certPath)
	if err != nil {
		return nil, nil, false, err
	}
	fInfo, statErr := f.Stat()
	if statErr != nil || !fInfo.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, true, nil
	}
	return f, fInfo, false, nil
}
