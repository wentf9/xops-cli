package credentialfile

// CompatibilityReport describes an explicit disposable filesystem probe. It
// verifies operations, not resistance to physical power loss or future I/O stalls.
type CompatibilityReport struct {
	Platform  string   `json:"platform"`
	Directory string   `json:"directory"`
	Checks    []string `json:"checks"`
}
