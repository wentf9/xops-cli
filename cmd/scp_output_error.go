package cmd

// SCPOutputError records failed auxiliary SCP output. The CLI must not try
// to print this error to standard streams again: they may share a blocked sink.
// Unwrap preserves the original I/O and cancellation errors for API callers.
type SCPOutputError struct {
	Stream string
	Err    error
}

func (e *SCPOutputError) Error() string { return "write SCP " + e.Stream + ": " + e.Err.Error() }
func (e *SCPOutputError) Unwrap() error { return e.Err }
