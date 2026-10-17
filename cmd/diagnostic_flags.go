package cmd

import "strconv"

// Numeric spacing mirrors OpenSSH log.h: repeated -v after -q advances through
// FATAL, ERROR, INFO and VERBOSE before reaching DEBUG1 again.
const (
	sshLogQuiet  = 0
	sshLogInfo   = 3
	sshLogDebug1 = 5
	sshLogDebug3 = 7
)

// orderedOutputFlag preserves argument order, including combined short flags.
// SSH uses one log level; SCP separately tracks its own SFTP verbosity.
type orderedOutputFlag struct {
	value *bool
	set   func(bool)
}

func (f orderedOutputFlag) String() string { return strconv.FormatBool(*f.value) }
func (f orderedOutputFlag) Type() string   { return "bool" }
func (f orderedOutputFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	*f.value = v
	f.set(v)
	return nil
}

// quotedDiagnostic bounds untrusted metadata and escapes terminal controls.
func quotedDiagnostic(s string) string {
	if len(s) > 256 {
		s = s[:256] + "..."
	}
	return strconv.QuoteToASCII(s)
}
