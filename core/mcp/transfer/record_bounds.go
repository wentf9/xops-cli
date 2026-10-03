package transfer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const maxDiagnosticBytes = 4096

// ValidateDiagnostic bounds the JSON content as well as its UTF-8 byte length.
// This is used for exact operator reasons, which must not be silently truncated.
func ValidateDiagnostic(value string) error {
	if !utf8.ValidString(value) || diagnosticPrefix(value) != len(value) {
		return errors.New("transfer diagnostic exceeds the encoded 4096-byte limit or is not valid UTF-8")
	}
	return nil
}

func diagnosticPrefix(value string) int {
	size := 0
	for index, char := range value {
		cost := utf8.RuneLen(char)
		switch char {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			cost = 2
		case '<', '>', '&', '\u2028', '\u2029':
			cost = 6
		default:
			if char < 0x20 {
				cost = 6
			}
		}
		if size+cost > maxDiagnosticBytes {
			return index
		}
		size += cost
	}
	return len(value)
}

func boundedDiagnostic(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	return value[:diagnosticPrefix(value)]
}

// A token is issued only if the immutable payload leaves enough room for all
// mutable fields through failure, unknown outcome, recovery and resolution.
func validatePreparationSize(record Record) error {
	if _, err := encodeRecord(record); err != nil {
		return err
	}
	worst := record
	worst.State = Transferring // longest state spelling
	worst.UpdatedAt = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	worst.Bytes = record.Spec.Size
	worst.SHA256 = strings.Repeat("f", 64)
	if record.Spec.Direction == Upload {
		worst.TempPath = temporaryPath(record.Spec.RemotePath, record.ID)
	}
	worst.Error = strings.Repeat("e", maxDiagnosticBytes)
	worst.Warning = worst.Error
	worst.Resolution = worst.Error
	worst.TempOwned, worst.CleanupPending, worst.CancelRequested, worst.Resolved = false, false, false, false
	// The projection combines maxima, not an executable state transition.
	data, err := json.Marshal(worst)
	if err != nil {
		return fmt.Errorf("encode transfer growth reservation: %w", err)
	}
	if len(data) > maxRecordBytes {
		return fmt.Errorf("reserve transfer journal growth: %w", ErrRecordTooLarge)
	}
	return nil
}
