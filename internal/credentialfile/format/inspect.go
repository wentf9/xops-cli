package format

// InspectItem reads bounded, unauthenticated identity metadata for enumeration.
// Callers must compare it with the vault and filename, then authenticate OpenItem.
func InspectItem(data []byte) (ItemIdentity, error) {
	h, p, err := split(data, itemMagic, MaxItemBytes)
	if err != nil {
		return ItemIdentity{}, err
	}
	if len(p) < 17 || len(p) > MaxSecretBytes+16 {
		return ItemIdentity{}, ErrCorrupt
	}
	parsed, err := parseItemHeader(h)
	if err != nil {
		return ItemIdentity{}, err
	}
	return parsed.identity, nil
}
