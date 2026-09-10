package format

// InspectTransaction validates public syntax only, to locate wrapping metadata.
// Its result MUST NOT authorize reads, publication or deletion without a valid MAC.
func InspectTransaction(data []byte) (Transaction, error) {
	fields, err := parseEnvelope(data)
	if err != nil {
		return Transaction{}, err
	}
	return parseTransactionPayload(fields["payload"])
}
