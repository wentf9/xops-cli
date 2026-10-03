package transfer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// The v2 journal encodes opaque credential CAS tokens as base64. Legacy CLI
// providers use binary SHA-256 strings, which JSON strings cannot round-trip.
func (a Authorization) MarshalJSON() ([]byte, error) {
	copy := a.clone()
	if err := copy.mapTokens(func(value string) (string, error) { return base64.StdEncoding.EncodeToString([]byte(value)), nil }); err != nil {
		return nil, err
	}
	type plain Authorization
	return json.Marshal((*plain)(copy))
}

func (a *Authorization) UnmarshalJSON(data []byte) error {
	type plain Authorization
	var decoded plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("decode transfer authorization: %w", err)
	}
	value := Authorization(decoded)
	if err := value.mapTokens(func(token string) (string, error) {
		data, err := base64.StdEncoding.Strict().DecodeString(token)
		return string(data), err
	}); err != nil {
		return fmt.Errorf("decode transfer credential version: %w", err)
	}
	*a = value
	return nil
}

func (a *Authorization) mapTokens(convert func(string) (string, error)) error {
	for id, target := range a.Snapshot.Targets {
		for i := range target.Plan.Hops {
			hop := &target.Plan.Hops[i]
			var err error
			hop.AuthUpdateToken, err = convert(hop.AuthUpdateToken)
			if err != nil {
				return err
			}
			hop.SudoUpdateToken, err = convert(hop.SudoUpdateToken)
			if err != nil {
				return err
			}
		}
		a.Snapshot.Targets[id] = target
	}
	return nil
}
