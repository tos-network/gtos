package sysaction

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrInvalidSysAction is returned when tx.Data cannot be decoded as a SysAction.
var ErrInvalidSysAction = errors.New("invalid system action payload")

// Decode parses a SysAction from raw bytes (tx.Data).
func Decode(data []byte) (*SysAction, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrInvalidSysAction)
	}
	var sa SysAction
	if err := json.Unmarshal(data, &sa); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSysAction, err)
	}
	if sa.Action == "" {
		return nil, fmt.Errorf("%w: missing action field", ErrInvalidSysAction)
	}
	return &sa, nil
}

// DecodePayload unmarshals sa.Payload into dst.
func DecodePayload(sa *SysAction, dst interface{}) error {
	if len(sa.Payload) == 0 {
		return nil
	}
	return json.Unmarshal(sa.Payload, dst)
}

// Encode serialises a SysAction to JSON bytes suitable for tx.Data.
func Encode(sa *SysAction) ([]byte, error) {
	return json.Marshal(sa)
}

// MakeSysAction is a convenience helper that creates and encodes a SysAction.
func MakeSysAction(kind ActionKind, payload interface{}) ([]byte, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	return Encode(&SysAction{Action: kind, Payload: raw})
}
