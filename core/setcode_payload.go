package core

import (
	"errors"
	"math"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rlp"
)

const setCodePayloadVersion uint8 = 1

var (
	// ErrInvalidSetCodePayload indicates malformed setCode payload bytes.
	ErrInvalidSetCodePayload = errors.New("invalid setCode payload")

	// Metadata slots stored on the account state trie.
	SetCodeCreatedAtSlot = crypto.Keccak256Hash([]byte("gtos.setCode.createdAt"))
	SetCodeExpireAtSlot  = crypto.Keccak256Hash([]byte("gtos.setCode.expireAt"))
)

// SetCodePayload carries code bytes and ttl delta (in blocks).
type SetCodePayload struct {
	TTL  uint64
	Code []byte
}

type setCodeEnvelope struct {
	Version uint8
	TTL     uint64
	Code    []byte
}

// EncodeSetCodePayload serializes a setCode payload into tx.Data.
func EncodeSetCodePayload(ttl uint64, code []byte) ([]byte, error) {
	if ttl == 0 {
		return nil, ErrInvalidSetCodePayload
	}
	return rlp.EncodeToBytes(&setCodeEnvelope{
		Version: setCodePayloadVersion,
		TTL:     ttl,
		Code:    common.CopyBytes(code),
	})
}

// DecodeSetCodePayload parses tx.Data into a setCode payload.
func DecodeSetCodePayload(data []byte) (*SetCodePayload, error) {
	if len(data) == 0 {
		return nil, ErrInvalidSetCodePayload
	}
	var env setCodeEnvelope
	if err := rlp.DecodeBytes(data, &env); err != nil {
		return nil, ErrInvalidSetCodePayload
	}
	if env.Version != setCodePayloadVersion || env.TTL == 0 {
		return nil, ErrInvalidSetCodePayload
	}
	return &SetCodePayload{
		TTL:  env.TTL,
		Code: common.CopyBytes(env.Code),
	}, nil
}

// SetCodeTTLGas returns additional gas charged by ttl retention.
func SetCodeTTLGas(ttl uint64) (uint64, error) {
	if ttl == 0 {
		return 0, nil
	}
	if ttl > math.MaxUint64/params.SetCodeTTLBlockGas {
		return 0, ErrGasUintOverflow
	}
	return ttl * params.SetCodeTTLBlockGas, nil
}

// EstimateSetCodeGas returns deterministic gas for a setCode operation.
func EstimateSetCodeGas(code []byte, ttl uint64) (uint64, error) {
	payload, err := EncodeSetCodePayload(ttl, code)
	if err != nil {
		return 0, err
	}
	return EstimateSetCodePayloadGas(payload, ttl)
}

// EstimateSetCodePayloadGas returns deterministic gas for an encoded setCode payload and ttl.
func EstimateSetCodePayloadGas(payload []byte, ttl uint64) (uint64, error) {
	intrinsic, err := IntrinsicGas(payload, nil, true, true, true)
	if err != nil {
		return 0, err
	}
	ttlGas, err := SetCodeTTLGas(ttl)
	if err != nil {
		return 0, err
	}
	if intrinsic > math.MaxUint64-ttlGas {
		return 0, ErrGasUintOverflow
	}
	return intrinsic + ttlGas, nil
}
