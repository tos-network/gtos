package kvstore

import (
	"math"

	"github.com/tos-network/gtos/params"
)

// KVTTLGas returns additional gas charged by ttl retention.
func KVTTLGas(ttl uint64) (uint64, error) {
	if ttl == 0 {
		return 0, ErrInvalidTTL
	}
	if ttl > math.MaxUint64/params.KVTTLBlockGas {
		return 0, ErrTTLOverflow
	}
	return ttl * params.KVTTLBlockGas, nil
}

func intrinsicDataGas(payload []byte) (uint64, error) {
	gas := params.TxGas
	if len(payload) == 0 {
		return gas, nil
	}
	var nonZero uint64
	for _, b := range payload {
		if b != 0 {
			nonZero++
		}
	}
	if (math.MaxUint64-gas)/params.TxDataNonZeroGasReduced < nonZero {
		return 0, ErrTTLOverflow
	}
	gas += nonZero * params.TxDataNonZeroGasReduced
	zero := uint64(len(payload)) - nonZero
	if (math.MaxUint64-gas)/params.TxDataZeroGas < zero {
		return 0, ErrTTLOverflow
	}
	gas += zero * params.TxDataZeroGas
	return gas, nil
}

// EstimatePutPayloadGas returns deterministic gas for an encoded KV payload and ttl.
func EstimatePutPayloadGas(payload []byte, ttl uint64) (uint64, error) {
	intrinsic, err := intrinsicDataGas(payload)
	if err != nil {
		return 0, err
	}
	ttlGas, err := KVTTLGas(ttl)
	if err != nil {
		return 0, err
	}
	if intrinsic > math.MaxUint64-ttlGas {
		return 0, ErrTTLOverflow
	}
	return intrinsic + ttlGas, nil
}
