package parallel

import (
	"errors"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/kvstore"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rlp"
)

var errInvalidPayload = errors.New("invalid payload")

// setCodeEnvelope mirrors core.setCodeEnvelope for local RLP decoding.
// (We cannot import package core to avoid an import cycle.)
type setCodeEnvelope struct {
	Version uint8
	TTL     uint64
	Code    []byte
}

// decodeSetCodeTTL parses only the TTL from a setCode tx.Data payload.
func decodeSetCodeTTL(data []byte) (uint64, error) {
	if len(data) == 0 {
		return 0, errInvalidPayload
	}
	var env setCodeEnvelope
	if err := rlp.DecodeBytes(data, &env); err != nil {
		return 0, errInvalidPayload
	}
	if env.Version != 1 || env.TTL == 0 {
		return 0, errInvalidPayload
	}
	return env.TTL, nil
}

// putUint64BE writes v into b (len >= 8) in big-endian order.
func putUint64BE(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

// setCodeExpiryCountSlot returns the storage slot on SystemActionAddress that
// holds the count for the setCode expiry bucket at the given expireAt block.
// Mirrors the private helpers in core/setcode_prune.go.
func setCodeExpiryCountSlot(expireAt uint64) common.Hash {
	var n [8]byte
	putUint64BE(n[:], expireAt)
	buf := make([]byte, 0, 26+8)
	buf = append(buf, "gtos.setcode.expiry.bucket"...)
	buf = append(buf, n[:]...)
	base := common.BytesToHash(crypto.Keccak256(buf))

	meta := make([]byte, 0, 32+1+6+1+5)
	meta = append(meta, base[:]...)
	meta = append(meta, 0x00)
	meta = append(meta, "bucket"...)
	meta = append(meta, 0x00)
	meta = append(meta, "count"...)
	return common.BytesToHash(crypto.Keccak256(meta))
}

// kvExpiryCountSlot returns the storage slot on KVRouterAddress that holds
// the count for the KV expiry bucket at the given expireAt block.
// Mirrors the private helpers in kvstore/state.go.
func kvExpiryCountSlot(expireAt uint64) common.Hash {
	var n [8]byte
	putUint64BE(n[:], expireAt)
	buf := make([]byte, 0, 21+8)
	buf = append(buf, "gtos.kv.expiry.bucket"...)
	buf = append(buf, n[:]...)
	base := common.BytesToHash(crypto.Keccak256(buf))

	meta := make([]byte, 0, 32+1+6+1+5)
	meta = append(meta, base[:]...)
	meta = append(meta, 0x00)
	meta = append(meta, "bucket"...)
	meta = append(meta, 0x00)
	meta = append(meta, "count"...)
	return common.BytesToHash(crypto.Keccak256(meta))
}

func addWriteSlot(as *AccessSet, addr common.Address, slot common.Hash) {
	if as.WriteSlots[addr] == nil {
		as.WriteSlots[addr] = make(map[common.Hash]struct{})
	}
	as.WriteSlots[addr][slot] = struct{}{}
}

// AnalyzeTx returns the static access set for a transaction message.
// blockNumber is the current block height, used to compute expireAt for TTL slots.
func AnalyzeTx(msg types.Message, blockNumber uint64) AccessSet {
	sender := msg.From()
	as := AccessSet{
		ReadAddrs:  make(map[common.Address]struct{}),
		ReadSlots:  make(map[common.Address]map[common.Hash]struct{}),
		WriteAddrs: make(map[common.Address]struct{}),
		WriteSlots: make(map[common.Address]map[common.Hash]struct{}),
	}

	// All tx types write sender balance and nonce.
	as.WriteAddrs[sender] = struct{}{}

	to := msg.To()
	if to == nil {
		// SetCode transaction.
		ttl, err := decodeSetCodeTTL(msg.Data())
		if err != nil {
			// Parse failure: conservatively conflict with SystemActionAddress.
			as.WriteAddrs[params.SystemActionAddress] = struct{}{}
			return as
		}
		expireAt := blockNumber + ttl
		addWriteSlot(&as, params.SystemActionAddress, setCodeExpiryCountSlot(expireAt))
		return as
	}

	switch *to {
	case params.SystemActionAddress:
		// System action conflicts with any other system action on ValidatorRegistryAddress.
		as.WriteAddrs[params.ValidatorRegistryAddress] = struct{}{}

	case params.KVRouterAddress:
		// KV Put: also writes sender KV state (sender addr covers that).
		// Conflicts between two KV puts sharing expireAt via the count slot.
		payload, err := kvstore.DecodePutPayload(msg.Data())
		if err != nil {
			// Parse failure: conservatively conflict with KVRouterAddress.
			as.WriteAddrs[params.KVRouterAddress] = struct{}{}
			return as
		}
		expireAt := blockNumber + payload.TTL
		addWriteSlot(&as, params.KVRouterAddress, kvExpiryCountSlot(expireAt))

	default:
		// Plain TOS transfer: writes recipient balance.
		as.WriteAddrs[*to] = struct{}{}
		as.ReadAddrs[*to] = struct{}{}
	}

	return as
}
