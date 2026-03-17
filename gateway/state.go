package gateway

import (
	"encoding/binary"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

// stateDB is the minimal storage interface required by this package.
type stateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

// registry is a shorthand for the GatewayRegistryAddress.
var registry = params.GatewayRegistryAddress

// ---------- Slot helpers ----------

// gwSlot returns a storage slot for a per-gateway scalar field.
// Key = keccak256("gw\x00" || addr[20] || 0x00 || field).
func gwSlot(addr common.Address, field string) common.Hash {
	key := make([]byte, 0, 3+common.AddressLength+1+len(field))
	key = append(key, "gw\x00"...)
	key = append(key, addr.Bytes()...)
	key = append(key, 0x00)
	key = append(key, field...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// gwCountSlot stores the total count of ever-registered gateways (uint64).
var gwCountSlot = common.BytesToHash(crypto.Keccak256([]byte("gw\x00count")))

// ---------- Active flag ----------

// ReadActive returns true if the gateway is active.
func ReadActive(db stateDB, addr common.Address) bool {
	raw := db.GetState(registry, gwSlot(addr, "active"))
	return raw[31] != 0
}

// WriteActive writes the active flag for a gateway.
func WriteActive(db stateDB, addr common.Address, active bool) {
	var val common.Hash
	if active {
		val[31] = 1
	}
	db.SetState(registry, gwSlot(addr, "active"), val)
}

// ---------- RegisteredAt ----------

// ReadRegisteredAt returns the block number when the gateway was registered.
func ReadRegisteredAt(db stateDB, addr common.Address) uint64 {
	raw := db.GetState(registry, gwSlot(addr, "registeredAt"))
	return binary.BigEndian.Uint64(raw[24:])
}

// WriteRegisteredAt writes the registration block number.
func WriteRegisteredAt(db stateDB, addr common.Address, blockNum uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], blockNum)
	db.SetState(registry, gwSlot(addr, "registeredAt"), val)
}

// ---------- MaxRelayGas ----------

// ReadMaxRelayGas returns the maximum relay gas for a gateway.
func ReadMaxRelayGas(db stateDB, addr common.Address) uint64 {
	raw := db.GetState(registry, gwSlot(addr, "maxRelayGas"))
	return binary.BigEndian.Uint64(raw[24:])
}

// WriteMaxRelayGas writes the max relay gas.
func WriteMaxRelayGas(db stateDB, addr common.Address, gas uint64) {
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], gas)
	db.SetState(registry, gwSlot(addr, "maxRelayGas"), val)
}

// ---------- FeePolicy ----------

// ReadFeePolicy returns the fee policy string (stored as a single-slot short string).
func ReadFeePolicy(db stateDB, addr common.Address) string {
	raw := db.GetState(registry, gwSlot(addr, "feePolicy"))
	length := int(raw[0])
	if length == 0 || length > 31 {
		return ""
	}
	return string(raw[1 : 1+length])
}

// WriteFeePolicy writes the fee policy (must be <= 31 bytes).
func WriteFeePolicy(db stateDB, addr common.Address, policy string) {
	var val common.Hash
	val[0] = byte(len(policy))
	copy(val[1:], []byte(policy))
	db.SetState(registry, gwSlot(addr, "feePolicy"), val)
}

// ---------- FeeAmount ----------

// ReadFeeAmount returns the fee amount for a gateway.
func ReadFeeAmount(db stateDB, addr common.Address) *big.Int {
	raw := db.GetState(registry, gwSlot(addr, "feeAmount"))
	return raw.Big()
}

// WriteFeeAmount writes the fee amount.
func WriteFeeAmount(db stateDB, addr common.Address, amount *big.Int) {
	db.SetState(registry, gwSlot(addr, "feeAmount"), common.BigToHash(amount))
}

// ---------- Endpoint (multi-slot string) ----------

// endpointBaseSlot returns the base slot for the endpoint string data.
func endpointBaseSlot(addr common.Address) common.Hash {
	key := append([]byte("gw\x00endpoint\x00"), addr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// ReadEndpoint returns the stored endpoint for a gateway.
func ReadEndpoint(db stateDB, addr common.Address) string {
	lenRaw := db.GetState(registry, gwSlot(addr, "endpointLen"))
	uriLen := int(binary.BigEndian.Uint64(lenRaw[24:]))
	if uriLen == 0 || uriLen > MaxEndpointLength {
		return ""
	}
	baseSlot := endpointBaseSlot(addr).Big()
	buf := make([]byte, 0, uriLen)
	for i := 0; len(buf) < uriLen; i++ {
		slot := common.BigToHash(new(big.Int).Add(baseSlot, big.NewInt(int64(i))))
		raw := db.GetState(registry, slot)
		remaining := uriLen - len(buf)
		if remaining >= 32 {
			buf = append(buf, raw[:]...)
		} else {
			buf = append(buf, raw[:remaining]...)
		}
	}
	return string(buf)
}

// WriteEndpoint stores the endpoint string across multiple 32-byte slots.
func WriteEndpoint(db stateDB, addr common.Address, endpoint string) {
	data := []byte(endpoint)
	var lenVal common.Hash
	binary.BigEndian.PutUint64(lenVal[24:], uint64(len(data)))
	db.SetState(registry, gwSlot(addr, "endpointLen"), lenVal)

	baseSlot := endpointBaseSlot(addr).Big()
	for i := 0; i < len(data); i += 32 {
		var val common.Hash
		end := i + 32
		if end > len(data) {
			end = len(data)
		}
		copy(val[:], data[i:end])
		slot := common.BigToHash(new(big.Int).Add(baseSlot, big.NewInt(int64(i/32))))
		db.SetState(registry, slot, val)
	}
}

// ---------- SupportedKinds (multi-slot) ----------

// kindsBaseSlot returns the base slot for supported kinds data.
func kindsBaseSlot(addr common.Address) common.Hash {
	key := append([]byte("gw\x00kinds\x00"), addr.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(key))
}

// ReadSupportedKinds returns the stored supported kinds for a gateway.
func ReadSupportedKinds(db stateDB, addr common.Address) []string {
	countRaw := db.GetState(registry, gwSlot(addr, "kindsCount"))
	count := int(binary.BigEndian.Uint64(countRaw[24:]))
	if count == 0 || count > MaxSupportedKinds {
		return nil
	}
	baseSlot := kindsBaseSlot(addr).Big()
	kinds := make([]string, 0, count)
	for i := 0; i < count; i++ {
		slot := common.BigToHash(new(big.Int).Add(baseSlot, big.NewInt(int64(i))))
		raw := db.GetState(registry, slot)
		length := int(raw[0])
		if length == 0 || length > 31 {
			continue
		}
		kinds = append(kinds, string(raw[1:1+length]))
	}
	return kinds
}

// WriteSupportedKinds stores the supported kinds. Each kind is stored in a single
// 32-byte slot (max 31 chars per kind, first byte = length).
func WriteSupportedKinds(db stateDB, addr common.Address, kinds []string) {
	var countVal common.Hash
	binary.BigEndian.PutUint64(countVal[24:], uint64(len(kinds)))
	db.SetState(registry, gwSlot(addr, "kindsCount"), countVal)

	baseSlot := kindsBaseSlot(addr).Big()
	for i, kind := range kinds {
		var val common.Hash
		val[0] = byte(len(kind))
		copy(val[1:], []byte(kind))
		slot := common.BigToHash(new(big.Int).Add(baseSlot, big.NewInt(int64(i))))
		db.SetState(registry, slot, val)
	}
}

// ---------- Gateway count ----------

// ReadGatewayCount returns the total number of ever-registered gateways.
func ReadGatewayCount(db stateDB) uint64 {
	raw := db.GetState(registry, gwCountSlot)
	return binary.BigEndian.Uint64(raw[24:])
}

// IncrementGatewayCount increments the gateway count by one.
func IncrementGatewayCount(db stateDB) {
	n := ReadGatewayCount(db)
	var val common.Hash
	binary.BigEndian.PutUint64(val[24:], n+1)
	db.SetState(registry, gwCountSlot, val)
}
