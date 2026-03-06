package kyc

import (
	"encoding/binary"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

func kycSlot(addr common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(
		append([]byte("kyc\x00"), addr.Bytes()...)))
}

func readPacked(db vm.StateDB, addr common.Address) (level uint16, status KycStatus) {
	raw := db.GetState(params.KYCRegistryAddress, kycSlot(addr))
	level = binary.BigEndian.Uint16(raw[29:31])
	status = KycStatus(raw[31])
	return
}

func writePacked(db vm.StateDB, addr common.Address, level uint16, status KycStatus) {
	var val common.Hash
	binary.BigEndian.PutUint16(val[29:31], level)
	val[31] = byte(status)
	db.SetState(params.KYCRegistryAddress, kycSlot(addr), val)
}

// ReadLevel returns the KYC level bitmask for addr.
func ReadLevel(db vm.StateDB, addr common.Address) uint16 {
	level, _ := readPacked(db, addr)
	return level
}

// ReadStatus returns the KYC status for addr.
func ReadStatus(db vm.StateDB, addr common.Address) KycStatus {
	_, status := readPacked(db, addr)
	return status
}

// WriteKYC writes level and status into the packed slot.
func WriteKYC(db vm.StateDB, addr common.Address, level uint16, status KycStatus) {
	writePacked(db, addr, level, status)
}

// MeetsLevel returns true if addr has active KYC and (level & required) == required.
func MeetsLevel(db vm.StateDB, addr common.Address, required uint16) bool {
	level, status := readPacked(db, addr)
	return status == KycActive && (level&required) == required
}
