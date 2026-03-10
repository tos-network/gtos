package core

import (
	"encoding/binary"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
)

func sponsorNonceSlot(addr common.Address) common.Hash {
	return crypto.Keccak256Hash([]byte("tos.sponsor.nonce"), addr.Bytes())
}

// ReadSponsorNonce returns the current sponsor replay nonce for a sponsor account.
func ReadSponsorNonce(statedb vm.StateDB, sponsor common.Address) uint64 {
	slot := statedb.GetState(params.SponsorRegistryAddress, sponsorNonceSlot(sponsor))
	return binary.BigEndian.Uint64(slot[common.HashLength-8:])
}

func getSponsorNonce(statedb vm.StateDB, sponsor common.Address) uint64 {
	return ReadSponsorNonce(statedb, sponsor)
}

func setSponsorNonce(statedb vm.StateDB, sponsor common.Address, nonce uint64) {
	var encoded common.Hash
	binary.BigEndian.PutUint64(encoded[common.HashLength-8:], nonce)
	statedb.SetState(params.SponsorRegistryAddress, sponsorNonceSlot(sponsor), encoded)
}
