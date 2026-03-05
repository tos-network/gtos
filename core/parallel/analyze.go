package parallel

import (
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
)

// StateReader is the subset of vm.StateDB used by AnalyzeTx to detect
// code-bearing addresses without importing the full vm package.
type StateReader interface {
	GetCodeSize(addr common.Address) int
}

// AnalyzeTx returns the static access set for a transaction message.
//
// statedb is used to detect LVM contract calls: any transaction whose
// destination holds on-chain code is assigned params.LVMSerialAddress as a
// write address, forcing it into a serial execution level (SEC-1 fix).
func AnalyzeTx(msg types.Message, statedb StateReader) AccessSet {
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
		// SetCode: writes sender code and slots only.
		return as
	}

	switch *to {
	case params.SystemActionAddress:
		// System action: conflicts with any other system action via ValidatorRegistryAddress.
		as.WriteAddrs[params.ValidatorRegistryAddress] = struct{}{}

	case params.PrivacyRouterAddress:
		// UNO transactions are serialized in MVP for deterministic proof/state handling.
		as.WriteAddrs[params.PrivacyRouterAddress] = struct{}{}

	default:
		// Plain TOS transfer: writes recipient balance.
		as.WriteAddrs[*to] = struct{}{}
		as.ReadAddrs[*to] = struct{}{}

		// SEC-1: LVM contract calls cannot be statically analyzed for cross-contract
		// storage writes. Serialise any call to a code-bearing address by injecting
		// LVMSerialAddress into the write set so all such transactions fall into the
		// same execution level.
		if statedb != nil && statedb.GetCodeSize(*to) > 0 {
			as.WriteAddrs[params.LVMSerialAddress] = struct{}{}
		}
	}

	return as
}
