package parallel

import (
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
)

// AnalyzeTx returns the static access set for a transaction message.
// With lazy expiry, SetCode and KV Put write only the sender's own state —
// no shared global index slots — so different-sender txs of these types
// are conflict-free and execute in level 0.
func AnalyzeTx(msg types.Message) AccessSet {
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

	case params.KVRouterAddress:
		// KV Put: writes sender KV slots only.

	case params.PrivacyRouterAddress:
		// UNO transactions are serialized in MVP for deterministic proof/state handling.
		as.WriteAddrs[params.PrivacyRouterAddress] = struct{}{}

	default:
		// Plain TOS transfer: writes recipient balance.
		as.WriteAddrs[*to] = struct{}{}
		as.ReadAddrs[*to] = struct{}{}
	}

	return as
}
