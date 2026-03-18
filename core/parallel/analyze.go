package parallel

import (
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
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

	// SEC-3: Sponsored transactions read/write the sponsor's nonce slot at
	// SponsorRegistryAddress. Two txs sharing the same sponsor must not run
	// in the same parallel level, otherwise both read the same nonce and
	// produce a divergent state root.
	if sponsor := msg.Sponsor(); sponsor != (common.Address{}) {
		nonceSlot := crypto.Keccak256Hash([]byte("tos.sponsor.nonce"), sponsor.Bytes())
		if as.WriteSlots[params.SponsorRegistryAddress] == nil {
			as.WriteSlots[params.SponsorRegistryAddress] = make(map[common.Hash]struct{})
		}
		as.WriteSlots[params.SponsorRegistryAddress][nonceSlot] = struct{}{}
	}

	// PrivTransferTx: read/write both sender and receiver priv-account addresses.
	// Serialized in MVP via PrivacyRouterAddress for deterministic
	// proof/state handling.
	if msg.Type() == types.PrivTransferTxType {
		toAddr := msg.To()
		as.ReadAddrs[sender] = struct{}{}
		if toAddr != nil {
			as.WriteAddrs[*toAddr] = struct{}{}
			as.ReadAddrs[*toAddr] = struct{}{}
		}
		// Serialize with other privacy txs.
		as.WriteAddrs[params.PrivacyRouterAddress] = struct{}{}
		as.ReadAddrs[params.LVMSerialAddress] = struct{}{}
		return as
	}

	to := msg.To()
	if to == nil {
		// CREATE: derive the deterministic contract address (sender, nonce) so that
		// a subsequent CALL to that address is detected as a write-set conflict and
		// placed in a later execution level — never parallelised with this CREATE.
		// Also inject LVMSerialAddress to serialise with other LVM contract calls,
		// since the constructor executes arbitrary code with unknown cross-contract
		// storage effects.
		contractAddr := crypto.CreateAddress(sender, msg.Nonce())
		as.WriteAddrs[contractAddr] = struct{}{}
		as.ReadAddrs[contractAddr] = struct{}{}
		as.WriteAddrs[params.LVMSerialAddress] = struct{}{}
		return as
	}

	switch *to {
	case params.SystemActionAddress:
		// System actions can mutate or query multiple native registries (lease,
		// policy wallet, tasks, agent/capability state, etc.) that are not fully
		// captured by static decoding. Conservatively serialize them with all
		// normal/LVM txs via LVMSerialAddress to preserve batch/per-tx parity.
		as.WriteAddrs[params.ValidatorRegistryAddress] = struct{}{}
		as.WriteAddrs[params.LVMSerialAddress] = struct{}{}
		if sa, err := sysaction.Decode(msg.Data()); err == nil && sa.Action == sysaction.ActionLeaseDeploy {
			contractAddr := crypto.CreateAddress(sender, msg.Nonce())
			as.WriteAddrs[params.LeaseRegistryAddress] = struct{}{}
			as.WriteAddrs[contractAddr] = struct{}{}
			as.ReadAddrs[contractAddr] = struct{}{}
		}

	case params.CheckpointSlashIndicatorAddress:
		// Slash-indicator execution both mutates its own registry and reads the
		// validator registry to confirm the signer is currently registered.
		// Serialize it with validator-changing system actions and with the wider
		// tx set for deterministic native-state visibility.
		as.WriteAddrs[params.CheckpointSlashIndicatorAddress] = struct{}{}
		as.ReadAddrs[params.ValidatorRegistryAddress] = struct{}{}
		as.WriteAddrs[params.LVMSerialAddress] = struct{}{}

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

		// SEC-2 (runtime dynamic write-set): an LVM contract can call tos.transfer()
		// to any arbitrary address at runtime — a dynamic write not captured in static
		// analysis. To prevent a plain transfer from racing with a concurrent LVM call
		// that transfers to the same recipient, plain transfers READ LVMSerialAddress.
		// Since all LVM calls WRITE LVMSerialAddress, conflict detection forces any
		// plain transfer into a later level than any concurrent LVM call.
		as.ReadAddrs[params.LVMSerialAddress] = struct{}{}
	}

	return as
}
