package parallel

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/indexmap"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
)

// writeBufSnapshot is a point-in-time copy of all overlay maps, used to
// support Snapshot/RevertToSnapshot for LVM contract execution.
type writeBufSnapshot struct {
	balances *indexmap.IndexMap[common.Address, *big.Int]
	nonces   *indexmap.IndexMap[common.Address, uint64]
	codes    *indexmap.IndexMap[common.Address, []byte]
	storage  *indexmap.IndexMap[common.Address, *indexmap.IndexMap[common.Hash, common.Hash]]
	created  *indexmap.IndexMap[common.Address, bool]
	logLen   int
}

// WriteBufStateDB implements vm.StateDB, wrapping a frozen read-only parent snapshot.
// Reads are served from a local overlay first, then the parent.
// Writes go to the local overlay only.
//
// This is used by parallel tx execution: each tx in a level gets its own
// WriteBufStateDB backed by the same frozen snapshot. After execution, the
// overlay is merged into the real statedb serially.
//
// All overlay maps use indexmap.IndexMap to guarantee deterministic
// (insertion-order) iteration, eliminating consensus-critical non-determinism
// from Go's built-in map randomised traversal.
type WriteBufStateDB struct {
	parent *state.StateDB // frozen snapshot — read-only

	balances *indexmap.IndexMap[common.Address, *big.Int]
	nonces   *indexmap.IndexMap[common.Address, uint64]
	codes    *indexmap.IndexMap[common.Address, []byte]
	storage  *indexmap.IndexMap[common.Address, *indexmap.IndexMap[common.Hash, common.Hash]]
	created  *indexmap.IndexMap[common.Address, bool]

	snapshots []writeBufSnapshot

	// tx context for log attribution
	txHash  common.Hash
	txIndex int
	logs    []*types.Log

	// per-transaction access list (mirrors state.StateDB.accessList).
	// GTOS has no warm/cold gas distinction, but tracking is kept for
	// serial/parallel consistency and future compatibility.
	alAddrs map[common.Address]bool
	alSlots map[common.Address]map[common.Hash]bool
}

// NewWriteBufStateDB creates a new overlay backed by parent.
func NewWriteBufStateDB(parent *state.StateDB) *WriteBufStateDB {
	return &WriteBufStateDB{
		parent:   parent,
		balances: indexmap.New[common.Address, *big.Int](0),
		nonces:   indexmap.New[common.Address, uint64](0),
		codes:    indexmap.New[common.Address, []byte](0),
		storage:  indexmap.New[common.Address, *indexmap.IndexMap[common.Hash, common.Hash]](0),
		created:  indexmap.New[common.Address, bool](0),
	}
}

// Prepare sets the tx hash and index for log attribution.
func (b *WriteBufStateDB) Prepare(txHash common.Hash, txIndex int) {
	b.txHash = txHash
	b.txIndex = txIndex
}

// Logs returns the logs emitted by this tx.
func (b *WriteBufStateDB) Logs() []*types.Log {
	return b.logs
}

// Merge applies the overlay writes to dst.
// Balances are applied as deltas relative to the parent snapshot, so that
// multiple WriteBufs (each backed by the same parent) can be merged serially
// without overwriting each other.
//
// All iterations use IndexMap.Range which visits entries in deterministic
// (insertion) order, ensuring identical state roots across all nodes.
func (b *WriteBufStateDB) Merge(dst *state.StateDB) {
	// Propagate newly created accounts first, so subsequent balance/nonce/code
	// writes target an account that exists in dst.
	b.created.Range(func(addr common.Address, _ bool) bool {
		dst.CreateAccount(addr)
		return true
	})
	// Apply balance deltas: overlay stores absolute values; compute delta vs parent.
	b.balances.Range(func(addr common.Address, bal *big.Int) bool {
		parentBal := b.parent.GetBalance(addr)
		delta := new(big.Int).Sub(bal, parentBal)
		if delta.Sign() > 0 {
			dst.AddBalance(addr, delta)
		} else if delta.Sign() < 0 {
			dst.SubBalance(addr, new(big.Int).Neg(delta))
		}
		return true
	})
	// Apply nonces (absolute).
	b.nonces.Range(func(addr common.Address, nonce uint64) bool {
		dst.SetNonce(addr, nonce)
		return true
	})
	// Apply code (absolute).
	b.codes.Range(func(addr common.Address, code []byte) bool {
		dst.SetCode(addr, code)
		return true
	})
	// Apply storage (absolute).
	b.storage.Range(func(addr common.Address, slots *indexmap.IndexMap[common.Hash, common.Hash]) bool {
		slots.Range(func(slot common.Hash, val common.Hash) bool {
			dst.SetState(addr, slot, val)
			return true
		})
		return true
	})
}

// ─── vm.StateDB implementation ───────────────────────────────────────────────

func (b *WriteBufStateDB) GetBalance(addr common.Address) *big.Int {
	if bal, ok := b.balances.Get(addr); ok {
		return new(big.Int).Set(bal)
	}
	return b.parent.GetBalance(addr)
}

func (b *WriteBufStateDB) AddBalance(addr common.Address, amount *big.Int) {
	cur := b.getBalance(addr)
	b.balances.Set(addr, new(big.Int).Add(cur, amount))
}

func (b *WriteBufStateDB) SubBalance(addr common.Address, amount *big.Int) {
	cur := b.getBalance(addr)
	b.balances.Set(addr, new(big.Int).Sub(cur, amount))
}

// getBalance returns the current balance from overlay or parent (no copy).
func (b *WriteBufStateDB) getBalance(addr common.Address) *big.Int {
	if bal, ok := b.balances.Get(addr); ok {
		return bal
	}
	return b.parent.GetBalance(addr)
}

func (b *WriteBufStateDB) GetNonce(addr common.Address) uint64 {
	if n, ok := b.nonces.Get(addr); ok {
		return n
	}
	return b.parent.GetNonce(addr)
}

func (b *WriteBufStateDB) SetNonce(addr common.Address, nonce uint64) {
	b.nonces.Set(addr, nonce)
}

func (b *WriteBufStateDB) GetCodeHash(addr common.Address) common.Hash {
	if code, ok := b.codes.Get(addr); ok {
		if len(code) == 0 {
			return emptyCodeHash
		}
		return crypto.Keccak256Hash(code)
	}
	return b.parent.GetCodeHash(addr)
}

var emptyCodeHash = common.HexToHash("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

func (b *WriteBufStateDB) GetCode(addr common.Address) []byte {
	if code, ok := b.codes.Get(addr); ok {
		return code
	}
	return b.parent.GetCode(addr)
}

func (b *WriteBufStateDB) SetCode(addr common.Address, code []byte) {
	b.codes.Set(addr, code)
}

func (b *WriteBufStateDB) GetCodeSize(addr common.Address) int {
	return len(b.GetCode(addr))
}

func (b *WriteBufStateDB) GetState(addr common.Address, slot common.Hash) common.Hash {
	if slots, ok := b.storage.Get(addr); ok {
		if val, ok2 := slots.Get(slot); ok2 {
			return val
		}
	}
	return b.parent.GetState(addr, slot)
}

func (b *WriteBufStateDB) SetState(addr common.Address, slot common.Hash, val common.Hash) {
	slots, ok := b.storage.Get(addr)
	if !ok {
		slots = indexmap.New[common.Hash, common.Hash](0)
		b.storage.Set(addr, slots)
	}
	slots.Set(slot, val)
}

// GetCommittedState always returns the pre-tx (parent) state, ignoring the overlay.
func (b *WriteBufStateDB) GetCommittedState(addr common.Address, slot common.Hash) common.Hash {
	return b.parent.GetCommittedState(addr, slot)
}

func (b *WriteBufStateDB) AddLog(log *types.Log) {
	log.TxHash = b.txHash
	log.TxIndex = uint(b.txIndex)
	b.logs = append(b.logs, log)
}

func (b *WriteBufStateDB) CreateAccount(addr common.Address) {
	b.created.Set(addr, true)
}

func (b *WriteBufStateDB) Exist(addr common.Address) bool {
	if b.created.Has(addr) {
		return true
	}
	return b.parent.Exist(addr)
}

func (b *WriteBufStateDB) Empty(addr common.Address) bool {
	bal := b.getBalance(addr)
	nonce := b.GetNonce(addr)
	code := b.GetCode(addr)
	return bal.Sign() == 0 && nonce == 0 && len(code) == 0
}

// ─── Unused / delegated methods ──────────────────────────────────────────────

func (b *WriteBufStateDB) Suicide(_ common.Address) bool     { panic("WriteBufStateDB: Suicide not supported") }
func (b *WriteBufStateDB) HasSuicided(_ common.Address) bool { panic("WriteBufStateDB: HasSuicided not supported") }
func (b *WriteBufStateDB) AddRefund(_ uint64)                {} // no-op: GTOS LVM has no SSTORE gas refund model
func (b *WriteBufStateDB) SubRefund(_ uint64)                {} // no-op: GTOS LVM has no SSTORE gas refund model
func (b *WriteBufStateDB) GetRefund() uint64                 { return 0 } // no-op: GTOS LVM has no SSTORE gas refund model
func (b *WriteBufStateDB) AddPreimage(_ common.Hash, _ []byte) {}

// Snapshot captures a deep copy of the current overlay state and returns an
// opaque ID that can be passed to RevertToSnapshot. Used by lvm.Call to undo
// state changes when an LVM contract reverts.
func (b *WriteBufStateDB) Snapshot() int {
	snap := writeBufSnapshot{
		balances: indexmap.New[common.Address, *big.Int](b.balances.Len()),
		nonces:   indexmap.New[common.Address, uint64](b.nonces.Len()),
		codes:    indexmap.New[common.Address, []byte](b.codes.Len()),
		storage:  indexmap.New[common.Address, *indexmap.IndexMap[common.Hash, common.Hash]](b.storage.Len()),
		created:  indexmap.New[common.Address, bool](b.created.Len()),
		logLen:   len(b.logs),
	}
	b.balances.Range(func(addr common.Address, bal *big.Int) bool {
		snap.balances.Set(addr, new(big.Int).Set(bal))
		return true
	})
	b.nonces.Range(func(addr common.Address, n uint64) bool {
		snap.nonces.Set(addr, n)
		return true
	})
	b.codes.Range(func(addr common.Address, code []byte) bool {
		cp := make([]byte, len(code))
		copy(cp, code)
		snap.codes.Set(addr, cp)
		return true
	})
	b.storage.Range(func(addr common.Address, slots *indexmap.IndexMap[common.Hash, common.Hash]) bool {
		snapSlots := indexmap.New[common.Hash, common.Hash](slots.Len())
		slots.Range(func(k common.Hash, v common.Hash) bool {
			snapSlots.Set(k, v)
			return true
		})
		snap.storage.Set(addr, snapSlots)
		return true
	})
	b.created.Range(func(addr common.Address, v bool) bool {
		snap.created.Set(addr, v)
		return true
	})
	id := len(b.snapshots)
	b.snapshots = append(b.snapshots, snap)
	return id
}

// RevertToSnapshot restores the overlay to the state captured by Snapshot(id).
// All snapshots taken after id are discarded.
func (b *WriteBufStateDB) RevertToSnapshot(id int) {
	if id >= len(b.snapshots) {
		return
	}
	snap := b.snapshots[id]
	b.balances = snap.balances
	b.nonces = snap.nonces
	b.codes = snap.codes
	b.storage = snap.storage
	b.created = snap.created
	b.logs = b.logs[:snap.logLen]
	b.snapshots = b.snapshots[:id]
}

// ── Per-transaction access list ───────────────────────────────────────────────
//
// GTOS does not use warm/cold gas semantics, so the access list has no
// effect on gas costs.  We track it here anyway so that serial and parallel
// execution produce identical vm.StateDB.AddressInAccessList / SlotInAccessList
// responses, which is required for correctness if any future primitive checks it.
//
// The local maps are per-WriteBufStateDB (one per tx in a parallel level) and
// are never merged back into the parent — consistent with the go-ethereum model
// where access list state is not persisted across blocks.

func (b *WriteBufStateDB) PrepareAccessList(sender common.Address, dst *common.Address, precompiles []common.Address, list types.AccessList) {
	b.alAddrs = make(map[common.Address]bool)
	b.alSlots = make(map[common.Address]map[common.Hash]bool)
	b.AddAddressToAccessList(sender)
	if dst != nil {
		b.AddAddressToAccessList(*dst)
	}
	for _, addr := range precompiles {
		b.AddAddressToAccessList(addr)
	}
	for _, el := range list {
		b.AddAddressToAccessList(el.Address)
		for _, key := range el.StorageKeys {
			b.AddSlotToAccessList(el.Address, key)
		}
	}
}

func (b *WriteBufStateDB) AddressInAccessList(addr common.Address) bool {
	return b.alAddrs[addr]
}

func (b *WriteBufStateDB) SlotInAccessList(addr common.Address, slot common.Hash) (addressPresent bool, slotPresent bool) {
	addressPresent = b.alAddrs[addr]
	if addressPresent && b.alSlots[addr] != nil {
		slotPresent = b.alSlots[addr][slot]
	}
	return
}

func (b *WriteBufStateDB) AddAddressToAccessList(addr common.Address) {
	if b.alAddrs == nil {
		b.alAddrs = make(map[common.Address]bool)
	}
	b.alAddrs[addr] = true
}

func (b *WriteBufStateDB) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	b.AddAddressToAccessList(addr)
	if b.alSlots == nil {
		b.alSlots = make(map[common.Address]map[common.Hash]bool)
	}
	if b.alSlots[addr] == nil {
		b.alSlots[addr] = make(map[common.Hash]bool)
	}
	b.alSlots[addr][slot] = true
}

func (b *WriteBufStateDB) ForEachStorage(_ common.Address, _ func(common.Hash, common.Hash) bool) error {
	panic("WriteBufStateDB: ForEachStorage not supported in parallel execution")
}

// Compile-time check that WriteBufStateDB implements vm.StateDB.
var _ vm.StateDB = (*WriteBufStateDB)(nil)
