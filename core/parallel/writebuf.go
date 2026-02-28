package parallel

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
)

// writeBufSnapshot is a point-in-time copy of all overlay maps, used to
// support Snapshot/RevertToSnapshot for Lua contract execution.
type writeBufSnapshot struct {
	balances map[common.Address]*big.Int
	nonces   map[common.Address]uint64
	codes    map[common.Address][]byte
	storage  map[common.Address]map[common.Hash]common.Hash
	created  map[common.Address]bool
	logLen   int
}

// WriteBufStateDB implements vm.StateDB, wrapping a frozen read-only parent snapshot.
// Reads are served from a local overlay first, then the parent.
// Writes go to the local overlay only.
//
// This is used by parallel tx execution: each tx in a level gets its own
// WriteBufStateDB backed by the same frozen snapshot. After execution, the
// overlay is merged into the real statedb serially.
type WriteBufStateDB struct {
	parent   *state.StateDB // frozen snapshot — read-only

	balances map[common.Address]*big.Int
	nonces   map[common.Address]uint64
	codes    map[common.Address][]byte
	storage  map[common.Address]map[common.Hash]common.Hash
	created  map[common.Address]bool

	snapshots []writeBufSnapshot

	// tx context for log attribution
	txHash  common.Hash
	txIndex int
	logs    []*types.Log
}

// NewWriteBufStateDB creates a new overlay backed by parent.
func NewWriteBufStateDB(parent *state.StateDB) *WriteBufStateDB {
	return &WriteBufStateDB{
		parent:  parent,
		balances: make(map[common.Address]*big.Int),
		nonces:   make(map[common.Address]uint64),
		codes:    make(map[common.Address][]byte),
		storage:  make(map[common.Address]map[common.Hash]common.Hash),
		created:  make(map[common.Address]bool),
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
func (b *WriteBufStateDB) Merge(dst *state.StateDB) {
	// Apply balance deltas: overlay stores absolute values; compute delta vs parent.
	for addr, bal := range b.balances {
		parentBal := b.parent.GetBalance(addr)
		delta := new(big.Int).Sub(bal, parentBal)
		if delta.Sign() > 0 {
			dst.AddBalance(addr, delta)
		} else if delta.Sign() < 0 {
			dst.SubBalance(addr, new(big.Int).Neg(delta))
		}
	}
	// Apply nonces (absolute).
	for addr, nonce := range b.nonces {
		dst.SetNonce(addr, nonce)
	}
	// Apply code (absolute).
	for addr, code := range b.codes {
		dst.SetCode(addr, code)
	}
	// Apply storage (absolute).
	for addr, slots := range b.storage {
		for slot, val := range slots {
			dst.SetState(addr, slot, val)
		}
	}
}

// ─── vm.StateDB implementation ───────────────────────────────────────────────

func (b *WriteBufStateDB) GetBalance(addr common.Address) *big.Int {
	if bal, ok := b.balances[addr]; ok {
		return new(big.Int).Set(bal)
	}
	return b.parent.GetBalance(addr)
}

func (b *WriteBufStateDB) AddBalance(addr common.Address, amount *big.Int) {
	cur := b.getBalance(addr)
	b.balances[addr] = new(big.Int).Add(cur, amount)
}

func (b *WriteBufStateDB) SubBalance(addr common.Address, amount *big.Int) {
	cur := b.getBalance(addr)
	b.balances[addr] = new(big.Int).Sub(cur, amount)
}

// getBalance returns the current balance from overlay or parent (no copy).
func (b *WriteBufStateDB) getBalance(addr common.Address) *big.Int {
	if bal, ok := b.balances[addr]; ok {
		return bal
	}
	return b.parent.GetBalance(addr)
}

func (b *WriteBufStateDB) GetNonce(addr common.Address) uint64 {
	if n, ok := b.nonces[addr]; ok {
		return n
	}
	return b.parent.GetNonce(addr)
}

func (b *WriteBufStateDB) SetNonce(addr common.Address, nonce uint64) {
	b.nonces[addr] = nonce
}

func (b *WriteBufStateDB) GetCodeHash(addr common.Address) common.Hash {
	if code, ok := b.codes[addr]; ok {
		if len(code) == 0 {
			return emptyCodeHash
		}
		return crypto.Keccak256Hash(code)
	}
	return b.parent.GetCodeHash(addr)
}

var emptyCodeHash = common.HexToHash("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

func (b *WriteBufStateDB) GetCode(addr common.Address) []byte {
	if code, ok := b.codes[addr]; ok {
		return code
	}
	return b.parent.GetCode(addr)
}

func (b *WriteBufStateDB) SetCode(addr common.Address, code []byte) {
	b.codes[addr] = code
}

func (b *WriteBufStateDB) GetCodeSize(addr common.Address) int {
	return len(b.GetCode(addr))
}

func (b *WriteBufStateDB) GetState(addr common.Address, slot common.Hash) common.Hash {
	if slots, ok := b.storage[addr]; ok {
		if val, ok2 := slots[slot]; ok2 {
			return val
		}
	}
	return b.parent.GetState(addr, slot)
}

func (b *WriteBufStateDB) SetState(addr common.Address, slot common.Hash, val common.Hash) {
	if b.storage[addr] == nil {
		b.storage[addr] = make(map[common.Hash]common.Hash)
	}
	b.storage[addr][slot] = val
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
	b.created[addr] = true
}

func (b *WriteBufStateDB) Exist(addr common.Address) bool {
	if b.created[addr] {
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

func (b *WriteBufStateDB) Suicide(_ common.Address) bool        { return false }
func (b *WriteBufStateDB) HasSuicided(_ common.Address) bool    { return false }
func (b *WriteBufStateDB) AddRefund(_ uint64)                   {}
func (b *WriteBufStateDB) SubRefund(_ uint64)                   {}
func (b *WriteBufStateDB) GetRefund() uint64                    { return 0 }
func (b *WriteBufStateDB) AddPreimage(_ common.Hash, _ []byte)  {}
// Snapshot captures a deep copy of the current overlay state and returns an
// opaque ID that can be passed to RevertToSnapshot. Used by applyLua to undo
// state changes when a Lua contract reverts.
func (b *WriteBufStateDB) Snapshot() int {
	snap := writeBufSnapshot{
		balances: make(map[common.Address]*big.Int, len(b.balances)),
		nonces:   make(map[common.Address]uint64, len(b.nonces)),
		codes:    make(map[common.Address][]byte, len(b.codes)),
		storage:  make(map[common.Address]map[common.Hash]common.Hash, len(b.storage)),
		created:  make(map[common.Address]bool, len(b.created)),
		logLen:   len(b.logs),
	}
	for addr, bal := range b.balances {
		snap.balances[addr] = new(big.Int).Set(bal)
	}
	for addr, n := range b.nonces {
		snap.nonces[addr] = n
	}
	for addr, code := range b.codes {
		cp := make([]byte, len(code))
		copy(cp, code)
		snap.codes[addr] = cp
	}
	for addr, slots := range b.storage {
		snapSlots := make(map[common.Hash]common.Hash, len(slots))
		for k, v := range slots {
			snapSlots[k] = v
		}
		snap.storage[addr] = snapSlots
	}
	for addr, v := range b.created {
		snap.created[addr] = v
	}
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

func (b *WriteBufStateDB) PrepareAccessList(_ common.Address, _ *common.Address, _ []common.Address, _ types.AccessList) {
}
func (b *WriteBufStateDB) AddressInAccessList(_ common.Address) bool { return false }
func (b *WriteBufStateDB) SlotInAccessList(_ common.Address, _ common.Hash) (bool, bool) {
	return false, false
}
func (b *WriteBufStateDB) AddAddressToAccessList(_ common.Address) {}
func (b *WriteBufStateDB) AddSlotToAccessList(_ common.Address, _ common.Hash) {}

func (b *WriteBufStateDB) ForEachStorage(_ common.Address, _ func(common.Hash, common.Hash) bool) error {
	return nil
}

// Compile-time check that WriteBufStateDB implements vm.StateDB.
var _ vm.StateDB = (*WriteBufStateDB)(nil)
