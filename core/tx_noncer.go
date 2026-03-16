package core

import (
	"sync"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/priv"
	"github.com/tos-network/gtos/core/state"
	"github.com/tos-network/gtos/core/types"
)

// txNoncer is a tiny virtual state database to manage the executable nonces of
// accounts in the pool, falling back to reading from a real state database if
// an account is unknown.
type txNoncer struct {
	fallback *state.StateDB
	nonces   map[common.Address]uint64
	lock     sync.Mutex
}

// newTxNoncer creates a new virtual state database to track the pool nonces.
func newTxNoncer(statedb *state.StateDB) *txNoncer {
	return &txNoncer{
		fallback: statedb.Copy(),
		nonces:   make(map[common.Address]uint64),
	}
}

// get returns the current nonce of an account, falling back to a real state
// database if the account is unknown.
func (txn *txNoncer) get(addr common.Address) uint64 {
	// We use mutex for get operation is the underlying
	// state will mutate db even for read access.
	txn.lock.Lock()
	defer txn.lock.Unlock()

	if _, ok := txn.nonces[addr]; !ok {
		txn.nonces[addr] = txn.fallback.GetNonce(addr)
	}
	return txn.nonces[addr]
}

// set inserts a new virtual nonce into the virtual state database to be returned
// whenever the pool requests it instead of reaching into the real state database.
func (txn *txNoncer) set(addr common.Address, nonce uint64) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	txn.nonces[addr] = nonce
}

// setIfLower updates a new virtual nonce into the virtual state database if the
// the new one is lower.
func (txn *txNoncer) setIfLower(addr common.Address, nonce uint64) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	if _, ok := txn.nonces[addr]; !ok {
		txn.nonces[addr] = txn.fallback.GetNonce(addr)
	}
	if txn.nonces[addr] <= nonce {
		return
	}
	txn.nonces[addr] = nonce
}

// getForType returns the current nonce of an account, using the appropriate
// nonce source based on the transaction type. All privacy transaction types
// read from the priv storage slot; public transactions use the regular account
// nonce.
func (txn *txNoncer) getForType(addr common.Address, txType byte) uint64 {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	if _, ok := txn.nonces[addr]; !ok {
		switch txType {
		case types.PrivTransferTxType, types.ShieldTxType, types.UnshieldTxType:
			txn.nonces[addr] = priv.GetPrivNonce(txn.fallback, addr)
		default:
			txn.nonces[addr] = txn.fallback.GetNonce(addr)
		}
	}
	return txn.nonces[addr]
}

// setIfLowerForType updates a new virtual nonce if the new one is lower,
// using the appropriate nonce source based on the transaction type for the
// fallback read.
func (txn *txNoncer) setIfLowerForType(addr common.Address, nonce uint64, txType byte) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	if _, ok := txn.nonces[addr]; !ok {
		switch txType {
		case types.PrivTransferTxType, types.ShieldTxType, types.UnshieldTxType:
			txn.nonces[addr] = priv.GetPrivNonce(txn.fallback, addr)
		default:
			txn.nonces[addr] = txn.fallback.GetNonce(addr)
		}
	}
	if txn.nonces[addr] <= nonce {
		return
	}
	txn.nonces[addr] = nonce
}

// setAll sets the nonces for all accounts to the given map.
func (txn *txNoncer) setAll(all map[common.Address]uint64) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	txn.nonces = all
}
