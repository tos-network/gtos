package core

import (
	"sync"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/state"
)

// sponsorNoncer is a tiny virtual state database to manage the executable
// sponsor nonces inside the txpool, falling back to sponsor state if a sponsor
// is unknown.
type sponsorNoncer struct {
	fallback *state.StateDB
	nonces   map[common.Address]uint64
	lock     sync.Mutex
}

func newSponsorNoncer(statedb *state.StateDB) *sponsorNoncer {
	return &sponsorNoncer{
		fallback: statedb.Copy(),
		nonces:   make(map[common.Address]uint64),
	}
}

func (sn *sponsorNoncer) get(addr common.Address) uint64 {
	sn.lock.Lock()
	defer sn.lock.Unlock()

	if _, ok := sn.nonces[addr]; !ok {
		sn.nonces[addr] = getSponsorNonce(sn.fallback, addr)
	}
	return sn.nonces[addr]
}

func (sn *sponsorNoncer) set(addr common.Address, nonce uint64) {
	sn.lock.Lock()
	defer sn.lock.Unlock()

	sn.nonces[addr] = nonce
}

func (sn *sponsorNoncer) setIfLower(addr common.Address, nonce uint64) {
	sn.lock.Lock()
	defer sn.lock.Unlock()

	if _, ok := sn.nonces[addr]; !ok {
		sn.nonces[addr] = getSponsorNonce(sn.fallback, addr)
	}
	if sn.nonces[addr] <= nonce {
		return
	}
	sn.nonces[addr] = nonce
}

func (sn *sponsorNoncer) setAll(all map[common.Address]uint64) {
	sn.lock.Lock()
	defer sn.lock.Unlock()

	sn.nonces = all
}
