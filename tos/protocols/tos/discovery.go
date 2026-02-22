package tos

import (
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/forkid"
	"github.com/tos-network/gtos/p2p/enode"
	"github.com/tos-network/gtos/rlp"
)

// enrEntry is the ENR entry which advertises `tos` protocol on the discovery.
type enrEntry struct {
	ForkID forkid.ID // Fork identifier

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// ENRKey implements enr.Entry.
func (e enrEntry) ENRKey() string {
	return "tos"
}

// StartENRUpdater starts the `tos` ENR updater loop, which listens for chain
// head events and updates the requested node record whenever a fork is passed.
func StartENRUpdater(chain *core.BlockChain, ln *enode.LocalNode) {
	var newHead = make(chan core.ChainHeadEvent, 10)
	sub := chain.SubscribeChainHeadEvent(newHead)

	go func() {
		defer sub.Unsubscribe()
		for {
			select {
			case <-newHead:
				ln.Set(currentENREntry(chain))
			case <-sub.Err():
				// Would be nice to sync with Stop, but there is no
				// good way to do that.
				return
			}
		}
	}()
}

// currentENREntry constructs an `tos` ENR entry based on the current state of the chain.
func currentENREntry(chain *core.BlockChain) *enrEntry {
	return &enrEntry{
		ForkID: forkid.NewID(chain.Config(), chain.Genesis().Hash(), chain.CurrentHeader().Number.Uint64()),
	}
}
