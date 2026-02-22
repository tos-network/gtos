package consensus

import (
	"fmt"
	"sync"

	"github.com/tos-network/gtos/core/rawdb"
	"github.com/tos-network/gtos/log"
	"github.com/tos-network/gtos/rlp"
	"github.com/tos-network/gtos/tosdb"
)

// transitionStatus describes the status of tos1/2 transition. This switch
// between modes is a one-way action which is triggered by corresponding
// consensus-layer message.
type transitionStatus struct {
	LeftPoW    bool // The flag is set when the first NewHead message received
	EnteredPoS bool // The flag is set when the first FinalisedBlock message received
}

// Merger is an internal help structure used to track the tos1/2 transition status.
// It's a common structure can be used in both full node and light client.
type Merger struct {
	db     tosdb.KeyValueStore
	status transitionStatus
	mu     sync.RWMutex
}

// NewMerger creates a new Merger which stores its transition status in the provided db.
func NewMerger(db tosdb.KeyValueStore) *Merger {
	var status transitionStatus
	blob := rawdb.ReadTransitionStatus(db)
	if len(blob) != 0 {
		if err := rlp.DecodeBytes(blob, &status); err != nil {
			log.Crit("Failed to decode the transition status", "err", err)
		}
	}
	return &Merger{
		db:     db,
		status: status,
	}
}

// ReachTTD is called whenever the first NewHead message received
// from the consensus-layer.
func (m *Merger) ReachTTD() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status.LeftPoW {
		return
	}
	m.status = transitionStatus{LeftPoW: true}
	blob, err := rlp.EncodeToBytes(m.status)
	if err != nil {
		panic(fmt.Sprintf("Failed to encode the transition status: %v", err))
	}
	rawdb.WriteTransitionStatus(m.db, blob)
	log.Info("Left PoW stage")
}

// FinalizePoS is called whenever the first FinalisedBlock message received
// from the consensus-layer.
func (m *Merger) FinalizePoS() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.status.EnteredPoS {
		return
	}
	m.status = transitionStatus{LeftPoW: true, EnteredPoS: true}
	blob, err := rlp.EncodeToBytes(m.status)
	if err != nil {
		panic(fmt.Sprintf("Failed to encode the transition status: %v", err))
	}
	rawdb.WriteTransitionStatus(m.db, blob)
	log.Info("Entered PoS stage")
}

// TDDReached reports whether the chain has left the PoW stage.
func (m *Merger) TDDReached() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.status.LeftPoW
}

// PoSFinalized reports whether the chain has entered the PoS stage.
func (m *Merger) PoSFinalized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.status.EnteredPoS
}
