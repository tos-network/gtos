// Package agentidx maintains the in-memory agent capability index by
// consuming chain events and parsing AGENT_* system actions.
//
// It lives in a separate package (not agent/) to avoid an import cycle:
//   agent/ ← registry + types (no core/sysaction dependency)
//   agentidx/ ← imports agent, core, sysaction
package agentidx

import (
	"encoding/json"
	"time"

	"github.com/tos-network/gtos/agent"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/event"
	"github.com/tos-network/gtos/log"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

// BlockChain is the minimal chain interface consumed by Indexer.
// Satisfied by core.BlockChain.
type BlockChain interface {
	SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription
}

// Indexer subscribes to new-chain events and keeps the in-memory Registry
// up to date by parsing AGENT_* system actions from each block.
type Indexer struct {
	chain    BlockChain
	registry *agent.Registry
	quit     chan struct{}
}

// NewIndexer creates an Indexer backed by the given registry.
func NewIndexer(chain BlockChain, registry *agent.Registry) *Indexer {
	return &Indexer{
		chain:    chain,
		registry: registry,
		quit:     make(chan struct{}),
	}
}

// Start begins consuming chain events in a background goroutine.
func (idx *Indexer) Start() {
	go idx.loop()
}

// Stop shuts down the indexer.
func (idx *Indexer) Stop() {
	close(idx.quit)
}

func (idx *Indexer) loop() {
	ch := make(chan core.ChainEvent, 64)
	sub := idx.chain.SubscribeChainEvent(ch)
	defer sub.Unsubscribe()

	for {
		select {
		case ev := <-ch:
			idx.processBlock(ev.Block)
		case err := <-sub.Err():
			log.Warn("Agent indexer chain subscription error", "err", err)
			return
		case <-idx.quit:
			return
		}
	}
}

func (idx *Indexer) processBlock(block *types.Block) {
	for _, tx := range block.Transactions() {
		if tx.To() == nil || *tx.To() != params.SystemActionAddress {
			continue
		}
		sa, err := sysaction.Decode(tx.Data())
		if err != nil {
			continue
		}
		switch sa.Action {
		case sysaction.ActionAgentRegister, sysaction.ActionAgentUpdate:
			idx.handleRegister(sa, block.NumberU64())
		case sysaction.ActionAgentHeartbeat:
			idx.handleHeartbeat(sa)
		}
	}
}

func (idx *Indexer) handleRegister(sa *sysaction.SysAction, blockNum uint64) {
	var p sysaction.AgentRegisterPayload
	if err := sysaction.DecodePayload(sa, &p); err != nil {
		log.Debug("Agent indexer: bad register payload", "err", err)
		return
	}
	if p.AgentID == "" {
		return
	}

	record := agent.AgentRecord{
		RecordVersion:    "1",
		AgentID:          p.AgentID,
		CapabilityDigest: p.Category,
		UpdatedAt:        time.Now().Unix(),
		RegisteredBlock:  blockNum,
	}

	if len(p.Manifest) > 0 {
		var m agent.ToolManifest
		if err := json.Unmarshal(p.Manifest, &m); err == nil {
			if m.AgentID == "" {
				m.AgentID = p.AgentID
			}
			record.ManifestHash = agent.HashManifest(m)
			idx.registry.UpsertManifest(m)
		} else {
			log.Debug("Agent indexer: bad manifest JSON", "err", err)
		}
	}

	idx.registry.Upsert(record)
	log.Debug("Agent indexer: registered agent", "id", p.AgentID, "block", blockNum)
}

func (idx *Indexer) handleHeartbeat(sa *sysaction.SysAction) {
	var p sysaction.AgentHeartbeatPayload
	if err := sysaction.DecodePayload(sa, &p); err != nil || p.AgentID == "" {
		return
	}
	// Touch UpdatedAt to indicate the agent is still active.
	if rec, ok := idx.registry.Get(p.AgentID); ok {
		rec.UpdatedAt = time.Now().Unix()
		idx.registry.Upsert(rec)
	}
}
