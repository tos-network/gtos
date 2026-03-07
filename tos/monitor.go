package tos

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/event"
	"github.com/tos-network/gtos/log"
)

type validatorMonitor struct {
	chain                *core.BlockChain
	journalDir           string
	doubleSignEnabled    bool
	maliciousVoteEnabled bool

	stateMu      sync.Mutex
	seenBlocks   map[blockObservationKey]common.Hash
	lastSeenHead uint64
	state        monitorState

	chainCh  chan core.ChainEvent
	sideCh   chan core.ChainSideEvent
	voteCh   chan dpos.VoteMonitorEvent
	quit     chan struct{}
	wg       sync.WaitGroup
	chainSub event.Subscription
	sideSub  event.Subscription
}

type blockObservationKey struct {
	Number uint64
	Miner  common.Address
}

type monitorState struct {
	DoubleSignAlerts    uint64 `json:"doubleSignAlerts"`
	MaliciousVoteAlerts uint64 `json:"maliciousVoteAlerts"`
	LastAlertAtUnix     int64  `json:"lastAlertAtUnix,omitempty"`
	LastAlertKind       string `json:"lastAlertKind,omitempty"`
	LastObservedBlock   uint64 `json:"lastObservedBlock,omitempty"`
}

type monitorEventRecord struct {
	Timestamp string                 `json:"ts"`
	Kind      string                 `json:"kind"`
	Fields    map[string]interface{} `json:"fields"`
}

func newValidatorMonitor(chain *core.BlockChain, journalDir string, doubleSign, maliciousVote bool) *validatorMonitor {
	return &validatorMonitor{
		chain:                chain,
		journalDir:           journalDir,
		doubleSignEnabled:    doubleSign,
		maliciousVoteEnabled: maliciousVote,
		seenBlocks:           make(map[blockObservationKey]common.Hash),
		chainCh:              make(chan core.ChainEvent, 64),
		sideCh:               make(chan core.ChainSideEvent, 64),
		voteCh:               make(chan dpos.VoteMonitorEvent, 64),
		quit:                 make(chan struct{}),
	}
}

func (m *validatorMonitor) Start() error {
	if m == nil {
		return nil
	}
	if err := os.MkdirAll(m.journalDir, 0o755); err != nil {
		return err
	}
	if m.chain != nil && m.doubleSignEnabled {
		m.chainSub = m.chain.SubscribeChainEvent(m.chainCh)
		m.sideSub = m.chain.SubscribeChainSideEvent(m.sideCh)
	}
	m.wg.Add(1)
	go m.loop()
	return nil
}

func (m *validatorMonitor) Stop() error {
	if m == nil {
		return nil
	}
	select {
	case <-m.quit:
		return nil
	default:
		close(m.quit)
	}
	if m.chainSub != nil {
		m.chainSub.Unsubscribe()
	}
	if m.sideSub != nil {
		m.sideSub.Unsubscribe()
	}
	m.wg.Wait()
	return nil
}

func (m *validatorMonitor) HandleVoteEvent(ev dpos.VoteMonitorEvent) {
	if m == nil || !m.maliciousVoteEnabled {
		return
	}
	select {
	case m.voteCh <- ev:
	default:
		log.Warn("Validator monitor dropped vote anomaly event", "number", ev.Number, "signer", ev.Signer, "kind", ev.Kind)
	}
}

func (m *validatorMonitor) loop() {
	defer m.wg.Done()
	for {
		select {
		case ev := <-m.chainCh:
			if ev.Block != nil {
				m.recordBlockObservation("canonical", ev.Block)
			}
		case ev := <-m.sideCh:
			if ev.Block != nil {
				m.recordBlockObservation("side", ev.Block)
			}
		case ev := <-m.voteCh:
			m.recordVoteEvent(ev)
		case <-m.quit:
			return
		case err := <-m.subErr(m.chainSub):
			if err != nil {
				log.Warn("Validator monitor chain subscription terminated", "err", err)
			}
			m.chainSub = nil
		case err := <-m.subErr(m.sideSub):
			if err != nil {
				log.Warn("Validator monitor side-chain subscription terminated", "err", err)
			}
			m.sideSub = nil
		}
	}
}

func (m *validatorMonitor) subErr(sub event.Subscription) <-chan error {
	if sub == nil {
		return nil
	}
	return sub.Err()
}

func (m *validatorMonitor) recordBlockObservation(source string, block *types.Block) {
	if m == nil || !m.doubleSignEnabled || block == nil {
		return
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()

	number := block.NumberU64()
	key := blockObservationKey{Number: number, Miner: block.Coinbase()}
	hash := block.Hash()
	m.state.LastObservedBlock = number
	if number > m.lastSeenHead {
		m.lastSeenHead = number
		m.pruneSeenBlocks(number)
	}
	if previous, ok := m.seenBlocks[key]; ok {
		if previous == hash {
			return
		}
		now := time.Now().UTC()
		m.state.DoubleSignAlerts++
		m.state.LastAlertAtUnix = now.Unix()
		m.state.LastAlertKind = "doublesign"
		record := monitorEventRecord{
			Timestamp: now.Format(time.RFC3339),
			Kind:      "doublesign",
			Fields: map[string]interface{}{
				"source":       source,
				"number":       number,
				"miner":        key.Miner.Hex(),
				"existingHash": previous.Hex(),
				"newHash":      hash.Hex(),
			},
		}
		m.appendEvent("alerts.jsonl", record)
		m.writeState()
		return
	}
	m.seenBlocks[key] = hash
	record := monitorEventRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Kind:      "block_observed",
		Fields: map[string]interface{}{
			"source": source,
			"number": number,
			"miner":  key.Miner.Hex(),
			"hash":   hash.Hex(),
		},
	}
	m.appendEvent("events.jsonl", record)
	m.writeState()
}

func (m *validatorMonitor) recordVoteEvent(ev dpos.VoteMonitorEvent) {
	if m == nil || !m.maliciousVoteEnabled {
		return
	}
	m.stateMu.Lock()
	defer m.stateMu.Unlock()

	now := time.Now().UTC()
	m.state.MaliciousVoteAlerts++
	m.state.LastAlertAtUnix = now.Unix()
	m.state.LastAlertKind = "maliciousvote"
	record := monitorEventRecord{
		Timestamp: now.Format(time.RFC3339),
		Kind:      "maliciousvote",
		Fields: map[string]interface{}{
			"source":       ev.Source,
			"eventKind":    ev.Kind,
			"number":       ev.Number,
			"signer":       ev.Signer.Hex(),
			"existingHash": ev.ExistingHash.Hex(),
			"newHash":      ev.NewHash.Hex(),
		},
	}
	m.appendEvent("alerts.jsonl", record)
	m.writeState()
}

func (m *validatorMonitor) pruneSeenBlocks(head uint64) {
	if head < 2048 {
		return
	}
	minKeep := head - 2048
	for key := range m.seenBlocks {
		if key.Number < minKeep {
			delete(m.seenBlocks, key)
		}
	}
}

func (m *validatorMonitor) appendEvent(name string, record monitorEventRecord) {
	path := filepath.Join(m.journalDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Warn("Validator monitor failed to open journal", "path", path, "err", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(record); err != nil {
		log.Warn("Validator monitor failed to append journal event", "path", path, "err", err)
	}
}

func (m *validatorMonitor) writeState() {
	path := filepath.Join(m.journalDir, "state.json")
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		log.Warn("Validator monitor failed to marshal state", "err", err)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Warn("Validator monitor failed to write state", "path", path, "err", err)
	}
}
