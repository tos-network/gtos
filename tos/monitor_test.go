package tos

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/dpos"
	"github.com/tos-network/gtos/core/types"
)

func TestValidatorMonitorDetectsDoubleSign(t *testing.T) {
	dir := t.TempDir()
	monitor := newValidatorMonitor(nil, dir, true, false)
	miner := common.HexToAddress("0x100")

	blockA := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(7),
		Coinbase:   miner,
		ParentHash: common.HexToHash("0xaaa"),
	})
	blockB := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(7),
		Coinbase:   miner,
		ParentHash: common.HexToHash("0xbbb"),
	})

	monitor.recordBlockObservation("canonical", blockA)
	monitor.recordBlockObservation("side", blockB)

	state := readMonitorState(t, filepath.Join(dir, "state.json"))
	if state.DoubleSignAlerts != 1 {
		t.Fatalf("double-sign alerts = %d, want 1", state.DoubleSignAlerts)
	}
	alerts := readTextFile(t, filepath.Join(dir, "alerts.jsonl"))
	if !strings.Contains(alerts, "\"kind\":\"doublesign\"") {
		t.Fatalf("alerts missing doublesign entry: %s", alerts)
	}
}

func TestValidatorMonitorRecordsMaliciousVote(t *testing.T) {
	dir := t.TempDir()
	monitor := newValidatorMonitor(nil, dir, false, true)
	monitor.recordVoteEvent(dpos.VoteMonitorEvent{
		Kind:         "equivocation",
		Source:       "p2p",
		Signer:       common.HexToAddress("0x200"),
		Number:       42,
		ExistingHash: common.HexToHash("0xabc"),
		NewHash:      common.HexToHash("0xdef"),
	})

	state := readMonitorState(t, filepath.Join(dir, "state.json"))
	if state.MaliciousVoteAlerts != 1 {
		t.Fatalf("malicious-vote alerts = %d, want 1", state.MaliciousVoteAlerts)
	}
	alerts := readTextFile(t, filepath.Join(dir, "alerts.jsonl"))
	if !strings.Contains(alerts, "\"kind\":\"maliciousvote\"") {
		t.Fatalf("alerts missing maliciousvote entry: %s", alerts)
	}
}

func readMonitorState(t *testing.T, path string) monitorState {
	t.Helper()
	var state monitorState
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	return state
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %s: %v", path, err)
	}
	return string(data)
}
