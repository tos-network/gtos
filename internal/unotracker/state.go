package unotracker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type State struct {
	Address     string `json:"address"`
	Balance     uint64 `json:"balance"`
	Version     uint64 `json:"version"`
	BlockNumber uint64 `json:"blockNumber"`
	UpdatedAt   string `json:"updatedAt"`
}

func Load(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out State
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode tracker state: %w", err)
	}
	return &out, nil
}

func Validate(prev *State, curr State, allowReorg bool) error {
	if prev == nil {
		return nil
	}
	if prev.Address != "" && !strings.EqualFold(prev.Address, curr.Address) {
		return fmt.Errorf("tracker address mismatch: file=%s rpc=%s", prev.Address, curr.Address)
	}
	if curr.BlockNumber < prev.BlockNumber {
		if allowReorg {
			return nil
		}
		return fmt.Errorf("reorg detected: block moved backward %d -> %d (use --track-accept-reorg to accept)", prev.BlockNumber, curr.BlockNumber)
	}
	if curr.Version < prev.Version {
		if allowReorg {
			return nil
		}
		return fmt.Errorf("version moved backward %d -> %d (use --track-accept-reorg to accept)", prev.Version, curr.Version)
	}
	return nil
}

func Save(path string, curr State) error {
	curr.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(curr, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
