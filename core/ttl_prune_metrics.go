package core

import "github.com/tos-network/gtos/metrics"

var (
	ttlCodePrunedMeter = metrics.NewRegisteredMeter("chain/ttlprune/code", nil)
	ttlKVPrunedMeter   = metrics.NewRegisteredMeter("chain/ttlprune/kv", nil)
)
