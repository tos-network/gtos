package core

import "github.com/tos-network/gtos/metrics"

var (
	ttlCodePrunedMeter = metrics.NewRegisteredMeter("chain/ttlprune/code", nil)
	ttlKVPrunedMeter   = metrics.NewRegisteredMeter("chain/ttlprune/kv", nil)
	ttlCodePruneTimer  = metrics.NewRegisteredTimer("chain/ttlprune/code_time", nil)
	ttlKVPruneTimer    = metrics.NewRegisteredTimer("chain/ttlprune/kv_time", nil)
)
