package tosapi

import "github.com/tos-network/gtos/metrics"

var (
	rpcHistoryPrunedMeter = metrics.NewRegisteredMeter("rpc/tos/history_pruned", nil)
)
