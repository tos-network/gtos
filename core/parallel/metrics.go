package parallel

import "github.com/tos-network/gtos/metrics"

var (
	coinbaseSenderFallbackBlocksMeter = metrics.NewRegisteredMeter("chain/parallel/fallback/coinbase_sender/blocks", nil)
	coinbaseSenderFallbackTxsMeter    = metrics.NewRegisteredMeter("chain/parallel/fallback/coinbase_sender/txs", nil)
)
