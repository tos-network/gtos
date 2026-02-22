package state

import "github.com/tos-network/gtos/metrics"

var (
	accountUpdatedMeter        = metrics.NewRegisteredMeter("state/update/account", nil)
	storageUpdatedMeter        = metrics.NewRegisteredMeter("state/update/storage", nil)
	accountDeletedMeter        = metrics.NewRegisteredMeter("state/delete/account", nil)
	storageDeletedMeter        = metrics.NewRegisteredMeter("state/delete/storage", nil)
	accountTrieCommittedMeter  = metrics.NewRegisteredMeter("state/commit/accountnodes", nil)
	storageTriesCommittedMeter = metrics.NewRegisteredMeter("state/commit/storagenodes", nil)
)
