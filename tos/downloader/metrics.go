// Contains the metrics collected by the downloader.

package downloader

import (
	"github.com/tos-network/gtos/metrics"
)

var (
	headerInMeter      = metrics.NewRegisteredMeter("tos/downloader/headers/in", nil)
	headerReqTimer     = metrics.NewRegisteredTimer("tos/downloader/headers/req", nil)
	headerDropMeter    = metrics.NewRegisteredMeter("tos/downloader/headers/drop", nil)
	headerTimeoutMeter = metrics.NewRegisteredMeter("tos/downloader/headers/timeout", nil)

	bodyInMeter      = metrics.NewRegisteredMeter("tos/downloader/bodies/in", nil)
	bodyReqTimer     = metrics.NewRegisteredTimer("tos/downloader/bodies/req", nil)
	bodyDropMeter    = metrics.NewRegisteredMeter("tos/downloader/bodies/drop", nil)
	bodyTimeoutMeter = metrics.NewRegisteredMeter("tos/downloader/bodies/timeout", nil)

	receiptInMeter      = metrics.NewRegisteredMeter("tos/downloader/receipts/in", nil)
	receiptReqTimer     = metrics.NewRegisteredTimer("tos/downloader/receipts/req", nil)
	receiptDropMeter    = metrics.NewRegisteredMeter("tos/downloader/receipts/drop", nil)
	receiptTimeoutMeter = metrics.NewRegisteredMeter("tos/downloader/receipts/timeout", nil)

	throttleCounter = metrics.NewRegisteredCounter("tos/downloader/throttle", nil)
)
