package snap

import (
	"time"

	"github.com/tos-network/gtos/p2p/tracker"
)

// requestTracker is a singleton tracker for request times.
var requestTracker = tracker.New(ProtocolName, time.Minute)
