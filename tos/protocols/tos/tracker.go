package tos

import (
	"time"

	"github.com/tos-network/gtos/p2p/tracker"
)

// requestTracker is a singleton tracker for tos/66 and newer request times.
var requestTracker = tracker.New(ProtocolName, 5*time.Minute)
