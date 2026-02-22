package misc

import (
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/params"
)

// VerifyForkHashes verifies that blocks conforming to network hard-forks do have
// the correct hashes, to avoid clients going off on different chains. This is an
// optional feature.
func VerifyForkHashes(config *params.ChainConfig, header *types.Header, uncle bool) error {
	_ = config
	_ = header
	// We don't care about uncles
	if uncle {
		return nil
	}
	// GTOS does not enforce gas-related TIP fork hashes.
	return nil
}
