package registry

import (
	"github.com/tos-network/gtos/capability"
	"github.com/tos-network/gtos/common"
)

type capabilityStateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)
}

func IsGovernor(db capabilityStateDB, addr common.Address) bool {
	return capability.HasCapability(db, addr, GovernorCapabilityBit)
}
