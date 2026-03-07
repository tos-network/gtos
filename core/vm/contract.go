package vm

import "github.com/tos-network/gtos/common"

// ContractAccount implements ContractRef for a plain EOA or contract address.
// Used when there is no parent contract object to reference (top-level tx call).
type ContractAccount common.Address

func (ca ContractAccount) Address() common.Address { return (common.Address)(ca) }
