package lvm

import "github.com/tos-network/gtos/common"

// ContractRef is a reference to the contract's backing object.
// Mirrors go-ethereum's core/vm.ContractRef interface.
type ContractRef interface {
	Address() common.Address
}

// ContractAccount implements ContractRef for a plain EOA or contract address.
// Used when there is no parent contract object to reference (top-level tx call).
type ContractAccount common.Address

func (ca ContractAccount) Address() common.Address { return (common.Address)(ca) }
