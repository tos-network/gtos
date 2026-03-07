// Package vmtypes contains the shared VM type definitions used by both core/vm
// and domain packages (agent, sysaction, task, etc.). It is kept dependency-free
// from domain packages so that those packages can import it without creating
// import cycles with core/vm (which imports the domain packages via lvm.go).
package vmtypes

import (
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
)

// StateDB is the TVM database interface for full state querying.
type StateDB interface {
	CreateAccount(common.Address)

	SubBalance(common.Address, *big.Int)
	AddBalance(common.Address, *big.Int)
	GetBalance(common.Address) *big.Int

	GetNonce(common.Address) uint64
	SetNonce(common.Address, uint64)

	GetCodeHash(common.Address) common.Hash
	GetCode(common.Address) []byte
	SetCode(common.Address, []byte)
	GetCodeSize(common.Address) int

	AddRefund(uint64)
	SubRefund(uint64)
	GetRefund() uint64

	GetCommittedState(common.Address, common.Hash) common.Hash
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash)

	Suicide(common.Address) bool
	HasSuicided(common.Address) bool

	Exist(common.Address) bool
	Empty(common.Address) bool

	PrepareAccessList(sender common.Address, dest *common.Address, precompiles []common.Address, txAccesses types.AccessList)
	AddressInAccessList(addr common.Address) bool
	SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool)
	AddAddressToAccessList(addr common.Address)
	AddSlotToAccessList(addr common.Address, slot common.Hash)

	RevertToSnapshot(int)
	Snapshot() int

	AddLog(*types.Log)
	Logs() []*types.Log
	AddPreimage(common.Hash, []byte)

	ForEachStorage(common.Address, func(common.Hash, common.Hash) bool) error
}

// BlockContext provides auxiliary information for transaction processing.
type BlockContext struct {
	CanTransfer CanTransferFunc
	Transfer    TransferFunc
	GetHash     GetHashFunc

	Coinbase    common.Address
	GasLimit    uint64
	BlockNumber *big.Int
	Time        *big.Int
	Difficulty  *big.Int
	BaseFee     *big.Int
	Random      *common.Hash
}

// TxContext provides information about a transaction.
type TxContext struct {
	Origin   common.Address
	GasPrice *big.Int
}

// CanTransferFunc is the signature of a transfer guard function.
type CanTransferFunc func(StateDB, common.Address, *big.Int) bool

// TransferFunc is the signature of a transfer function.
type TransferFunc func(StateDB, common.Address, common.Address, *big.Int)

// GetHashFunc returns the nth block hash in the blockchain.
type GetHashFunc func(uint64) common.Hash
