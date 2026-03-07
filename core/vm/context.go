// Package vm provides the GTOS execution environment.
package vm

import (
	"github.com/tos-network/gtos/common"
	vmtypes "github.com/tos-network/gtos/core/vmtypes"
)

// TVMLogger is the interface for TVM execution loggers (stub, no-op after TVM removal).
type TVMLogger interface {
	CaptureTxStart(gasLimit uint64)
	CaptureTxEnd(restGas uint64)
}

// Config holds configuration options. Kept as a stub after TVM removal.
type Config struct {
	Debug                   bool
	Tracer                  TVMLogger
	NoBaseFee               bool
	EnablePreimageRecording bool
	ExtraEips               []int
}

// Type aliases re-exported from core/vmtypes for backward compatibility.
// All existing code using vm.BlockContext, vm.TxContext, etc. continues to work.

// BlockContext provides auxiliary information for transaction processing.
type BlockContext = vmtypes.BlockContext

// TxContext provides information about a transaction.
type TxContext = vmtypes.TxContext

// CanTransferFunc is the signature of a transfer guard function.
type CanTransferFunc = vmtypes.CanTransferFunc

// TransferFunc is the signature of a transfer function.
type TransferFunc = vmtypes.TransferFunc

// GetHashFunc returns the nth block hash in the blockchain.
type GetHashFunc = vmtypes.GetHashFunc

// ContractRef is a reference to the contract's backing object.
type ContractRef interface {
	Address() common.Address
}

// AccountRef implements ContractRef.
type AccountRef common.Address

// Address casts AccountRef to common.Address.
func (ar AccountRef) Address() common.Address { return (common.Address)(ar) }
