// Package vm provides the GTOS execution environment.
// The TVM interpreter has been removed.
// Execution is now handled via system actions or plain TOS transfers.
package vm

import (
	"math/big"
	"sync/atomic"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
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
	Origin  common.Address
	TxPrice *big.Int
}

// CanTransferFunc is the signature of a transfer guard function.
type CanTransferFunc func(StateDB, common.Address, *big.Int) bool

// TransferFunc is the signature of a transfer function.
type TransferFunc func(StateDB, common.Address, common.Address, *big.Int)

// GetHashFunc returns the nth block hash in the blockchain.
type GetHashFunc func(uint64) common.Hash

// ContractRef is a reference to the contract's backing object.
type ContractRef interface {
	Address() common.Address
}

// AccountRef implements ContractRef.
type AccountRef common.Address

// Address casts AccountRef to common.Address.
func (ar AccountRef) Address() common.Address { return (common.Address)(ar) }

// TVM is a stub after removal of the TVM interpreter.
// All execution now goes through system actions or direct TOS transfers.
type TVM struct {
	Context     BlockContext
	TxContext   TxContext
	StateDB     StateDB
	chainConfig *params.ChainConfig
	chainRules  params.Rules
	Config      Config
	abort       int32 // atomic flag for cancellation
	depth       int
}

// NewTVM returns a new TVM stub.
func NewTVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *TVM {
	return &TVM{
		Context:     blockCtx,
		TxContext:   txCtx,
		StateDB:     statedb,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(blockCtx.BlockNumber, blockCtx.Random != nil),
		Config:      config,
	}
}

// ChainConfig returns the chain configuration.
func (tvm *TVM) ChainConfig() *params.ChainConfig { return tvm.chainConfig }

// Reset resets the TVM with a new transaction context.
func (tvm *TVM) Reset(txCtx TxContext, statedb StateDB) {
	tvm.TxContext = txCtx
	tvm.StateDB = statedb
}

// Cancel sets the cancellation flag atomically.
func (tvm *TVM) Cancel() {
	atomic.StoreInt32(&tvm.abort, 1)
}

// Cancelled reports whether Cancel has been called.
func (tvm *TVM) Cancelled() bool {
	return atomic.LoadInt32(&tvm.abort) == 1
}

// Depth returns the current call depth (always 0 in stub).
func (tvm *TVM) Depth() int { return tvm.depth }

// Call executes a plain value transfer (no bytecode execution).
// Contract calls are not supported in GTOS.
func (tvm *TVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if value != nil && value.Sign() > 0 {
		if !tvm.Context.CanTransfer(tvm.StateDB, caller.Address(), value) {
			return nil, gas, ErrInsufficientBalance
		}
		tvm.Context.Transfer(tvm.StateDB, caller.Address(), addr, value)
	}
	return nil, gas, nil
}

// Create is not supported in GTOS (no smart contract deployment).
func (tvm *TVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	return nil, common.Address{}, gas, ErrExecutionReverted
}

// Create2 is not supported in GTOS.
func (tvm *TVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *common.Hash) ([]byte, common.Address, uint64, error) {
	return nil, common.Address{}, gas, ErrExecutionReverted
}

// StaticCall is not supported in GTOS.
func (tvm *TVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	return nil, gas, ErrExecutionReverted
}
