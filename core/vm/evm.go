// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package vm provides the GTOS execution environment.
// The EVM interpreter has been removed; only precompiled contracts remain.
// Execution is now handled via system actions or plain TOS transfers.
package vm

import (
	"math/big"
	"sync/atomic"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/params"
)

// EVMLogger is the interface for EVM execution loggers (stub, no-op after EVM removal).
type EVMLogger interface {
	CaptureTxStart(gasLimit uint64)
	CaptureTxEnd(restGas uint64)
}

// Config holds configuration options. Kept as a stub after EVM removal.
type Config struct {
	Debug                   bool
	Tracer                  EVMLogger
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
	Origin   common.Address
	GasPrice *big.Int
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

// EVM is a stub after removal of the EVM interpreter.
// All execution now goes through system actions or direct TOS transfers.
type EVM struct {
	Context     BlockContext
	TxContext   TxContext
	StateDB     StateDB
	chainConfig *params.ChainConfig
	chainRules  params.Rules
	Config      Config
	abort       int32 // atomic flag for cancellation
	depth       int
}

// NewEVM returns a new EVM stub.
func NewEVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *EVM {
	return &EVM{
		Context:     blockCtx,
		TxContext:   txCtx,
		StateDB:     statedb,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(blockCtx.BlockNumber, blockCtx.Random != nil),
		Config:      config,
	}
}

// ChainConfig returns the chain configuration.
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

// Reset resets the EVM with a new transaction context.
func (evm *EVM) Reset(txCtx TxContext, statedb StateDB) {
	evm.TxContext = txCtx
	evm.StateDB = statedb
}

// Cancel sets the cancellation flag atomically.
func (evm *EVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

// Cancelled reports whether Cancel has been called.
func (evm *EVM) Cancelled() bool {
	return atomic.LoadInt32(&evm.abort) == 1
}

// Depth returns the current call depth (always 0 in stub).
func (evm *EVM) Depth() int { return evm.depth }

// Call executes a plain value transfer (no bytecode execution).
// Contract calls are not supported in GTOS.
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if value != nil && value.Sign() > 0 {
		if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
			return nil, gas, ErrInsufficientBalance
		}
		evm.Context.Transfer(evm.StateDB, caller.Address(), addr, value)
	}
	return nil, gas, nil
}

// Create is not supported in GTOS (no smart contract deployment).
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	return nil, common.Address{}, gas, ErrExecutionReverted
}

// Create2 is not supported in GTOS.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *common.Hash) ([]byte, common.Address, uint64, error) {
	return nil, common.Address{}, gas, ErrExecutionReverted
}

// StaticCall is not supported in GTOS.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	return nil, gas, ErrExecutionReverted
}
