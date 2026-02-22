package core

import (
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/sysaction"
)

var emptyCodeHash = common.HexToHash("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

// StateTransition handles GTOS state transitions.
// Smart contract execution is not supported; only plain TOS transfers and
// system actions are allowed.
type StateTransition struct {
	gp          *GasPool
	msg         Message
	gas         uint64
	gasPrice    *big.Int
	gasFeeCap   *big.Int
	gasTipCap   *big.Int
	initialGas  uint64
	value       *big.Int
	data        []byte
	state       vm.StateDB
	blockCtx    vm.BlockContext
	chainConfig *params.ChainConfig
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	To() *common.Address

	GasPrice() *big.Int
	GasFeeCap() *big.Int
	GasTipCap() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	IsFake() bool
	Data() []byte
	AccessList() types.AccessList
}

// ExecutionResult includes all output after executing a given message.
type ExecutionResult struct {
	UsedGas    uint64 // Total used gas (including refunded gas)
	Err        error  // Any error encountered during execution
	ReturnData []byte // Returned data
}

// Unwrap returns the internal error.
func (result *ExecutionResult) Unwrap() error {
	return result.Err
}

// Failed returns true if the execution failed.
func (result *ExecutionResult) Failed() bool { return result.Err != nil }

// Return returns the data after execution if no error occurred.
func (result *ExecutionResult) Return() []byte {
	if result.Err != nil {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// Revert returns the revert reason if the execution was reverted.
func (result *ExecutionResult) Revert() []byte {
	if result.Err != vm.ErrExecutionReverted {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// ErrContractNotSupported is returned when a transaction attempts to deploy or
// call a smart contract, which is not supported in GTOS.
var ErrContractNotSupported = errors.New("smart contract execution not supported in GTOS")

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, accessList types.AccessList, isContractCreation bool, isHomestead, isEIP2028 bool) (uint64, error) {
	var gas uint64
	if isContractCreation && isHomestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	if len(data) > 0 {
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		nonZeroGas := params.TxDataNonZeroGasFrontier
		if isEIP2028 {
			nonZeroGas = params.TxDataNonZeroGasEIP2028
		}
		if (math.MaxUint64-gas)/nonZeroGas < nz {
			return 0, ErrGasUintOverflow
		}
		gas += nz * nonZeroGas

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, ErrGasUintOverflow
		}
		gas += z * params.TxDataZeroGas
	}
	if accessList != nil {
		gas += uint64(len(accessList)) * params.TxAccessListAddressGas
		gas += uint64(accessList.StorageKeys()) * params.TxAccessListStorageKeyGas
	}
	return gas, nil
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(blockCtx vm.BlockContext, chainConfig *params.ChainConfig, msg Message, gp *GasPool, statedb vm.StateDB) *StateTransition {
	return &StateTransition{
		gp:          gp,
		msg:         msg,
		gasPrice:    msg.GasPrice(),
		gasFeeCap:   msg.GasFeeCap(),
		gasTipCap:   msg.GasTipCap(),
		value:       msg.Value(),
		data:        msg.Data(),
		state:       statedb,
		blockCtx:    blockCtx,
		chainConfig: chainConfig,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
func ApplyMessage(blockCtx vm.BlockContext, chainConfig *params.ChainConfig, msg Message, gp *GasPool, statedb vm.StateDB) (*ExecutionResult, error) {
	return NewStateTransition(blockCtx, chainConfig, msg, gp, statedb).TransitionDb()
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) buyGas() error {
	mgval := new(big.Int).SetUint64(st.msg.Gas())
	mgval = mgval.Mul(mgval, st.gasPrice)
	balanceCheck := mgval
	if st.gasFeeCap != nil {
		balanceCheck = new(big.Int).SetUint64(st.msg.Gas())
		balanceCheck = balanceCheck.Mul(balanceCheck, st.gasFeeCap)
		balanceCheck.Add(balanceCheck, st.value)
	}
	if have, want := st.state.GetBalance(st.msg.From()), balanceCheck; have.Cmp(want) < 0 {
		return fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, st.msg.From().Hex(), have, want)
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.gas += st.msg.Gas()
	st.initialGas = st.msg.Gas()
	st.state.SubBalance(st.msg.From(), mgval)
	return nil
}

func (st *StateTransition) preCheck() error {
	if !st.msg.IsFake() {
		stNonce := st.state.GetNonce(st.msg.From())
		if msgNonce := st.msg.Nonce(); stNonce < msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooHigh,
				st.msg.From().Hex(), msgNonce, stNonce)
		} else if stNonce > msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooLow,
				st.msg.From().Hex(), msgNonce, stNonce)
		} else if stNonce+1 < stNonce {
			return fmt.Errorf("%w: address %v, nonce: %d", ErrNonceMax,
				st.msg.From().Hex(), stNonce)
		}
		// Sender must be an EOA (no contract code)
		if codeHash := st.state.GetCodeHash(st.msg.From()); codeHash != emptyCodeHash && codeHash != (common.Hash{}) {
			return fmt.Errorf("%w: address %v, codehash: %s", ErrSenderNoEOA,
				st.msg.From().Hex(), codeHash)
		}
	}
	return st.buyGas()
}

// TransitionDb transitions the state by applying the current message.
//
// GTOS transaction rules:
//  1. Contract creation (To == nil): rejected
//  2. System action address (params.SystemActionAddress): execute via sysaction.Execute
//  3. Plain TOS transfer (To != nil, empty data, no code at destination): transfer value
//  4. Transactions with non-empty data to non-system addresses: rejected
func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	if err := st.preCheck(); err != nil {
		return nil, err
	}

	var (
		msg              = st.msg
		rules            = st.chainConfig.Rules(st.blockCtx.BlockNumber, st.blockCtx.Random != nil)
		contractCreation = msg.To() == nil
	)

	// Subtract intrinsic gas
	gas, err := IntrinsicGas(st.data, st.msg.AccessList(), contractCreation, rules.IsHomestead, rules.IsIstanbul)
	if err != nil {
		return nil, err
	}
	if st.gas < gas {
		return nil, fmt.Errorf("%w: have %d, want %d", ErrIntrinsicGas, st.gas, gas)
	}
	st.gas -= gas

	var vmerr error

	if contractCreation {
		// Contract creation is not supported in GTOS
		vmerr = ErrContractNotSupported
	} else {
		// Increment nonce
		st.state.SetNonce(msg.From(), st.state.GetNonce(msg.From())+1)

		toAddr := st.to()

		if toAddr == params.SystemActionAddress {
			gasUsed, execErr := sysaction.Execute(msg, st.state, st.blockCtx.BlockNumber, st.chainConfig)
			// Deduct sysaction-specific gas on top of intrinsic gas.
			if st.gas >= gasUsed {
				st.gas -= gasUsed
			} else {
				st.gas = 0
			}
			vmerr = execErr
		} else {
			// Check sender has enough balance for value transfer
			if msg.Value().Sign() > 0 && !st.blockCtx.CanTransfer(st.state, msg.From(), msg.Value()) {
				return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From().Hex())
			}

			toCode := st.state.GetCode(toAddr)

			if len(st.data) > 0 && len(toCode) == 0 {
				// Data with no contract code at destination: reject
				vmerr = ErrContractNotSupported
			} else if len(toCode) > 0 {
				// Destination has contract code: reject (no EVM execution)
				vmerr = ErrContractNotSupported
			} else {
				// Plain TOS transfer
				if msg.Value().Sign() > 0 {
					st.blockCtx.Transfer(st.state, msg.From(), toAddr, msg.Value())
				}
			}
		}
	}

	// Refund gas
	st.refundGas(params.RefundQuotient)

	// Pay miner fee by fixed gasPrice
	effectiveTip := st.gasPrice
	fee := new(big.Int).SetUint64(st.gasUsed())
	fee.Mul(fee, effectiveTip)
	st.state.AddBalance(st.blockCtx.Coinbase, fee)

	return &ExecutionResult{
		UsedGas:    st.gasUsed(),
		Err:        vmerr,
		ReturnData: nil,
	}, nil
}

func (st *StateTransition) refundGas(refundQuotient uint64) {
	refund := st.gasUsed() / refundQuotient
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(st.msg.From(), remaining)

	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
