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

package core

import (
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/uno"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/kvstore"
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
	txPrice     *big.Int
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

	TxPrice() *big.Int
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

var ErrCodeAlreadyActive = errors.New("active code already exists")

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, accessList types.AccessList, isContractCreation bool, isHomestead, isReducedDataGas bool) (uint64, error) {
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
		if isReducedDataGas {
			nonZeroGas = params.TxDataNonZeroGasReduced
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
		txPrice:     msg.TxPrice(),
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
	mgval = mgval.Mul(mgval, st.txPrice)
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
		// Sender must be an EOA for non-creation transactions.
		// The to==nil path is reserved for setCode payload transactions.
		if st.msg.To() != nil {
			if codeHash := st.state.GetCodeHash(st.msg.From()); codeHash != emptyCodeHash && codeHash != (common.Hash{}) {
				return fmt.Errorf("%w: address %v, codehash: %s", ErrSenderNoEOA,
					st.msg.From().Hex(), codeHash)
			}
		}
	}
	return st.buyGas()
}

// TransitionDb transitions the state by applying the current message.
//
// GTOS transaction rules:
//  1. Contract creation branch (To == nil): reserved for setCode payload transaction.
//  2. System action address (params.SystemActionAddress): execute via sysaction.Execute
//  3. KV router address (params.KVRouterAddress): parse tx.Data and apply KV put directly
//  4. UNO privacy router (params.PrivacyRouterAddress): parse tx.Data and execute UNO action
//  5. Plain TOS transfer (To != nil, empty data, no code at destination): transfer value
//  6. Transactions with non-empty data to other non-system addresses: rejected
func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	if err := st.preCheck(); err != nil {
		return nil, err
	}

	var (
		msg              = st.msg
		contractCreation = msg.To() == nil
	)

	// Increment nonce for all real transactions.
	st.state.SetNonce(msg.From(), st.state.GetNonce(msg.From())+1)

	// Subtract intrinsic gas
	gas, err := IntrinsicGas(st.data, st.msg.AccessList(), contractCreation, true, true)
	if err != nil {
		return nil, err
	}
	if st.gas < gas {
		return nil, fmt.Errorf("%w: have %d, want %d", ErrIntrinsicGas, st.gas, gas)
	}
	st.gas -= gas

	var vmerr error

	if contractCreation {
		vmerr = st.applySetCode(msg)
	} else {
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
		} else if toAddr == params.KVRouterAddress {
			vmerr = st.applyKVPut(msg)
		} else if toAddr == params.PrivacyRouterAddress {
			vmerr = st.applyUNO(msg)
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
				// Destination has contract code: reject (no TVM execution)
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

	// Pay miner fee by fixed txPrice
	effectiveTip := st.txPrice
	fee := new(big.Int).SetUint64(st.gasUsed())
	fee.Mul(fee, effectiveTip)
	st.state.AddBalance(st.blockCtx.Coinbase, fee)

	return &ExecutionResult{
		UsedGas:    st.gasUsed(),
		Err:        vmerr,
		ReturnData: nil,
	}, nil
}

func uint64ToStateWord(v uint64) common.Hash {
	return common.BigToHash(new(big.Int).SetUint64(v))
}

func stateWordToUint64(h common.Hash) uint64 {
	return new(big.Int).SetBytes(h.Bytes()).Uint64()
}

func (st *StateTransition) applySetCode(msg Message) error {
	if msg.Value() != nil && msg.Value().Sign() != 0 {
		return ErrContractNotSupported
	}
	payload, err := DecodeSetCodePayload(st.data)
	if err != nil {
		return ErrContractNotSupported
	}
	if len(payload.Code) > int(params.MaxCodeSize) {
		return ErrContractNotSupported
	}
	currentBlock := st.blockCtx.BlockNumber.Uint64()
	if payload.TTL > math.MaxUint64-currentBlock {
		return ErrContractNotSupported
	}
	from := msg.From()
	expireAt := stateWordToUint64(st.state.GetState(from, SetCodeExpireAtSlot))
	code := st.state.GetCode(from)
	if len(code) > 0 && (expireAt == 0 || currentBlock < expireAt) {
		return ErrCodeAlreadyActive
	}
	ttlGas, err := SetCodeTTLGas(payload.TTL)
	if err != nil {
		return ErrContractNotSupported
	}
	if st.gas < ttlGas {
		return ErrIntrinsicGas
	}
	st.gas -= ttlGas
	st.state.SetCode(from, payload.Code)
	st.state.SetState(from, SetCodeCreatedAtSlot, uint64ToStateWord(currentBlock))
	st.state.SetState(from, SetCodeExpireAtSlot, uint64ToStateWord(currentBlock+payload.TTL))
	return nil
}

func (st *StateTransition) applyKVPut(msg Message) error {
	if msg.Value() != nil && msg.Value().Sign() != 0 {
		return ErrContractNotSupported
	}
	payload, err := kvstore.DecodePutPayload(st.data)
	if err != nil {
		return ErrContractNotSupported
	}
	currentBlock := st.blockCtx.BlockNumber.Uint64()
	if payload.TTL > math.MaxUint64-currentBlock {
		return ErrContractNotSupported
	}
	ttlGas, err := kvstore.KVTTLGas(payload.TTL)
	if err != nil {
		return ErrContractNotSupported
	}
	if st.gas < ttlGas {
		return ErrIntrinsicGas
	}
	st.gas -= ttlGas
	kvstore.Put(st.state, msg.From(), payload.Namespace, payload.Key, payload.Value, currentBlock, currentBlock+payload.TTL)
	return nil
}

func (st *StateTransition) applyUNO(msg Message) error {
	if msg.Value() != nil && msg.Value().Sign() != 0 {
		return ErrContractNotSupported
	}
	if len(st.data) == 0 || len(st.data) > params.UNOMaxPayloadBytes {
		return ErrContractNotSupported
	}
	env, err := uno.DecodeEnvelope(st.data)
	if err != nil {
		return ErrContractNotSupported
	}
	senderPubkey, err := uno.RequireElgamalSigner(st.state, msg.From())
	if err != nil {
		return err
	}

	switch env.Action {
	case uno.ActionShield:
		payload, err := uno.DecodeShieldPayload(env.Body)
		if err != nil || len(payload.ProofBundle) == 0 || len(payload.ProofBundle) > params.UNOMaxProofBytes {
			return ErrContractNotSupported
		}
		chargeGas := params.UNOBaseGas + params.UNOShieldGas
		if st.gas < chargeGas {
			return ErrIntrinsicGas
		}
		st.gas -= chargeGas

		amount := new(big.Int).SetUint64(payload.Amount)
		if !st.blockCtx.CanTransfer(st.state, msg.From(), amount) {
			return fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From().Hex())
		}
		if err := uno.VerifyShieldProofBundle(
			payload.ProofBundle,
			payload.NewSender.Commitment[:],
			payload.NewSender.Handle[:],
			senderPubkey,
			payload.Amount,
		); err != nil {
			return err
		}

		senderState := uno.GetAccountState(st.state, msg.From())
		nextSenderCiphertext, err := uno.AddCiphertexts(senderState.Ciphertext, payload.NewSender)
		if err != nil {
			return err
		}
		if senderState.Version == math.MaxUint64 {
			return uno.ErrVersionOverflow
		}

		st.state.SubBalance(msg.From(), amount)
		senderState.Ciphertext = nextSenderCiphertext
		senderState.Version++
		uno.SetAccountState(st.state, msg.From(), senderState)
		return nil
	case uno.ActionTransfer:
		payload, err := uno.DecodeTransferPayload(env.Body)
		if err != nil || len(payload.ProofBundle) == 0 || len(payload.ProofBundle) > params.UNOMaxProofBytes {
			return ErrContractNotSupported
		}
		receiverPubkey, err := uno.RequireElgamalSigner(st.state, payload.To)
		if err != nil {
			return err
		}
		chargeGas := params.UNOBaseGas + params.UNOTransferGas
		if st.gas < chargeGas {
			return ErrIntrinsicGas
		}
		st.gas -= chargeGas

		senderState := uno.GetAccountState(st.state, msg.From())
		receiverState := uno.GetAccountState(st.state, payload.To)
		if senderState.Version == math.MaxUint64 || receiverState.Version == math.MaxUint64 {
			return uno.ErrVersionOverflow
		}
		senderDelta, err := uno.SubCiphertexts(senderState.Ciphertext, payload.NewSender)
		if err != nil {
			return err
		}
		if err := uno.VerifyTransferProofBundle(payload.ProofBundle, senderDelta, payload.ReceiverDelta, senderPubkey, receiverPubkey); err != nil {
			return err
		}
		nextReceiverCiphertext, err := uno.AddCiphertexts(receiverState.Ciphertext, payload.ReceiverDelta)
		if err != nil {
			return err
		}

		senderState.Ciphertext = payload.NewSender
		senderState.Version++
		receiverState.Ciphertext = nextReceiverCiphertext
		receiverState.Version++
		uno.SetAccountState(st.state, msg.From(), senderState)
		uno.SetAccountState(st.state, payload.To, receiverState)
		return nil
	case uno.ActionUnshield:
		payload, err := uno.DecodeUnshieldPayload(env.Body)
		if err != nil || len(payload.ProofBundle) == 0 || len(payload.ProofBundle) > params.UNOMaxProofBytes {
			return ErrContractNotSupported
		}
		chargeGas := params.UNOBaseGas + params.UNOUnshieldGas
		if st.gas < chargeGas {
			return ErrIntrinsicGas
		}
		st.gas -= chargeGas

		senderState := uno.GetAccountState(st.state, msg.From())
		if senderState.Version == math.MaxUint64 {
			return uno.ErrVersionOverflow
		}
		senderDelta, err := uno.SubCiphertexts(senderState.Ciphertext, payload.NewSender)
		if err != nil {
			return err
		}
		if err := uno.VerifyUnshieldProofBundle(payload.ProofBundle, senderDelta, senderPubkey, payload.Amount); err != nil {
			return err
		}

		senderState.Ciphertext = payload.NewSender
		senderState.Version++
		uno.SetAccountState(st.state, msg.From(), senderState)
		st.state.AddBalance(payload.To, new(big.Int).SetUint64(payload.Amount))
		return nil
	default:
		return ErrContractNotSupported
	}
}

func (st *StateTransition) refundGas(refundQuotient uint64) {
	refund := st.gasUsed() / refundQuotient
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.txPrice)
	st.state.AddBalance(st.msg.From(), remaining)

	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
