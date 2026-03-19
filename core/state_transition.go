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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/slashindicator"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/core/vm"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/lease"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/policywallet"
	"github.com/tos-network/gtos/sysaction"
)

var emptyCodeHash = crypto.Keccak256Hash(nil)

// StateTransition handles GTOS state transitions.
// Smart contract execution is not supported; only plain TOS transfers and
// system actions are allowed.
type StateTransition struct {
	gp            *GasPool
	msg           Message
	gas           uint64
	txPrice       *big.Int
	gasFeeCap     *big.Int
	gasTipCap     *big.Int
	initialGas    uint64
	validationGas uint64 // gas consumed by AA validate() — tracked separately from st.gas
	value         *big.Int
	data          []byte
	state         vm.StateDB
	blockCtx      vm.BlockContext
	chainConfig   *params.ChainConfig
	lvm           *vm.LVM
	goCtx         context.Context // RPC timeout context; nil for block-processing
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	Sponsor() common.Address
	To() *common.Address

	TxPrice() *big.Int
	GasFeeCap() *big.Int
	GasTipCap() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	SponsorNonce() uint64
	SponsorExpiry() uint64
	SponsorPolicyHash() common.Hash
	IsSponsored() bool
	IsFake() bool
	Data() []byte
	AccessList() types.AccessList
	Type() byte
	TerminalClass() uint8
	TrustTier() uint8
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

// ErrExecutionAborted is returned when a transaction is interrupted by context
// cancellation or timeout before or during execution of a non-LVM branch
// (SystemAction). The LVM branch signals interruption via the Lua VM
// interrupt channel and surfaces its own error; this sentinel covers the rest.
var ErrExecutionAborted = errors.New("execution aborted")

// ErrAAValidationFailed is returned when an account contract's validate() call
// returns false, reverts, or runs out of gas during the AA two-phase check.
var ErrAAValidationFailed = errors.New("AA: account validation failed")

// aaMarkerSlot is the storage slot set by the TOL compiler in account contract
// constructors to mark the contract as an AA account contract.
// The slot is keccak256("tol.aa.validate").
var aaMarkerSlot = crypto.Keccak256Hash([]byte("tol.aa.validate"))

// validateSelector is the 4-byte ABI selector for validate(bytes32,bytes).
// Precomputed: keccak256("validate(bytes32,bytes)")[:4].
var validateSelector = crypto.Keccak256([]byte("validate(bytes32,bytes)"))[:4]

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
// goCtx is the optional Go context from the originating RPC call; pass
// context.Background() for block-processing paths (no timeout interrupts).
func NewStateTransition(goCtx context.Context, blockCtx vm.BlockContext, chainConfig *params.ChainConfig, msg Message, gp *GasPool, statedb vm.StateDB) *StateTransition {
	txCtx := vm.TxContext{Origin: msg.From(), GasPrice: msg.TxPrice()}
	l := vm.NewLVM(blockCtx, txCtx, statedb, chainConfig)
	l.SetGoCtx(goCtx)
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
		lvm:         l,
		goCtx:       goCtx,
	}
}

// ctxAborted reports whether the caller's Go context has been cancelled or
// timed out. Returns false for block-processing paths (goCtx == nil or
// context.Background()).
func (st *StateTransition) ctxAborted() bool {
	if st.goCtx == nil {
		return false
	}
	select {
	case <-st.goCtx.Done():
		return true
	default:
		return false
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
// goCtx is the caller's Go context; when cancelled the Lua VM aborts on the
// next instruction.  Pass context.Background() for block-processing paths.
func ApplyMessage(goCtx context.Context, blockCtx vm.BlockContext, chainConfig *params.ChainConfig, msg Message, gp *GasPool, statedb vm.StateDB) (*ExecutionResult, error) {
	return NewStateTransition(goCtx, blockCtx, chainConfig, msg, gp, statedb).TransitionDb()
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) gasPayer() common.Address {
	if st.msg != nil && st.msg.IsSponsored() {
		return st.msg.Sponsor()
	}
	return st.msg.From()
}

func (st *StateTransition) buyGas() error {
	mgval := new(big.Int).SetUint64(st.msg.Gas())
	mgval = mgval.Mul(mgval, st.txPrice)
	balanceCheck := mgval
	if st.gasFeeCap != nil {
		balanceCheck = new(big.Int).SetUint64(st.msg.Gas())
		balanceCheck = balanceCheck.Mul(balanceCheck, st.gasFeeCap)
		if !st.msg.IsSponsored() {
			balanceCheck.Add(balanceCheck, st.value)
		}
	}
	payer := st.gasPayer()
	if have, want := st.state.GetBalance(payer), balanceCheck; have.Cmp(want) < 0 {
		return fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, payer.Hex(), have, want)
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.gas += st.msg.Gas()
	st.initialGas = st.msg.Gas()
	st.state.SubBalance(payer, mgval)
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
		if st.msg.IsSponsored() {
			stSponsorNonce := getSponsorNonce(st.state, st.msg.Sponsor())
			if sponsorNonce := st.msg.SponsorNonce(); stSponsorNonce < sponsorNonce {
				return fmt.Errorf("%w: sponsor %v, tx: %d state: %d", ErrNonceTooHigh,
					st.msg.Sponsor().Hex(), sponsorNonce, stSponsorNonce)
			} else if stSponsorNonce > sponsorNonce {
				return fmt.Errorf("%w: sponsor %v, tx: %d state: %d", ErrNonceTooLow,
					st.msg.Sponsor().Hex(), sponsorNonce, stSponsorNonce)
			} else if stSponsorNonce+1 < stSponsorNonce {
				return fmt.Errorf("%w: sponsor %v, nonce: %d", ErrNonceMax,
					st.msg.Sponsor().Hex(), stSponsorNonce)
			}
			if expiry := st.msg.SponsorExpiry(); expiry != 0 && st.blockCtx.Time != nil && st.blockCtx.Time.Sign() > 0 && st.blockCtx.Time.Uint64() > expiry {
				return fmt.Errorf("sponsor authorization expired: sponsor %v expiry %d block_time %d", st.msg.Sponsor().Hex(), expiry, st.blockCtx.Time.Uint64())
			}
		}
		// Sender must always be an EOA — contract addresses have no private key.
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
//  1. LVM contract deployment (To == nil): standard CREATE — derive address, collision-check,
//     charge 200 gas/byte for code storage, set code at the new address.
//  2. System action address (params.SystemActionAddress): execute via sysaction.Execute
//  3. Checkpoint SlashIndicator address (params.CheckpointSlashIndicatorAddress):
//     execute native evidence submission handler
//  4. Plain TOS transfer (To != nil, empty data, no code at destination): transfer value
//  5. Transactions with non-empty data to other non-system addresses: rejected
func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	// PrivTransferTx uses a completely separate fee model: gas=0, no buyGas,
	// no intrinsic-gas check, no refund, no gas-based miner fee.  The fee is
	// handled entirely inside applyPrivTransfer() which credits coinbase
	// directly.  Skip all gas-related pre-checks and post-processing.
	switch st.msg.Type() {
	case types.PrivTransferTxType:
		return st.transitionPrivTransfer()
	case types.ShieldTxType:
		return st.transitionShield()
	case types.UnshieldTxType:
		return st.transitionUnshield()
	}

	if err := st.preCheck(); err != nil {
		return nil, err
	}

	var (
		msg              = st.msg
		contractCreation = msg.To() == nil
		ret              []byte // return data from LVM call, passed through to ExecutionResult
	)

	if !contractCreation && msg.To() != nil {
		if err := st.rejectTombstonedAddress(*msg.To()); err != nil {
			return nil, err
		}
		if st.state.GetCodeSize(*msg.To()) > 0 {
			if err := st.ensureLeaseCallable(*msg.To()); err != nil {
				return nil, err
			}
		}
	}

	// Account Abstraction two-phase: if the destination is an AA account contract,
	// run its validate(txHash, sig) before the nonce increment. On failure the tx
	// is rejected without consuming gas from the caller.
	if !contractCreation && msg.To() != nil && st.isAccountContract(*msg.To()) {
		// Compute tx hash from the raw signed transaction data.
		// chainID is prepended to prevent cross-fork replay: after a fork both
		// chains share the same chainID in the outer signer but the AA contract
		// sees the raw hash; including chainID makes the hash fork-unique.
		var chainIDBuf [32]byte
		if st.chainConfig.ChainID != nil {
			st.chainConfig.ChainID.FillBytes(chainIDBuf[:])
		}
		txHashInput := append(chainIDBuf[:], msg.From().Bytes()...)
		txHashInput = append(txHashInput, msg.To().Bytes()...)
		var nonceBuf [8]byte
		binary.BigEndian.PutUint64(nonceBuf[:], msg.Nonce())
		txHashInput = append(txHashInput, nonceBuf[:]...)
		var gasBuf [8]byte
		binary.BigEndian.PutUint64(gasBuf[:], msg.Gas())
		txHashInput = append(txHashInput, gasBuf[:]...)
		var valueBuf [32]byte
		msg.Value().FillBytes(valueBuf[:])
		txHashInput = append(txHashInput, valueBuf[:]...)
		txHashInput = append(txHashInput, msg.Data()...)
		txHash := crypto.Keccak256Hash(txHashInput)

		// Use the tx signature bytes embedded in msg.Data() as the sig argument.
		// TOL account contracts that implement validate() extract the real sig
		// from calldata themselves; we pass the full calldata as sig here.
		//
		// Snapshot before validate() so any state mutations from a failing
		// validate() call are rolled back. Passing validate() keeps its changes
		// (e.g. replay-prevention counter updates).
		validationSnap := st.state.Snapshot()
		if err := st.validateAccountContract(txHash, msg.Data()); err != nil {
			st.state.RevertToSnapshot(validationSnap)
			return nil, err
		}
	}

	// Warm sender, recipient, and any explicit access-list entries for this transaction.
	// GTOS has no precompiles, so the precompile slice is nil.
	st.state.PrepareAccessList(msg.From(), msg.To(), nil, msg.AccessList())

	// Subtract intrinsic gas (clause 4-5).
	// Nonce is NOT incremented yet — only after all consensus checks pass (mirrors geth).
	gas, err := IntrinsicGas(st.data, st.msg.AccessList(), contractCreation, true, true)
	if err != nil {
		return nil, err
	}
	if st.gas < gas {
		return nil, fmt.Errorf("%w: have %d, want %d", ErrIntrinsicGas, st.gas, gas)
	}
	st.gas -= gas

	// Clause 6 — unified CanTransfer check covering all transaction types (CREATE,
	// CALL, SystemAction).  Mirrors geth's single check before the CREATE/CALL
	// branch.
	if msg.Value().Sign() > 0 && !st.blockCtx.CanTransfer(st.state, msg.From(), msg.Value()) {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From().Hex())
	}
	if msg.IsSponsored() {
		setSponsorNonce(st.state, msg.Sponsor(), getSponsorNonce(st.state, msg.Sponsor())+1)

		// Policy wallet validation: if the sender's account has a policy
		// wallet owner set, enforce the terminal/sponsor policy rules.
		// Accounts without a policy wallet (owner == zero) are unaffected.
		if owner := policywallet.ReadOwner(st.state, msg.From()); owner != (common.Address{}) {
			terminalClass := msg.TerminalClass()
			trustTier := msg.TrustTier()
			// If both are zero (unset), fall back to permissive defaults
			// for backward compatibility: TerminalApp + TrustFull means
			// "no terminal restriction".
			if terminalClass == 0 && trustTier == 0 {
				terminalClass = policywallet.TerminalApp
				trustTier = policywallet.TrustFull
			}
			if err := policywallet.ValidateSponsoredExecution(st.state, msg.From(), msg.Sponsor(), msg.Value(), terminalClass, trustTier); err != nil {
				return nil, err
			}
		}
	}

	var vmerr error

	if contractCreation {
		// For CREATE the sender nonce is incremented inside lvm.Create() — this
		// mirrors geth where evm.Create() calls StateDB.SetNonce(caller, nonce+1).
		// TransitionDb must not touch the nonce here so it is only advanced once
		// and only after all consensus checks above have passed.
		deployPkgBytes, ctorArgs, splitErr := vm.SplitDeployDataAndConstructorArgs(st.data)
		if splitErr != nil {
			// Not a valid .tor package — let Create() produce the proper error.
			deployPkgBytes = st.data
			ctorArgs = nil
		}
		_, st.gas, vmerr = st.lvm.Create(vm.ContractAccount(msg.From()), deployPkgBytes, ctorArgs, st.gas, msg.Value(), st.msg.Nonce())
	} else {
		// Increment sender nonce for all CALL-type transactions (mirrors geth's
		// explicit SetNonce inside the else branch, after all pre-checks pass).
		st.state.SetNonce(msg.From(), st.state.GetNonce(msg.From())+1)

		toAddr := st.to()

		// Check if this is a PrivTransferTx
		if st.msg.Type() == types.PrivTransferTxType {
			if st.ctxAborted() {
				vmerr = ErrExecutionAborted
			} else {
				snap := st.state.Snapshot()
				vmerr = st.applyPrivTransfer()
				if vmerr != nil {
					st.state.RevertToSnapshot(snap)
				}
			}
		} else if toAddr == params.SystemActionAddress {
			if st.ctxAborted() {
				vmerr = ErrExecutionAborted
			} else {
				snap := st.state.Snapshot()
				sa, decErr := sysaction.Decode(msg.Data())
				if decErr != nil {
					if st.gas < params.SysActionGas {
						st.gas = 0
						vmerr = vm.ErrOutOfGas
					} else {
						st.gas -= params.SysActionGas
						vmerr = decErr
					}
				} else if sa.Action == sysaction.ActionLeaseDeploy {
					vmerr = st.executeLeaseDeploy(sa)
				} else if st.gas < params.SysActionGas {
					st.gas = 0
					vmerr = vm.ErrOutOfGas
				} else {
					gasUsed, execErr := sysaction.Execute(msg, st.state, st.blockCtx.BlockNumber, st.chainConfig)
					st.gas -= gasUsed
					vmerr = execErr
				}
				if vmerr != nil {
					st.state.RevertToSnapshot(snap)
				}
			}
		} else if toAddr == params.CheckpointSlashIndicatorAddress {
			if st.ctxAborted() {
				vmerr = ErrExecutionAborted
			} else if st.gas < params.SysActionGas {
				st.gas = 0
				vmerr = vm.ErrOutOfGas
			} else {
				snap := st.state.Snapshot()
				gasUsed, execErr := slashindicator.Execute(msg, st.state, st.blockCtx.BlockNumber, st.chainConfig)
				st.gas -= gasUsed
				vmerr = execErr
				if vmerr != nil {
					st.state.RevertToSnapshot(snap)
				}
			}
		} else {
			toCode := st.state.GetCode(toAddr)

			if len(toCode) > 0 {
				// Destination has LVM contract code: execute it.
				ret, st.gas, vmerr = st.lvm.Call(vm.ContractAccount(msg.From()), toAddr, msg.Data(), st.gas, msg.Value())
			} else {
				// Plain TOS transfer
				if msg.Value().Sign() > 0 {
					st.blockCtx.Transfer(st.state, msg.From(), toAddr, msg.Value())
				}
			}
		}
	}

	// Refund gas — apply strict cap (gasUsed/5).
	st.refundGas(params.RefundQuotientStrict)

	// Pay miner fee by fixed txPrice — skip for simulated calls (DoCall/DoEstimateGas).
	// IsFake() is true for all simulated messages; avoiding the credit prevents
	// spurious coinbase balance changes that break trace/diff outputs.
	if !st.msg.IsFake() {
		effectiveTip := st.txPrice
		fee := new(big.Int).SetUint64(st.gasUsed())
		fee.Mul(fee, effectiveTip)
		st.state.AddBalance(st.blockCtx.Coinbase, fee)
	}

	return &ExecutionResult{
		UsedGas:    st.gasUsed(),
		Err:        vmerr,
		ReturnData: ret,
	}, nil
}

func uint64ToStateWord(v uint64) common.Hash {
	return common.BigToHash(new(big.Int).SetUint64(v))
}

func stateWordToUint64(h common.Hash) uint64 {
	return new(big.Int).SetBytes(h.Bytes()).Uint64()
}

func (st *StateTransition) ensureLeaseCallable(addr common.Address) error {
	if st.blockCtx.BlockNumber == nil {
		return lease.CheckCallable(st.state, addr, 0, st.chainConfig)
	}
	return lease.CheckCallable(st.state, addr, st.blockCtx.BlockNumber.Uint64(), st.chainConfig)
}

func (st *StateTransition) rejectTombstonedAddress(addr common.Address) error {
	return lease.RejectTombstoned(st.state, addr)
}

func (st *StateTransition) executeLeaseDeploy(sa *sysaction.SysAction) error {
	var payload lease.DeployAction
	if err := sysaction.DecodePayload(sa, &payload); err != nil {
		return err
	}
	if len(payload.Code) == 0 {
		return lease.ErrLeaseCodeRequired
	}
	if err := lease.ValidateLeaseBlocks(payload.LeaseBlocks); err != nil {
		return err
	}
	owner := payload.LeaseOwner
	if owner == (common.Address{}) {
		owner = st.msg.From()
	}
	if err := lease.RequireRenewCapableOwner(st.state, owner); err != nil {
		return err
	}

	deployPkgBytes, ctorArgs, splitErr := vm.SplitDeployDataAndConstructorArgs(payload.Code)
	if splitErr != nil {
		deployPkgBytes = payload.Code
		ctorArgs = nil
	}

	deposit, err := lease.DepositFor(uint64(len(deployPkgBytes)), payload.LeaseBlocks)
	if err != nil {
		return err
	}
	if st.state.GetBalance(st.msg.From()).Cmp(deposit) < 0 {
		return lease.ErrLeaseInsufficientDeposit
	}

	currentBlock := uint64(0)
	if st.blockCtx.BlockNumber != nil {
		currentBlock = st.blockCtx.BlockNumber.Uint64()
	}

	if deposit.Sign() > 0 {
		st.state.SubBalance(st.msg.From(), deposit)
		st.state.AddBalance(params.LeaseRegistryAddress, deposit)
	}

	contractAddr, leftOverGas, createErr := st.lvm.CreateLease(
		vm.ContractAccount(st.msg.From()),
		deployPkgBytes,
		ctorArgs,
		st.gas,
		st.msg.Value(),
		st.msg.Nonce(),
	)
	st.gas = leftOverGas
	if createErr != nil {
		return createErr
	}
	_, err = lease.Activate(
		st.state,
		contractAddr,
		owner,
		currentBlock,
		payload.LeaseBlocks,
		uint64(len(deployPkgBytes)),
		deposit,
		st.chainConfig,
	)
	return err
}

// isAccountContract returns true if addr is a TOL account contract.
// TOL account contracts set aaMarkerSlot in their own storage during construction.
func (st *StateTransition) isAccountContract(addr common.Address) bool {
	return st.state.GetState(addr, aaMarkerSlot) != (common.Hash{})
}

// validateAccountContract runs the two-phase AA validation for a call targeting
// an account contract. It calls validate(tx_hash, sig) on the destination contract
// with a hard gas cap of ValidationGasCap.
//
// Phase 1 — pre-flight balance check:
//
//	sender balance must cover ValidationGasCap * txPrice (worst-case validation cost).
//
// Phase 2 — LVM call:
//
//	validate(txHash, sig) is executed with gas cap 50k, Readonly=false.
//	If it returns false, reverts, or runs OOG → ErrAAValidationFailed, no gas charged.
//
// Phase 3 — deduct actual validation gas:
//
//	gasUsed * txPrice is deducted from the sender's balance.
func (st *StateTransition) validateAccountContract(txHash common.Hash, sig []byte) error {
	toAddr := st.to()

	// Phase 1: balance must cover the worst-case validation cost.
	// This prevents DoS via repeated validation attempts with empty accounts.
	worstCaseCost := new(big.Int).Mul(
		new(big.Int).SetUint64(params.ValidationGasCap),
		st.txPrice,
	)
	if st.state.GetBalance(st.gasPayer()).Cmp(worstCaseCost) < 0 {
		return ErrAAValidationFailed
	}

	// Phase 2: encode calldata — validateSelector || abi.encode(bytes32 txHash, bytes sig)
	// Layout: [4 selector][32 txHash][32 offset-to-bytes-arg][32 length][sig padded to 32]
	sigPadded := make([]byte, ((len(sig)+31)/32)*32)
	copy(sigPadded, sig)

	calldata := make([]byte, 0, 4+32+32+32+len(sigPadded))
	calldata = append(calldata, validateSelector...)
	calldata = append(calldata, txHash[:]...)
	// ABI offset for the dynamic `bytes` argument: 64 bytes after the selector.
	var offsetWord [32]byte
	binary.BigEndian.PutUint64(offsetWord[24:], 64)
	calldata = append(calldata, offsetWord[:]...)
	var lenWord [32]byte
	binary.BigEndian.PutUint64(lenWord[24:], uint64(len(sig)))
	calldata = append(calldata, lenWord[:]...)
	calldata = append(calldata, sigPadded...)

	ctx := vm.CallCtx{
		From:     st.msg.From(),
		To:       toAddr,
		Value:    big.NewInt(0),
		Data:     calldata,
		Depth:    0,
		TxOrigin: st.msg.From(),
		TxPrice:  st.txPrice,
		Readonly: false,
		GoCtx:    st.goCtx,
	}
	code := st.state.GetCode(toAddr)
	// Execute validate() against a standalone gas cap (ValidationGasCap).
	//
	// We intentionally do NOT touch st.gp (the per-tx gas pool) here.
	// In the block-processing path, st.gp is a per-tx pool pre-funded with
	// msg.Gas() and already drained by buyGas(), so SubGas(ValidationGasCap)
	// would always fail → ErrAAValidationFailed for every AA tx (Issue 2).
	//
	// Block-level gas accounting for the validation cost is handled by
	// st.validationGas: it is added to st.gasUsed(), which feeds UsedGas in
	// the result, the coinbase fee, and ExecuteParallel's gp.SubGas (Issue 3).
	gasUsed, retData, _, execErr := vm.Execute(st.state, st.blockCtx, st.chainConfig, ctx, code, params.ValidationGasCap)

	if execErr != nil {
		return ErrAAValidationFailed
	}

	// validate() must return a non-zero 32-byte value (truthy bool / bytes32).
	if len(retData) < 32 {
		return ErrAAValidationFailed
	}
	allZero := true
	for _, b := range retData[:32] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ErrAAValidationFailed
	}

	// Phase 3: deduct actual validation gas cost from sender balance and record
	// it so gasUsed() / coinbase-fee / block-gas-pool accounting include it.
	// gasUsed is bounded by ValidationGasCap so this cannot underflow given phase 1.
	actualCost := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), st.txPrice)
	if actualCost.Sign() > 0 {
		st.state.SubBalance(st.gasPayer(), actualCost)
	}
	st.validationGas = gasUsed // included in st.gasUsed() for consistent accounting

	return nil
}

// transitionPrivTransfer handles the full state transition for PrivTransferTx.
// It bypasses the normal gas pipeline (preCheck/buyGas, intrinsicGas,
// refundGas, gas-based miner fee) because PrivTransferTx uses a separate
// plaintext fee model handled inside applyPrivTransfer().
func (st *StateTransition) transitionPrivTransfer() (*ExecutionResult, error) {
	var vmerr error
	if st.ctxAborted() {
		vmerr = ErrExecutionAborted
	} else {
		snap := st.state.Snapshot()
		vmerr = st.applyPrivTransfer()
		if vmerr != nil {
			st.state.RevertToSnapshot(snap)
		}
	}
	return &ExecutionResult{
		UsedGas:    0,
		Err:        vmerr,
		ReturnData: nil,
	}, nil
}

// applyPrivTransfer executes a PrivTransferTx: verifies proofs, updates
// sender/receiver encrypted balances, increments PrivNonce, and credits the
// fee to the block coinbase.
//
// Fee model (aligned with X protocol):
//   - Fee and FeeLimit are plaintext uint64 values
//   - At build time the sender locks FeeLimit into SourceCommitment:
//     new_balance = old_balance - fee_limit - transfer_amount
//   - At execution the validator computes required_fee and refund:
//     refund = fee_limit - actual_fee_paid
//   - Refund is added back via homomorphic scalar addition
func (st *StateTransition) applyPrivTransfer() error {
	tmsg, ok := st.msg.(types.Message)
	if !ok {
		return errors.New("priv: message is not types.Message")
	}
	ptx := tmsg.PrivTransferInner()
	if ptx == nil {
		return errors.New("priv: message does not contain PrivTransferTx")
	}
	feeWei, err := applyPrivTransferState(st.chainConfig.ChainID, st.state, ptx)
	if err != nil {
		return err
	}
	if feeWei != nil && feeWei.Sign() > 0 {
		st.state.AddBalance(st.blockCtx.Coinbase, feeWei)
	}
	return nil
}

// transitionShield handles the full state transition for ShieldTx.
func (st *StateTransition) transitionShield() (*ExecutionResult, error) {
	var vmerr error
	if st.ctxAborted() {
		vmerr = ErrExecutionAborted
	} else {
		snap := st.state.Snapshot()
		vmerr = st.applyShield()
		if vmerr != nil {
			st.state.RevertToSnapshot(snap)
		}
	}
	return &ExecutionResult{
		UsedGas:    0,
		Err:        vmerr,
		ReturnData: nil,
	}, nil
}

// transitionUnshield handles the full state transition for UnshieldTx.
func (st *StateTransition) transitionUnshield() (*ExecutionResult, error) {
	var vmerr error
	if st.ctxAborted() {
		vmerr = ErrExecutionAborted
	} else {
		snap := st.state.Snapshot()
		vmerr = st.applyUnshield()
		if vmerr != nil {
			st.state.RevertToSnapshot(snap)
		}
	}
	return &ExecutionResult{
		UsedGas:    0,
		Err:        vmerr,
		ReturnData: nil,
	}, nil
}

// applyShield executes a ShieldTx: deducts Amount+Fee from sender's public
// balance and adds (Commitment, Handle) to the recipient's encrypted balance.
func (st *StateTransition) applyShield() error {
	tmsg, ok := st.msg.(types.Message)
	if !ok {
		return errors.New("priv: message is not types.Message")
	}
	stx := tmsg.ShieldInner()
	if stx == nil {
		return errors.New("priv: message does not contain ShieldTx")
	}
	feeWei, err := applyShieldState(st.chainConfig.ChainID, st.state, stx)
	if err != nil {
		return err
	}
	if feeWei != nil && feeWei.Sign() > 0 {
		st.state.AddBalance(st.blockCtx.Coinbase, feeWei)
	}
	return nil
}

// applyUnshield executes an UnshieldTx: verifies proofs, updates sender's
// encrypted balance, and credits Amount to recipient's public balance.
// Fee is deducted from the recipient's public balance after crediting Amount.
func (st *StateTransition) applyUnshield() error {
	tmsg, ok := st.msg.(types.Message)
	if !ok {
		return errors.New("priv: message is not types.Message")
	}
	utx := tmsg.UnshieldInner()
	if utx == nil {
		return errors.New("priv: message does not contain UnshieldTx")
	}
	feeWei, err := applyUnshieldState(st.chainConfig.ChainID, st.state, utx)
	if err != nil {
		return err
	}
	if feeWei != nil && feeWei.Sign() > 0 {
		st.state.AddBalance(st.blockCtx.Coinbase, feeWei)
	}
	return nil
}

func (st *StateTransition) refundGas(refundQuotient uint64) {
	refund := st.gasUsed() / refundQuotient
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.txPrice)
	st.state.AddBalance(st.gasPayer(), remaining)

	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition, including
// any gas consumed by an AA validate() call.  AA validation gas is tracked
// separately (st.validationGas) because it is drawn from a standalone gas cap
// rather than from st.gas (which is bounded by msg.Gas()).  Including it here
// ensures UsedGas, coinbase fee, and block gas accounting are all consistent.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas + st.validationGas
}
