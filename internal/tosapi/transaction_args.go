package tosapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/tos-network/gtos/accountsigner"
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/common/hexutil"
	"github.com/tos-network/gtos/common/math"
	"github.com/tos-network/gtos/core"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/log"
	"github.com/tos-network/gtos/params"
	"github.com/tos-network/gtos/rpc"
)

// TransactionArgs represents the arguments to construct a new transaction
// or a message call.
type TransactionArgs struct {
	From                 *common.Address `json:"from"`
	To                   *common.Address `json:"to"`
	Gas                  *hexutil.Uint64 `json:"gas"`
	MaxFeePerGas         *hexutil.Big    `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *hexutil.Big    `json:"maxPriorityFeePerGas"`
	Value                *hexutil.Big    `json:"value"`
	Nonce                *hexutil.Uint64 `json:"nonce"`

	// We accept "data" and "input" for backwards-compatibility reasons.
	// "input" is the newer name and should be preferred by clients.
	// Issue detail: https://github.com/tos-network/gtos/issues/15628
	Data  *hexutil.Bytes `json:"data"`
	Input *hexutil.Bytes `json:"input"`

	// Legacy compatibility fields from typed transactions.
	AccessList *types.AccessList `json:"accessList,omitempty"`
	ChainID    *hexutil.Big      `json:"chainId,omitempty"`
	SignerType *string           `json:"signerType,omitempty"`
}

// from retrieves the transaction sender address.
func (args *TransactionArgs) from() common.Address {
	if args.From == nil {
		return common.Address{}
	}
	return *args.From
}

// data retrieves the transaction calldata. Input field is preferred.
func (args *TransactionArgs) data() []byte {
	if args.Input != nil {
		return *args.Input
	}
	if args.Data != nil {
		return *args.Data
	}
	return nil
}

// setDefaults fills in default values for unspecified tx fields.
func (args *TransactionArgs) setDefaults(ctx context.Context, b Backend) error {
	if err := args.setFeeDefaults(ctx, b); err != nil {
		return err
	}
	if args.Value == nil {
		args.Value = new(hexutil.Big)
	}
	if args.Nonce == nil {
		nonce, err := b.GetPoolNonce(ctx, args.from())
		if err != nil {
			return err
		}
		args.Nonce = (*hexutil.Uint64)(&nonce)
	}
	if args.Data != nil && args.Input != nil && !bytes.Equal(*args.Data, *args.Input) {
		return errors.New(`both "data" and "input" are set and not equal. Please use "input" to pass transaction call data`)
	}
	if args.To == nil {
		if len(args.data()) == 0 {
			return errors.New(`contract creation requires non-empty input data`)
		}
	}
	// Estimate the gas usage if necessary.
	if args.Gas == nil {
		// These fields are immutable during the estimation, safe to
		// pass the pointer directly.
		data := args.data()
		callArgs := TransactionArgs{
			From:       args.From,
			To:         args.To,
			Value:      args.Value,
			Data:       (*hexutil.Bytes)(&data),
			AccessList: args.AccessList,
		}
		var estimated hexutil.Uint64
		// Contract calls (non-system address with calldata) require binary-search
		// gas estimation via actual execution, not a static formula.
		if args.To != nil && *args.To != params.SystemActionAddress && *args.To != params.CheckpointSlashIndicatorAddress && len(data) > 0 {
			est, err := DoEstimateGas(ctx, b, callArgs,
				rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber), b.RPCGasCap())
			if err != nil {
				return err
			}
			estimated = est
		} else {
			est, err := estimateStorageFirstGas(callArgs)
			if err != nil {
				return err
			}
			estimated = est
		}
		args.Gas = &estimated
		log.Trace("Estimate gas usage automatically", "gas", args.Gas)
	}
	// If chain id is provided, ensure it matches the local chain id. Otherwise, set the local
	// chain id as the default.
	want := b.ChainConfig().ChainID
	if args.ChainID != nil {
		if have := (*big.Int)(args.ChainID); have.Cmp(want) != 0 {
			return fmt.Errorf("chainId does not match node's (have=%v, want=%v)", have, want)
		}
	} else {
		args.ChainID = (*hexutil.Big)(want)
	}
	if args.SignerType != nil {
		normalized, err := accountsigner.CanonicalSignerType(*args.SignerType)
		if err != nil {
			return fmt.Errorf("invalid signerType: %w", err)
		}
		args.SignerType = &normalized
	} else {
		defaultSignerType := accountsigner.SignerTypeSecp256k1
		args.SignerType = &defaultSignerType
	}
	return nil
}

func estimateStorageFirstGas(args TransactionArgs) (hexutil.Uint64, error) {
	data := args.data()

	var accessList types.AccessList
	if args.AccessList != nil {
		accessList = *args.AccessList
	}
	if args.To == nil {
		// Standard CREATE: intrinsic gas + 200 gas/byte for code storage.
		intrinsic, err := core.IntrinsicGas(data, accessList, true, true, true)
		if err != nil {
			return 0, err
		}
		codeGas := uint64(len(data)) * 200
		if intrinsic > ^uint64(0)-codeGas {
			return 0, core.ErrGasUintOverflow
		}
		return hexutil.Uint64(intrinsic + codeGas), nil
	}
	to := *args.To
	if to == params.SystemActionAddress {
		gas, err := estimateSystemActionGas(data)
		if err != nil {
			return 0, err
		}
		return hexutil.Uint64(gas), nil
	}
	if to == params.CheckpointSlashIndicatorAddress {
		gas, err := estimateCheckpointSlashIndicatorGas(data)
		if err != nil {
			return 0, err
		}
		return hexutil.Uint64(gas), nil
	}
	gas, err := core.IntrinsicGas(nil, accessList, false, true, true)
	if err != nil {
		return 0, err
	}
	return hexutil.Uint64(gas), nil
}

// setFeeDefaults fills in default fee values for unspecified tx fields.
func (args *TransactionArgs) setFeeDefaults(ctx context.Context, b Backend) error {
	_ = ctx
	_ = b
	if args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil {
		return errors.New("maxFeePerGas/maxPriorityFeePerGas are not supported in GTOS")
	}
	return nil
}

// ToMessage converts the transaction arguments to the Message type used by the
// core tvm. This method is used in calls and traces that do not require a real
// live transaction.
func (args *TransactionArgs) ToMessage(globalGasCap uint64, baseFee *big.Int) (types.Message, error) {
	_ = baseFee
	if args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil {
		return types.Message{}, errors.New("maxFeePerGas/maxPriorityFeePerGas are not supported in GTOS")
	}
	// Set sender address or use zero address if none specified.
	addr := args.from()

	// Set default gas if none was set
	gas := globalGasCap
	if gas == 0 {
		gas = uint64(math.MaxUint64 / 2)
	}
	if args.Gas != nil {
		gas = uint64(*args.Gas)
	}
	if globalGasCap != 0 && globalGasCap < gas {
		log.Warn("Caller gas above allowance, capping", "requested", gas, "cap", globalGasCap)
		gas = globalGasCap
	}
	txPrice := params.TxPrice()
	gasFeeCap, gasTipCap := params.TxPrice(), params.TxPrice()
	value := new(big.Int)
	if args.Value != nil {
		value = args.Value.ToInt()
	}
	data := args.data()
	var accessList types.AccessList
	if args.AccessList != nil {
		accessList = *args.AccessList
	}
	msg := types.NewMessage(addr, args.To, 0, value, gas, txPrice, gasFeeCap, gasTipCap, data, accessList, true)
	return msg, nil
}

// toTransaction converts the arguments to a transaction.
// This assumes that setDefaults has been called.
func (args *TransactionArgs) toTransaction() *types.Transaction {
	var accessList types.AccessList
	if args.AccessList != nil {
		accessList = *args.AccessList
	}
	data := &types.SignerTx{
		To:         args.To,
		ChainID:    (*big.Int)(args.ChainID),
		Nonce:      uint64(*args.Nonce),
		Gas:        uint64(*args.Gas),
		Value:      (*big.Int)(args.Value),
		Data:       args.data(),
		AccessList: accessList,
		From:       args.from(),
		SignerType: *args.SignerType,
	}
	return types.NewTx(data)
}

// ToTransaction converts the arguments to a transaction.
// This assumes that setDefaults has been called.
func (args *TransactionArgs) ToTransaction() *types.Transaction {
	return args.toTransaction()
}
