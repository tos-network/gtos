package core

import (
	"fmt"
	"strings"

	lvm "github.com/tos-network/gtos/core/lvm"
)

// applyLua executes the Lua contract code (source or bytecode) stored at the
// destination address.
//
// Gas model:
//   - lvm.Execute is capped to st.gas total opcodes (including nested calls).
//   - On success, st.gas is decremented by total opcodes consumed.
//
// State model:
//   - A StateDB snapshot is taken before execution.
//   - Any Lua error (including OOG) reverts all state changes.
//   - msg.Value is transferred to contractAddr before the script runs.
func (st *StateTransition) applyLua(src []byte) error {
	contractAddr := st.to()

	// Snapshot for outer revert on any error.
	snapshot := st.state.Snapshot()

	// Transfer msg.Value from caller to contract before executing the script,
	// matching EVM semantics (value arrives before code runs).
	if v := st.msg.Value(); v != nil && v.Sign() > 0 {
		if !st.blockCtx.CanTransfer(st.state, st.msg.From(), v) {
			return fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, st.msg.From().Hex())
		}
		st.blockCtx.Transfer(st.state, st.msg.From(), contractAddr, v)
	}

	ctx := lvm.CallCtx{
		From:     st.msg.From(),
		To:       contractAddr,
		Value:    st.msg.Value(),
		Data:     st.msg.Data(),
		Depth:    0,
		TxOrigin: st.msg.From(),
		TxPrice:  st.txPrice,
	}

	gasUsed, _, _, err := lvm.Execute(st.state, st.blockCtx, st.chainConfig, ctx, src, st.gas)
	if err != nil {
		st.state.RevertToSnapshot(snapshot)
		if strings.Contains(err.Error(), "gas limit exceeded") {
			return ErrIntrinsicGas
		}
		return err
	}

	if gasUsed > st.gas {
		st.state.RevertToSnapshot(snapshot)
		return ErrIntrinsicGas
	}
	st.gas -= gasUsed
	return nil
}
