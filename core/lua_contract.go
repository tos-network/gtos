package core

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	lua "github.com/tos-network/gopher-lua"
)

// luaStorageSlot maps a Lua contract storage key to a deterministic EVM storage
// slot, namespaced under "gtos.lua.storage." to avoid collision with setCode
// metadata slots (gtos.setCode.*).
func luaStorageSlot(key string) common.Hash {
	return crypto.Keccak256Hash(append([]byte("gtos.lua.storage."), key...))
}

// applyLua executes the Lua contract stored at the destination address.
//
// Gas model (Phase 2):
//   - L.SetGasLimit(st.gas) caps total VM opcode gas.
//   - After execution, st.gas is decremented by L.GasUsed() (VM opcodes only).
//   - Primitive gas costs (tos.set, tos.get, …) are not yet charged; Phase 3.
//
// State model:
//   - A StateDB snapshot is taken before execution.
//   - Any Lua error (including OOG) reverts all state changes.
//   - msg.Value is transferred to contractAddr before the script runs.
func (st *StateTransition) applyLua(src []byte) error {
	contractAddr := st.to()

	// Snapshot for revert on any error.
	snapshot := st.state.Snapshot()

	// Transfer msg.Value from caller to contract before executing the script,
	// matching EVM semantics (value arrives before code runs).
	if v := st.msg.Value(); v != nil && v.Sign() > 0 {
		if !st.blockCtx.CanTransfer(st.state, st.msg.From(), v) {
			return fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, st.msg.From().Hex())
		}
		st.blockCtx.Transfer(st.state, st.msg.From(), contractAddr, v)
	}

	L := lua.NewState(lua.Options{SkipOpenLibs: false})
	defer L.Close()
	L.SetGasLimit(st.gas)

	// ── "tos" module ──────────────────────────────────────────────────────────
	tosTable := L.NewTable()

	// tos.get(key) → LNumber | LNil
	//   Reads a uint256 value from contract storage. Returns nil if never set.
	L.SetField(tosTable, "get", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val := st.state.GetState(contractAddr, luaStorageSlot(key))
		if val == (common.Hash{}) {
			L.Push(lua.LNil)
			return 1
		}
		n := new(big.Int).SetBytes(val[:])
		L.Push(lua.LNumber(n.Text(10)))
		return 1
	}))

	// tos.set(key, value)
	//   Stores a uint256 value (LNumber or numeric string) in contract storage.
	L.SetField(tosTable, "set", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		var numStr string
		switch v := L.CheckAny(2).(type) {
		case lua.LNumber:
			numStr = string(v)
		case lua.LString:
			numStr = string(v)
		default:
			L.RaiseError("tos.set: value must be a number or numeric string")
		}
		n, ok := new(big.Int).SetString(numStr, 10)
		if !ok || n.Sign() < 0 {
			L.RaiseError("tos.set: invalid uint256 value")
		}
		var slot common.Hash
		n.FillBytes(slot[:])
		st.state.SetState(contractAddr, luaStorageSlot(key), slot)
		return 0
	}))

	// tos.transfer(toAddr, amount)
	//   Sends `amount` wei from the contract's balance to `toAddr`.
	//   `toAddr` is a hex-encoded address string; `amount` is an LNumber (wei).
	L.SetField(tosTable, "transfer", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)
		amountNum := L.CheckNumber(2)
		to := common.HexToAddress(addrHex)
		amount, ok := new(big.Int).SetString(string(amountNum), 10)
		if !ok || amount.Sign() < 0 {
			L.RaiseError("tos.transfer: invalid amount")
		}
		if !st.blockCtx.CanTransfer(st.state, contractAddr, amount) {
			L.RaiseError("tos.transfer: insufficient contract balance")
		}
		st.blockCtx.Transfer(st.state, contractAddr, to, amount)
		return 0
	}))

	// tos.balance(addr) → LNumber  (wei as uint256 string)
	L.SetField(tosTable, "balance", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)
		addr := common.HexToAddress(addrHex)
		bal := st.state.GetBalance(addr)
		if bal == nil {
			L.Push(lua.LNumber("0"))
		} else {
			L.Push(lua.LNumber(bal.Text(10)))
		}
		return 1
	}))

	// tos.caller() → string  (hex address of msg.From)
	L.SetField(tosTable, "caller", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(st.msg.From().Hex()))
		return 1
	}))

	// tos.value() → LNumber  (msg.Value in wei)
	L.SetField(tosTable, "value", L.NewFunction(func(L *lua.LState) int {
		v := st.msg.Value()
		if v == nil || v.Sign() == 0 {
			L.Push(lua.LNumber("0"))
		} else {
			L.Push(lua.LNumber(v.Text(10)))
		}
		return 1
	}))

	// tos.block  (sub-table with block context)
	blockTable := L.NewTable()
	L.SetField(blockTable, "number", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(st.blockCtx.BlockNumber.Text(10)))
		return 1
	}))
	L.SetField(blockTable, "time", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(st.blockCtx.Time.Text(10)))
		return 1
	}))
	L.SetField(blockTable, "coinbase", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(st.blockCtx.Coinbase.Hex()))
		return 1
	}))
	L.SetField(blockTable, "chainid", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(st.chainConfig.ChainID.Text(10)))
		return 1
	}))
	L.SetField(blockTable, "gaslimit", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LNumber(new(big.Int).SetUint64(st.blockCtx.GasLimit).Text(10)))
		return 1
	}))
	L.SetField(blockTable, "basefee", L.NewFunction(func(L *lua.LState) int {
		if st.blockCtx.BaseFee != nil {
			L.Push(lua.LNumber(st.blockCtx.BaseFee.Text(10)))
		} else {
			L.Push(lua.LNumber("0"))
		}
		return 1
	}))
	L.SetField(tosTable, "block", blockTable)

	// tos.tx  (sub-table with transaction context)
	//   tos.tx.origin()   → hex address of the original tx sender (same as caller in TOS)
	//   tos.tx.gasprice() → gas price in wei (LNumber)
	txTable := L.NewTable()
	L.SetField(txTable, "origin", L.NewFunction(func(L *lua.LState) int {
		L.Push(lua.LString(st.msg.From().Hex()))
		return 1
	}))
	L.SetField(txTable, "gasprice", L.NewFunction(func(L *lua.LState) int {
		if st.txPrice != nil {
			L.Push(lua.LNumber(st.txPrice.Text(10)))
		} else {
			L.Push(lua.LNumber("0"))
		}
		return 1
	}))
	L.SetField(tosTable, "tx", txTable)

	// tos.gasleft() → LNumber  (remaining gas units at call time)
	L.SetField(tosTable, "gasleft", L.NewFunction(func(L *lua.LState) int {
		used := L.GasUsed()
		var remaining uint64
		if used < st.gas {
			remaining = st.gas - used
		}
		L.Push(lua.LNumber(new(big.Int).SetUint64(remaining).Text(10)))
		return 1
	}))

	// tos.require(condition, msg)
	//   Halts execution with an error if condition is false or nil.
	L.SetField(tosTable, "require", L.NewFunction(func(L *lua.LState) int {
		cond := L.CheckAny(1)
		message := L.OptString(2, "requirement failed")
		if cond == lua.LNil || cond == lua.LFalse {
			L.RaiseError("tos.require: %s", message)
		}
		return 0
	}))

	// tos.revert(msg)
	//   Explicitly reverts execution with an error message.
	L.SetField(tosTable, "revert", L.NewFunction(func(L *lua.LState) int {
		message := L.OptString(1, "revert")
		L.RaiseError("tos.revert: %s", message)
		return 0
	}))

	// tos.hash(data) → string  (keccak256 of data, hex-encoded)
	L.SetField(tosTable, "hash", L.NewFunction(func(L *lua.LState) int {
		data := L.CheckString(1)
		h := crypto.Keccak256Hash([]byte(data))
		L.Push(lua.LString(h.Hex()))
		return 1
	}))

	L.SetGlobal("tos", tosTable)

	// ── Execute the script ────────────────────────────────────────────────────
	if err := L.DoString(string(src)); err != nil {
		st.state.RevertToSnapshot(snapshot)
		if strings.Contains(err.Error(), "gas limit exceeded") {
			return ErrIntrinsicGas
		}
		return err
	}

	// Deduct VM opcode gas from the remaining allowance.
	gasUsed := L.GasUsed()
	if gasUsed > st.gas {
		st.state.RevertToSnapshot(snapshot)
		return ErrIntrinsicGas
	}
	st.gas -= gasUsed
	return nil
}
