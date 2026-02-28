package core

import (
	gosha256 "crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	lua "github.com/tos-network/gopher-lua"
)

// luaMaxCallDepth caps tos.call nesting to prevent stack-overflow DoS.
// Analogous to EVM call depth limit (1024); we use a smaller value since
// Lua call frames are heavier than EVM frames.
const luaMaxCallDepth = 8

// luaCallCtx is the per-invocation execution context for a Lua contract call.
// Top-level calls initialise it from StateTransition.msg; nested tos.call
// invocations override from/to/value/data while keeping txOrigin/txPrice
// constant (they belong to the transaction, not to each call frame).
type luaCallCtx struct {
	from     common.Address // msg.sender visible to this call
	to       common.Address // contract address being executed
	value    *big.Int       // msg.value for this call (nil treated as zero)
	data     []byte         // msg.data (calldata) for this call
	depth    int            // nesting depth (0 = top-level tx call)
	txOrigin common.Address // tx.origin: the original EOA, constant across all levels
	txPrice  *big.Int       // tx.gasprice: constant across all levels
}

// luaParseBigInt extracts a non-negative *big.Int from Lua argument n.
// Accepts LNumber or LString. Raises a Lua error on bad input.
func luaParseBigInt(L *lua.LState, n int) *big.Int {
	var s string
	switch v := L.CheckAny(n).(type) {
	case lua.LNumber:
		s = string(v)
	case lua.LString:
		s = string(v)
	default:
		L.ArgError(n, "expected number or numeric string")
		return nil
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		L.ArgError(n, "invalid integer")
		return nil
	}
	return bi
}

// luaStorageSlot maps a Lua contract storage key to a deterministic EVM storage
// slot, namespaced under "gtos.lua.storage." to avoid collision with setCode
// metadata slots (gtos.setCode.*).
func luaStorageSlot(key string) common.Hash {
	return crypto.Keccak256Hash(append([]byte("gtos.lua.storage."), key...))
}

// luaStrLenSlot returns the slot that holds the byte-length of a string value.
// It is distinct from the uint256 storage namespace ("gtos.lua.storage.").
func luaStrLenSlot(key string) common.Hash {
	return crypto.Keccak256Hash(append([]byte("gtos.lua.str."), key...))
}

// luaStrChunkSlot returns the slot for chunk i (0-based) of a stored string.
// The slot is derived from the base (length) slot and the 4-byte chunk index,
// making it independent of any character in key (no delimiter injection risk).
func luaStrChunkSlot(base common.Hash, i int) common.Hash {
	var b [36]byte
	copy(b[:32], base[:])
	binary.BigEndian.PutUint32(b[32:], uint32(i))
	return crypto.Keccak256Hash(b[:])
}

// luaArrLenSlot returns the slot holding the length of a dynamic uint256 array.
// Namespace "gtos.lua.arr." is distinct from the uint256 ("gtos.lua.storage.")
// and string ("gtos.lua.str.") namespaces.
func luaArrLenSlot(key string) common.Hash {
	return crypto.Keccak256Hash(append([]byte("gtos.lua.arr."), key...))
}

// luaArrElemSlot returns the slot for element i (0-based) of a dynamic array.
// Derived from the length-slot hash and an 8-byte big-endian index, so there
// is no delimiter-injection risk and the mapping is collision-free.
func luaArrElemSlot(base common.Hash, i uint64) common.Hash {
	var b [40]byte
	copy(b[:32], base[:])
	binary.BigEndian.PutUint64(b[32:], i)
	return crypto.Keccak256Hash(b[:])
}

// executeLuaVM runs Lua source code `src` in a fresh Lua state under the given
// call context, limited to `gasLimit` VM opcodes.
//
// Returns (total opcodes consumed including nested calls, execution error).
//
// Callers are responsible for StateDB snapshot/revert; this function does not
// modify snapshot state itself (tos.call takes its own inner snapshot for
// callee isolation).
func executeLuaVM(st *StateTransition, ctx luaCallCtx, src []byte, gasLimit uint64) (uint64, error) {
	contractAddr := ctx.to

	L := lua.NewState(lua.Options{SkipOpenLibs: false})
	defer L.Close()
	L.SetGasLimit(gasLimit)

	// totalChildGas accumulates opcodes consumed by all nested tos.call
	// invocations at this call level (not recursively — each level tracks its
	// own children separately).
	var totalChildGas uint64

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

	// ── Context properties ────────────────────────────────────────────────────
	//
	// All static for this call frame — pre-populated as Lua values, not
	// Go functions, so scripts read them as properties (no parentheses).

	// tos.caller  → string  (hex address of immediate msg.sender)
	L.SetField(tosTable, "caller", lua.LString(ctx.from.Hex()))

	// tos.value  → LNumber  (msg.value in wei)
	{
		v := ctx.value
		if v == nil || v.Sign() == 0 {
			L.SetField(tosTable, "value", lua.LNumber("0"))
		} else {
			L.SetField(tosTable, "value", lua.LNumber(v.Text(10)))
		}
	}

	// tos.block  (sub-table — static block context values)
	blockTable := L.NewTable()
	L.SetField(blockTable, "number", lua.LNumber(st.blockCtx.BlockNumber.Text(10)))
	L.SetField(blockTable, "timestamp", lua.LNumber(st.blockCtx.Time.Text(10)))
	L.SetField(blockTable, "coinbase", lua.LString(st.blockCtx.Coinbase.Hex()))
	L.SetField(blockTable, "chainid", lua.LNumber(st.chainConfig.ChainID.Text(10)))
	L.SetField(blockTable, "gaslimit", lua.LNumber(new(big.Int).SetUint64(st.blockCtx.GasLimit).Text(10)))
	if st.blockCtx.BaseFee != nil {
		L.SetField(blockTable, "basefee", lua.LNumber(st.blockCtx.BaseFee.Text(10)))
	} else {
		L.SetField(blockTable, "basefee", lua.LNumber("0"))
	}
	L.SetField(tosTable, "block", blockTable)

	// tos.tx  (sub-table — tx.origin is the original EOA, constant across frames)
	txTable := L.NewTable()
	L.SetField(txTable, "origin", lua.LString(ctx.txOrigin.Hex()))
	if ctx.txPrice != nil {
		L.SetField(txTable, "gasprice", lua.LNumber(ctx.txPrice.Text(10)))
	} else {
		L.SetField(txTable, "gasprice", lua.LNumber("0"))
	}
	L.SetField(tosTable, "tx", txTable)

	// tos.msg  (sub-table — Solidity-compatible aliases)
	//   msg.sender == tos.caller     (immediate caller for this frame)
	//   msg.value  == tos.value      (value forwarded to this frame)
	//   msg.data   → calldata hex    (this call's calldata)
	//   msg.sig    → first 4 bytes   (function selector)
	msgTable := L.NewTable()
	L.SetField(msgTable, "sender", lua.LString(ctx.from.Hex()))
	{
		v := ctx.value
		if v == nil || v.Sign() == 0 {
			L.SetField(msgTable, "value", lua.LNumber("0"))
		} else {
			L.SetField(msgTable, "value", lua.LNumber(v.Text(10)))
		}
	}
	{
		d := ctx.data
		var msgDataHex string
		if len(d) == 0 {
			msgDataHex = "0x"
		} else {
			msgDataHex = "0x" + common.Bytes2Hex(d)
		}
		L.SetField(msgTable, "data", lua.LString(msgDataHex))
		if len(d) >= 4 {
			L.SetField(msgTable, "sig", lua.LString("0x"+common.Bytes2Hex(d[:4])))
		} else {
			L.SetField(msgTable, "sig", lua.LString("0x"))
		}
	}
	L.SetField(tosTable, "msg", msgTable)

	// tos.abi  (sub-table — Ethereum ABI encode/decode)
	abiTable := L.NewTable()
	L.SetField(abiTable, "encode", L.NewFunction(luaABIEncode))
	L.SetField(abiTable, "encodePacked", L.NewFunction(luaABIEncodePacked))
	L.SetField(abiTable, "decode", L.NewFunction(luaABIDecode))
	L.SetField(tosTable, "abi", abiTable)

	// tos.gasleft() → LNumber
	//   Returns remaining gas at call time, accounting for child gas consumed.
	//   Must be a function because the value changes each opcode.
	L.SetField(tosTable, "gasleft", L.NewFunction(func(L *lua.LState) int {
		used := L.GasUsed() + totalChildGas
		var remaining uint64
		if used < gasLimit {
			remaining = gasLimit - used
		}
		L.Push(lua.LNumber(new(big.Int).SetUint64(remaining).Text(10)))
		return 1
	}))

	// tos.require(condition, msg)
	L.SetField(tosTable, "require", L.NewFunction(func(L *lua.LState) int {
		cond := L.CheckAny(1)
		message := L.OptString(2, "requirement failed")
		if cond == lua.LNil || cond == lua.LFalse {
			L.RaiseError("tos.require: %s", message)
		}
		return 0
	}))

	// tos.revert(msg)
	L.SetField(tosTable, "revert", L.NewFunction(func(L *lua.LState) int {
		message := L.OptString(1, "revert")
		L.RaiseError("tos.revert: %s", message)
		return 0
	}))

	// tos.keccak256(data) → string
	L.SetField(tosTable, "keccak256", L.NewFunction(func(L *lua.LState) int {
		data := L.CheckString(1)
		h := crypto.Keccak256Hash([]byte(data))
		L.Push(lua.LString(h.Hex()))
		return 1
	}))

	// tos.sha256(data) → string
	L.SetField(tosTable, "sha256", L.NewFunction(func(L *lua.LState) int {
		data := L.CheckString(1)
		h := gosha256.Sum256([]byte(data))
		L.Push(lua.LString("0x" + common.Bytes2Hex(h[:])))
		return 1
	}))

	// tos.ecrecover(hash, v, r, s) → string | nil
	L.SetField(tosTable, "ecrecover", L.NewFunction(func(L *lua.LState) int {
		hashHex := L.CheckString(1)
		vNum := uint8(L.CheckInt(2))
		rHex := L.CheckString(3)
		sHex := L.CheckString(4)

		hashBytes := common.FromHex(hashHex)
		rBytes := common.FromHex(rHex)
		sBytes := common.FromHex(sHex)
		if len(hashBytes) != 32 || len(rBytes) != 32 || len(sBytes) != 32 {
			L.Push(lua.LNil)
			return 1
		}
		v := vNum
		if v >= 27 {
			v -= 27
		}
		if v != 0 && v != 1 {
			L.Push(lua.LNil)
			return 1
		}
		sig := make([]byte, 65)
		copy(sig[0:32], rBytes)
		copy(sig[32:64], sBytes)
		sig[64] = v

		pub, err := crypto.SigToPub(hashBytes, sig)
		if err != nil {
			L.Push(lua.LNil)
			return 1
		}
		addr := crypto.PubkeyToAddress(*pub)
		L.Push(lua.LString(addr.Hex()))
		return 1
	}))

	// tos.addmod(x, y, k) → (x + y) % k
	L.SetField(tosTable, "addmod", L.NewFunction(func(L *lua.LState) int {
		x := luaParseBigInt(L, 1)
		y := luaParseBigInt(L, 2)
		k := luaParseBigInt(L, 3)
		if k.Sign() == 0 {
			L.RaiseError("addmod: modulus is zero")
		}
		result := new(big.Int).Add(x, y)
		result.Mod(result, k)
		L.Push(lua.LNumber(result.Text(10)))
		return 1
	}))

	// tos.mulmod(x, y, k) → (x * y) % k
	L.SetField(tosTable, "mulmod", L.NewFunction(func(L *lua.LState) int {
		x := luaParseBigInt(L, 1)
		y := luaParseBigInt(L, 2)
		k := luaParseBigInt(L, 3)
		if k.Sign() == 0 {
			L.RaiseError("mulmod: modulus is zero")
		}
		result := new(big.Int).Mul(x, y)
		result.Mod(result, k)
		L.Push(lua.LNumber(result.Text(10)))
		return 1
	}))

	// tos.blockhash(n) → string | nil
	L.SetField(tosTable, "blockhash", L.NewFunction(func(L *lua.LState) int {
		nNum := luaParseBigInt(L, 1)
		if nNum == nil || !nNum.IsUint64() {
			L.Push(lua.LNil)
			return 1
		}
		h := st.blockCtx.GetHash(nNum.Uint64())
		if h == (common.Hash{}) {
			L.Push(lua.LNil)
		} else {
			L.Push(lua.LString(h.Hex()))
		}
		return 1
	}))

	// tos.self → string  (this contract's own address)
	L.SetField(tosTable, "self", lua.LString(contractAddr.Hex()))

	// ── Constructor / one-time initializer ────────────────────────────────────

	// tos.oncreate(fn)
	//   Runs fn exactly once — on the very first call to the contract.
	L.SetField(tosTable, "oncreate", L.NewFunction(func(L *lua.LState) int {
		fn := L.CheckFunction(1)

		initSlot := luaStorageSlot("__oncreate__")
		if st.state.GetState(contractAddr, initSlot) != (common.Hash{}) {
			return 0
		}

		var one common.Hash
		one[31] = 1
		st.state.SetState(contractAddr, initSlot, one)

		if err := L.CallByParam(lua.P{Fn: fn, NRet: 0, Protect: true}); err != nil {
			st.state.SetState(contractAddr, initSlot, common.Hash{})
			L.RaiseError("%v", err)
		}
		return 0
	}))

	// ── Dynamic array storage ──────────────────────────────────────────────────

	// tos.arrLen(key) → LNumber
	L.SetField(tosTable, "arrLen", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		base := luaArrLenSlot(key)
		raw := st.state.GetState(contractAddr, base)
		n := new(big.Int).SetBytes(raw[:])
		L.Push(lua.LNumber(n.Text(10)))
		return 1
	}))

	// tos.arrGet(key, i) → LNumber | nil  (1-based)
	L.SetField(tosTable, "arrGet", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		idxBI := luaParseBigInt(L, 2)
		if idxBI == nil {
			L.Push(lua.LNil)
			return 1
		}
		base := luaArrLenSlot(key)
		raw := st.state.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:])
		one := big.NewInt(1)
		if idxBI.Cmp(one) < 0 || idxBI.Cmp(length) > 0 {
			L.Push(lua.LNil)
			return 1
		}
		i0 := new(big.Int).Sub(idxBI, one).Uint64()
		elemSlot := luaArrElemSlot(base, i0)
		val := st.state.GetState(contractAddr, elemSlot)
		n := new(big.Int).SetBytes(val[:])
		L.Push(lua.LNumber(n.Text(10)))
		return 1
	}))

	// tos.arrSet(key, i, value)  (1-based; reverts if OOB)
	L.SetField(tosTable, "arrSet", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		idxBI := luaParseBigInt(L, 2)
		val := luaParseBigInt(L, 3)
		base := luaArrLenSlot(key)
		raw := st.state.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:])
		one := big.NewInt(1)
		if idxBI == nil || idxBI.Cmp(one) < 0 || idxBI.Cmp(length) > 0 {
			L.RaiseError("tos.arrSet: index out of bounds (len=%s)", length.Text(10))
		}
		i0 := new(big.Int).Sub(idxBI, one).Uint64()
		var slot common.Hash
		val.FillBytes(slot[:])
		st.state.SetState(contractAddr, luaArrElemSlot(base, i0), slot)
		return 0
	}))

	// tos.arrPush(key, value)
	L.SetField(tosTable, "arrPush", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val := luaParseBigInt(L, 2)
		base := luaArrLenSlot(key)
		raw := st.state.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:]).Uint64()

		var elemSlot common.Hash
		val.FillBytes(elemSlot[:])
		st.state.SetState(contractAddr, luaArrElemSlot(base, length), elemSlot)

		var lenSlot common.Hash
		new(big.Int).SetUint64(length + 1).FillBytes(lenSlot[:])
		st.state.SetState(contractAddr, base, lenSlot)
		return 0
	}))

	// tos.arrPop(key) → LNumber | nil
	L.SetField(tosTable, "arrPop", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		base := luaArrLenSlot(key)
		raw := st.state.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:]).Uint64()
		if length == 0 {
			L.Push(lua.LNil)
			return 1
		}
		lastIdx := length - 1
		elemSlot := luaArrElemSlot(base, lastIdx)
		val := st.state.GetState(contractAddr, elemSlot)
		n := new(big.Int).SetBytes(val[:])

		st.state.SetState(contractAddr, elemSlot, common.Hash{})
		var lenSlot common.Hash
		new(big.Int).SetUint64(lastIdx).FillBytes(lenSlot[:])
		st.state.SetState(contractAddr, base, lenSlot)

		L.Push(lua.LNumber(n.Text(10)))
		return 1
	}))

	// ── Cross-contract read API ───────────────────────────────────────────────

	// tos.codeAt(addr) → bool
	L.SetField(tosTable, "codeAt", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)
		addr := common.HexToAddress(addrHex)
		L.Push(lua.LBool(st.state.GetCodeSize(addr) > 0))
		return 1
	}))

	// tos.at(addr) → read-only proxy table
	L.SetField(tosTable, "at", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)
		target := common.HexToAddress(addrHex)

		proxy := L.NewTable()

		L.SetField(proxy, "get", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			val := st.state.GetState(target, luaStorageSlot(key))
			if val == (common.Hash{}) {
				L.Push(lua.LNil)
				return 1
			}
			n := new(big.Int).SetBytes(val[:])
			L.Push(lua.LNumber(n.Text(10)))
			return 1
		}))

		L.SetField(proxy, "getStr", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			base := luaStrLenSlot(key)
			lenSlot := st.state.GetState(target, base)
			if lenSlot == (common.Hash{}) {
				L.Push(lua.LNil)
				return 1
			}
			length := binary.BigEndian.Uint64(lenSlot[24:]) - 1
			data := make([]byte, length)
			for i := 0; i < int(length); i += 32 {
				slot := st.state.GetState(target, luaStrChunkSlot(base, i/32))
				copy(data[i:], slot[:])
			}
			L.Push(lua.LString(string(data)))
			return 1
		}))

		L.SetField(proxy, "arrLen", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			base := luaArrLenSlot(key)
			raw := st.state.GetState(target, base)
			n := new(big.Int).SetBytes(raw[:])
			L.Push(lua.LNumber(n.Text(10)))
			return 1
		}))

		L.SetField(proxy, "arrGet", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			idxBI := luaParseBigInt(L, 2)
			if idxBI == nil {
				L.Push(lua.LNil)
				return 1
			}
			base := luaArrLenSlot(key)
			raw := st.state.GetState(target, base)
			length := new(big.Int).SetBytes(raw[:])
			one := big.NewInt(1)
			if idxBI.Cmp(one) < 0 || idxBI.Cmp(length) > 0 {
				L.Push(lua.LNil)
				return 1
			}
			i0 := new(big.Int).Sub(idxBI, one).Uint64()
			elemSlot := luaArrElemSlot(base, i0)
			val := st.state.GetState(target, elemSlot)
			n := new(big.Int).SetBytes(val[:])
			L.Push(lua.LNumber(n.Text(10)))
			return 1
		}))

		L.SetField(proxy, "balance", L.NewFunction(func(L *lua.LState) int {
			bal := st.state.GetBalance(target)
			if bal == nil {
				L.Push(lua.LNumber("0"))
			} else {
				L.Push(lua.LNumber(bal.Text(10)))
			}
			return 1
		}))

		L.Push(proxy)
		return 1
	}))

	// ── Inter-contract call ────────────────────────────────────────────────────

	// tos.call(addr [, value [, calldata]]) → bool
	//
	// Calls another Lua contract with optional value forwarding and calldata.
	// Returns true on success, false if the callee reverts.
	//
	// Semantics (Solidity low-level call equivalent):
	//   • Callee's code runs in a new Lua VM with its own gas budget.
	//   • msg.sender inside callee = this contract's address (not tx.origin).
	//   • msg.value inside callee = forwarded value.
	//   • State changes by callee are isolated: callee revert undoes only
	//     callee's changes; caller's changes before tos.call are preserved.
	//   • Gas consumed by callee is deducted from caller's remaining budget.
	//   • Nesting limited to luaMaxCallDepth (8) levels; deeper calls revert.
	//
	// If the target address has no code, tos.call acts as a plain TOS transfer
	// (returns true on success, false if caller's balance is insufficient).
	//
	// Example:
	//   local ok = tos.call(tokenAddr, 0, calldata)
	//   tos.require(ok, "token call failed")
	L.SetField(tosTable, "call", L.NewFunction(func(L *lua.LState) int {
		if ctx.depth >= luaMaxCallDepth {
			L.RaiseError("tos.call: max call depth (%d) exceeded", luaMaxCallDepth)
			return 0
		}

		addrHex := L.CheckString(1)
		calleeAddr := common.HexToAddress(addrHex)

		var callValue *big.Int
		if L.GetTop() >= 2 && L.Get(2) != lua.LNil {
			callValue = luaParseBigInt(L, 2)
		} else {
			callValue = new(big.Int)
		}

		var callData []byte
		if L.GetTop() >= 3 && L.Get(3) != lua.LNil {
			hexStr := L.CheckString(3)
			callData = common.FromHex(hexStr)
		}

		// Compute remaining gas budget for the child.
		// gasLimit is captured from the outer executeLuaVM parameter.
		parentUsedNow := L.GasUsed()
		totalUsed := parentUsedNow + totalChildGas
		if totalUsed >= gasLimit {
			L.RaiseError("tos.call: out of gas")
			return 0
		}
		childGasLimit := gasLimit - totalUsed

		// Inner snapshot: callee state changes are reverted on callee failure,
		// but caller state changes before this call are preserved.
		calleeSnap := st.state.Snapshot()

		// Value transfer from calling contract to callee.
		if callValue.Sign() > 0 {
			if !st.blockCtx.CanTransfer(st.state, contractAddr, callValue) {
				// Insufficient balance: soft failure (do not revert snapshot).
				L.Push(lua.LFalse)
				return 1
			}
			st.blockCtx.Transfer(st.state, contractAddr, calleeAddr, callValue)
		}

		// If no code, plain transfer succeeded.
		calleeCode := st.state.GetCode(calleeAddr)
		if len(calleeCode) == 0 {
			L.Push(lua.LTrue)
			return 1
		}

		// Build child context: msg.sender = this contract, tx.origin unchanged.
		childCtx := luaCallCtx{
			from:     contractAddr, // callee sees caller contract as msg.sender
			to:       calleeAddr,
			value:    callValue,
			data:     callData,
			depth:    ctx.depth + 1,
			txOrigin: ctx.txOrigin,
			txPrice:  ctx.txPrice,
		}

		childGasUsed, childErr := executeLuaVM(st, childCtx, calleeCode, childGasLimit)
		totalChildGas += childGasUsed

		// Recalculate remaining and update parent gas limit so the parent
		// cannot use gas that the child already consumed.
		newTotalUsed := parentUsedNow + totalChildGas
		if newTotalUsed < gasLimit {
			L.SetGasLimit(parentUsedNow + (gasLimit - newTotalUsed))
		} else {
			// Child consumed all remaining gas; freeze parent.
			L.SetGasLimit(parentUsedNow)
		}

		if childErr != nil {
			// Revert callee's state changes; caller's changes are preserved.
			st.state.RevertToSnapshot(calleeSnap)
			L.Push(lua.LFalse)
			return 1
		}

		L.Push(lua.LTrue)
		return 1
	}))

	// ── Selector / Dispatch ────────────────────────────────────────────────────

	// tos.selector(sig) → string  (4-byte keccak selector as "0x" hex)
	L.SetField(tosTable, "selector", L.NewFunction(func(L *lua.LState) int {
		sig := L.CheckString(1)
		h := crypto.Keccak256([]byte(sig))
		L.Push(lua.LString("0x" + common.Bytes2Hex(h[:4])))
		return 1
	}))

	// tos.dispatch(handlers)
	//   Routes msg.data to the correct handler by ABI function selector.
	L.SetField(tosTable, "dispatch", L.NewFunction(func(L *lua.LState) int {
		handlers := L.CheckTable(1)

		var msgSig string
		var calldata []byte

		msgTable, ok := L.GetGlobal("msg").(*lua.LTable)
		if ok {
			if sv, ok2 := msgTable.RawGetString("sig").(lua.LString); ok2 {
				msgSig = string(sv)
			}
			if dv, ok2 := msgTable.RawGetString("data").(lua.LString); ok2 {
				raw := common.FromHex(string(dv))
				if len(raw) >= 4 {
					calldata = raw[4:]
				}
			}
		}

		type handlerEntry struct {
			fn    lua.LValue
			types []string
		}
		handlerMap := make(map[string]handlerEntry)
		var fallbackEntry *handlerEntry

		var parseErr error
		handlers.ForEach(func(k, v lua.LValue) {
			if parseErr != nil {
				return
			}
			sigStr, ok := k.(lua.LString)
			if !ok {
				parseErr = fmt.Errorf("tos.dispatch: handler key must be a string, got %T", k)
				return
			}
			name, types, err := abiParseSignature(string(sigStr))
			if err != nil {
				parseErr = fmt.Errorf("tos.dispatch: %v", err)
				return
			}
			if name == "fallback" {
				entry := handlerEntry{fn: v, types: nil}
				fallbackEntry = &entry
				return
			}
			h := crypto.Keccak256([]byte(string(sigStr)))
			sel := "0x" + common.Bytes2Hex(h[:4])
			handlerMap[sel] = handlerEntry{fn: v, types: types}
		})
		if parseErr != nil {
			L.RaiseError("%v", parseErr)
			return 0
		}

		var entry *handlerEntry
		if len(msgSig) < 10 {
			if fallbackEntry != nil {
				entry = fallbackEntry
			}
		} else {
			if h, ok := handlerMap[msgSig]; ok {
				entry = &h
			} else if fallbackEntry != nil {
				entry = fallbackEntry
			} else {
				L.RaiseError("tos.dispatch: no handler for selector %s", msgSig)
				return 0
			}
		}

		if entry == nil {
			return 0
		}

		goVals, abiArgs, err := abiDecodeRawArgs(calldata, entry.types)
		if err != nil {
			L.RaiseError("tos.dispatch: decode args for %s: %v", msgSig, err)
			return 0
		}

		luaArgs := make([]lua.LValue, len(goVals))
		for i, gv := range goVals {
			lv, err := abiGoToLua(abiArgs[i].Type, gv)
			if err != nil {
				L.RaiseError("tos.dispatch: arg %d: %v", i+1, err)
				return 0
			}
			luaArgs[i] = lv
		}

		callParams := lua.P{Fn: entry.fn, NRet: 0, Protect: true}
		if err := L.CallByParam(callParams, luaArgs...); err != nil {
			L.RaiseError("%v", err)
		}
		return 0
	}))

	// ── Events ────────────────────────────────────────────────────────────────

	// tos.emit(eventName, "type1", val1, ...)
	//   Emits a receipt log with topic[0] = keccak256(eventName).
	L.SetField(tosTable, "emit", L.NewFunction(func(L *lua.LState) int {
		eventName := L.CheckString(1)
		topic0 := crypto.Keccak256Hash([]byte(eventName))
		data, err := luaABIEncodeBytes(L, 2)
		if err != nil {
			L.RaiseError("tos.emit: %v", err)
			return 0
		}
		st.state.AddLog(&types.Log{
			Address: contractAddr,
			Topics:  []common.Hash{topic0},
			Data:    data,
		})
		return 0
	}))

	// ── String storage ────────────────────────────────────────────────────────

	// tos.setStr(key, val)
	L.SetField(tosTable, "setStr", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val := L.CheckString(2)
		data := []byte(val)

		base := luaStrLenSlot(key)

		var lenSlot common.Hash
		binary.BigEndian.PutUint64(lenSlot[24:], uint64(len(data))+1)
		st.state.SetState(contractAddr, base, lenSlot)

		for i := 0; i < len(data); i += 32 {
			chunk := data[i:]
			if len(chunk) > 32 {
				chunk = chunk[:32]
			}
			var slot common.Hash
			copy(slot[:], chunk)
			st.state.SetState(contractAddr, luaStrChunkSlot(base, i/32), slot)
		}
		return 0
	}))

	// tos.getStr(key) → string | nil
	L.SetField(tosTable, "getStr", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		base := luaStrLenSlot(key)

		lenSlot := st.state.GetState(contractAddr, base)
		if lenSlot == (common.Hash{}) {
			L.Push(lua.LNil)
			return 1
		}
		length := binary.BigEndian.Uint64(lenSlot[24:]) - 1

		data := make([]byte, length)
		for i := 0; i < int(length); i += 32 {
			slot := st.state.GetState(contractAddr, luaStrChunkSlot(base, i/32))
			copy(data[i:], slot[:])
		}
		L.Push(lua.LString(string(data)))
		return 1
	}))

	// ── Inject globals ────────────────────────────────────────────────────────

	L.SetGlobal("tos", tosTable)

	// Make every tos.* field also available as a bare global.
	// tos.caller / caller, tos.set() / set(), tos.block.number / block.number …
	tosTable.ForEach(func(k, v lua.LValue) {
		if name, ok := k.(lua.LString); ok {
			L.SetGlobal(string(name), v)
		}
	})

	// ── Execute ───────────────────────────────────────────────────────────────

	if err := L.DoString(string(src)); err != nil {
		return L.GasUsed() + totalChildGas, err
	}
	return L.GasUsed() + totalChildGas, nil
}

// applyLua executes the Lua contract stored at the destination address.
//
// Gas model:
//   - executeLuaVM is capped to st.gas total opcodes (including nested calls).
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

	ctx := luaCallCtx{
		from:     st.msg.From(),
		to:       contractAddr,
		value:    st.msg.Value(),
		data:     st.msg.Data(),
		depth:    0,
		txOrigin: st.msg.From(),
		txPrice:  st.txPrice,
	}

	gasUsed, err := executeLuaVM(st, ctx, src, st.gas)
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
