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

	// ── Context properties (static values, no parentheses needed) ────────────
	//
	// These mirror EVM opcode semantics: constant within a single execution,
	// so they are pre-populated as plain Lua values rather than Go functions.
	// Scripts read them as properties: tos.caller, tos.value, tos.block.number…

	// tos.caller  → string  (hex address of msg.From, like Solidity msg.sender)
	L.SetField(tosTable, "caller", lua.LString(st.msg.From().Hex()))

	// tos.value  → LNumber  (msg.Value in wei, like Solidity msg.value)
	{
		v := st.msg.Value()
		if v == nil || v.Sign() == 0 {
			L.SetField(tosTable, "value", lua.LNumber("0"))
		} else {
			L.SetField(tosTable, "value", lua.LNumber(v.Text(10)))
		}
	}

	// tos.block  (sub-table — all fields are static values for this execution)
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

	// tos.tx  (sub-table — static values, like Solidity tx.origin / tx.gasprice)
	txTable := L.NewTable()
	L.SetField(txTable, "origin", lua.LString(st.msg.From().Hex()))
	if st.txPrice != nil {
		L.SetField(txTable, "gasprice", lua.LNumber(st.txPrice.Text(10)))
	} else {
		L.SetField(txTable, "gasprice", lua.LNumber("0"))
	}
	L.SetField(tosTable, "tx", txTable)

	// tos.msg  (sub-table — Solidity-compatible aliases)
	//   msg.sender == tos.caller == caller  (all three refer to the same value)
	//   msg.value  == tos.value  == value
	//   msg.data   → "0x"-prefixed hex of raw tx data (Solidity msg.data)
	//   msg.sig    → first 4 bytes of msg.data as "0x"+8 hex chars (Solidity msg.sig)
	// After the ForEach global injection below, all msg.* are also bare globals.
	msgTable := L.NewTable()
	L.SetField(msgTable, "sender", lua.LString(st.msg.From().Hex()))
	{
		v := st.msg.Value()
		if v == nil || v.Sign() == 0 {
			L.SetField(msgTable, "value", lua.LNumber("0"))
		} else {
			L.SetField(msgTable, "value", lua.LNumber(v.Text(10)))
		}
	}
	{
		d := st.msg.Data()
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

	// tos.abi  (sub-table — Ethereum ABI encode/decode, like Solidity abi.*)
	//   abi.encode("type", val, ...)         → "0x" hex  (standard ABI)
	//   abi.encodePacked("type", val, ...)   → "0x" hex  (tight, no padding)
	//   abi.decode(hexData, "type", ...)     → val, val, ...
	// After the ForEach injection, abi.encode / abi.encodePacked / abi.decode
	// are also accessible without any prefix.
	abiTable := L.NewTable()
	L.SetField(abiTable, "encode", L.NewFunction(luaABIEncode))
	L.SetField(abiTable, "encodePacked", L.NewFunction(luaABIEncodePacked))
	L.SetField(abiTable, "decode", L.NewFunction(luaABIDecode))
	L.SetField(tosTable, "abi", abiTable)

	// tos.gasleft() → LNumber  (remaining gas at call time — must be a function
	//   because the value changes with each opcode executed)
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

	// tos.keccak256(data) → string  (keccak256 of data, hex-encoded)
	L.SetField(tosTable, "keccak256", L.NewFunction(func(L *lua.LState) int {
		data := L.CheckString(1)
		h := crypto.Keccak256Hash([]byte(data))
		L.Push(lua.LString(h.Hex()))
		return 1
	}))

	// tos.sha256(data) → string  (SHA-256 of data as "0x" + 64 hex chars)
	L.SetField(tosTable, "sha256", L.NewFunction(func(L *lua.LState) int {
		data := L.CheckString(1)
		h := gosha256.Sum256([]byte(data))
		L.Push(lua.LString("0x" + common.Bytes2Hex(h[:])))
		return 1
	}))

	// tos.ecrecover(hash, v, r, s) → string | nil
	//   Recovers the signer address from an ECDSA signature (secp256k1).
	//   hash: "0x"-prefixed 32-byte hex string
	//   v:    27 or 28 (Solidity convention); also accepts 0 or 1
	//   r, s: "0x"-prefixed 32-byte hex strings
	//   Returns the signer address hex string, or nil on failure.
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
		// normalize v: Solidity uses 27/28; crypto.SigToPub expects 0/1
		v := vNum
		if v >= 27 {
			v -= 27
		}
		if v != 0 && v != 1 {
			L.Push(lua.LNil)
			return 1
		}
		// sig = [R(32) || S(32) || V(1)]
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

	// tos.addmod(x, y, k) → (x + y) % k  (uint256, reverts if k == 0)
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

	// tos.mulmod(x, y, k) → (x * y) % k  (uint256, reverts if k == 0)
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
	//   Returns the hash of block n as "0x"+64 hex chars, or nil if unavailable.
	//   Only recent blocks (within ~256) are guaranteed available.
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

	// tos.self → string  (this contract's own address, like Solidity address(this))
	L.SetField(tosTable, "self", lua.LString(contractAddr.Hex()))

	// ── Constructor / one-time initializer ────────────────────────────────────

	// tos.oncreate(fn)
	//   Runs fn exactly once — on the very first call to the contract.
	//   On every subsequent call fn is skipped (idempotent / constructor semantics).
	//
	//   The "initialized" flag is stored in a reserved storage slot so it
	//   survives across blocks.  fn is called in protected mode; if it reverts,
	//   the flag is NOT set (the constructor can be retried).
	//
	//   Example:
	//     tos.oncreate(function()
	//       tos.setStr("owner", tos.caller)
	//       tos.set("totalSupply", 1000000)
	//       tos.set("bal." .. tos.caller, 1000000)
	//       tos.emit("Deployed", "address", tos.caller)
	//     end)
	L.SetField(tosTable, "oncreate", L.NewFunction(func(L *lua.LState) int {
		fn := L.CheckFunction(1)

		// Reserved slot: __oncreate__ in the uint256 storage namespace.
		initSlot := luaStorageSlot("__oncreate__")
		if st.state.GetState(contractAddr, initSlot) != (common.Hash{}) {
			return 0 // already initialised — skip fn
		}

		// Mark as initialised BEFORE calling fn so that re-entrancy within fn
		// does not trigger a second constructor call.
		var one common.Hash
		one[31] = 1
		st.state.SetState(contractAddr, initSlot, one)

		// Call fn in protected mode so its errors propagate normally.
		if err := L.CallByParam(lua.P{Fn: fn, NRet: 0, Protect: true}); err != nil {
			// Constructor reverted: clear the flag so it can be retried.
			st.state.SetState(contractAddr, initSlot, common.Hash{})
			L.RaiseError("%v", err)
		}
		return 0
	}))

	// ── Dynamic array storage ──────────────────────────────────────────────────
	//
	// Arrays store ordered sequences of uint256 values.  The layout is:
	//   length slot  = keccak256("gtos.lua.arr." + key)         → uint256 length
	//   element i    = keccak256(length_slot || uint64(i))       → uint256 value
	//
	// The "gtos.lua.arr." namespace is independent of the scalar uint256
	// namespace ("gtos.lua.storage.") so arrays and scalars with the same key
	// never collide.
	//
	// Indices visible to Lua are 1-based (matching Lua table convention).

	// tos.arrLen(key) → LNumber
	//   Returns the current length of the array.  0 if never written to.
	L.SetField(tosTable, "arrLen", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		base := luaArrLenSlot(key)
		raw := st.state.GetState(contractAddr, base)
		n := new(big.Int).SetBytes(raw[:])
		L.Push(lua.LNumber(n.Text(10)))
		return 1
	}))

	// tos.arrGet(key, i) → LNumber | nil
	//   Returns the element at 1-based index i, or nil if out of bounds.
	//   Index must be a positive integer in [1, arrLen(key)].
	//   Any other value (0, negative, or beyond length) returns nil.
	//
	//   NOTE: negative Lua literals (-1, -2, …) evaluate to their uint256
	//   two's complement in this VM, so they are always > arrLen and return nil.
	L.SetField(tosTable, "arrGet", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		// Read index as a big.Int; negative Lua values arrive as large uint256.
		idxBI := luaParseBigInt(L, 2)
		if idxBI == nil {
			L.Push(lua.LNil)
			return 1
		}
		base := luaArrLenSlot(key)
		raw := st.state.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:])
		one := big.NewInt(1)
		// Valid range: [1, length]. idxBI < 1 or idxBI > length → nil.
		if idxBI.Cmp(one) < 0 || idxBI.Cmp(length) > 0 {
			L.Push(lua.LNil)
			return 1
		}
		// Convert to 0-based uint64 (safe: fits because ≤ length ≤ uint64).
		i0 := new(big.Int).Sub(idxBI, one).Uint64()
		elemSlot := luaArrElemSlot(base, i0)
		val := st.state.GetState(contractAddr, elemSlot)
		n := new(big.Int).SetBytes(val[:])
		L.Push(lua.LNumber(n.Text(10)))
		return 1
	}))

	// tos.arrSet(key, i, value)
	//   Overwrites the element at 1-based index i.  Raises an error if i is
	//   out of bounds (use arrPush to extend the array).
	L.SetField(tosTable, "arrSet", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		idxBI := luaParseBigInt(L, 2) // 1-based
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
	//   Appends value to the end of the array, incrementing its length.
	L.SetField(tosTable, "arrPush", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val := luaParseBigInt(L, 2)
		base := luaArrLenSlot(key)
		raw := st.state.GetState(contractAddr, base)
		length := new(big.Int).SetBytes(raw[:]).Uint64()

		// Store element.
		var elemSlot common.Hash
		val.FillBytes(elemSlot[:])
		st.state.SetState(contractAddr, luaArrElemSlot(base, length), elemSlot)

		// Increment length.
		var lenSlot common.Hash
		new(big.Int).SetUint64(length + 1).FillBytes(lenSlot[:])
		st.state.SetState(contractAddr, base, lenSlot)
		return 0
	}))

	// tos.arrPop(key) → LNumber | nil
	//   Removes and returns the last element of the array.
	//   Returns nil (and leaves the array unchanged) if it is empty.
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

		// Zero the element slot and decrement length.
		st.state.SetState(contractAddr, elemSlot, common.Hash{})
		var lenSlot common.Hash
		new(big.Int).SetUint64(lastIdx).FillBytes(lenSlot[:])
		st.state.SetState(contractAddr, base, lenSlot)

		L.Push(lua.LNumber(n.Text(10)))
		return 1
	}))

	// ── Cross-contract read API ───────────────────────────────────────────────
	//
	// These primitives expose read-only access to another contract's on-chain
	// state.  They never write — only StateDB.GetState / GetCode are called.
	// There is no re-entrancy risk because no Lua is executed inside the target.

	// tos.codeAt(addr) → bool
	//   Returns true if the given address has Lua contract code deployed.
	//   Useful as a guard before calling tos.at(addr):
	//     tos.require(tos.codeAt(tokenAddr), "not a contract")
	L.SetField(tosTable, "codeAt", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)
		addr := common.HexToAddress(addrHex)
		L.Push(lua.LBool(st.state.GetCodeSize(addr) > 0))
		return 1
	}))

	// tos.at(addr) → proxy table
	//   Returns a read-only storage proxy for the Lua contract at addr.
	//   The proxy exposes the same storage namespaces used by tos.get/set,
	//   tos.setStr/getStr, and tos.arrPush/arrGet — so any value written by
	//   contract A can be read by contract B via tos.at(addrA).get(key).
	//
	//   Proxy methods:
	//     proxy.get(key)        → LNumber | nil   (uint256 storage)
	//     proxy.getStr(key)     → string | nil    (string storage)
	//     proxy.arrLen(key)     → LNumber         (dynamic array length)
	//     proxy.arrGet(key, i)  → LNumber | nil   (1-based array element)
	//     proxy.balance()       → LNumber         (TOS balance in wei)
	//
	//   Example — read another token contract's balance mapping:
	//     local tok = tos.at("0xTokenAddr...")
	//     local bal = tok.get("bal." .. tos.caller)
	//     tos.require(bal >= 100, "insufficient token balance")
	L.SetField(tosTable, "at", L.NewFunction(func(L *lua.LState) int {
		addrHex := L.CheckString(1)
		target := common.HexToAddress(addrHex)

		proxy := L.NewTable()

		// proxy.get(key) — read uint256 slot
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

		// proxy.getStr(key) — read string slot
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

		// proxy.arrLen(key) — read dynamic array length
		L.SetField(proxy, "arrLen", L.NewFunction(func(L *lua.LState) int {
			key := L.CheckString(1)
			base := luaArrLenSlot(key)
			raw := st.state.GetState(target, base)
			n := new(big.Int).SetBytes(raw[:])
			L.Push(lua.LNumber(n.Text(10)))
			return 1
		}))

		// proxy.arrGet(key, i) — read 1-based array element
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

		// proxy.balance() — TOS balance of the target address
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

	// tos.selector(sig) → string  (4-byte keccak selector as "0x" hex)
	//   Computes the Ethereum ABI function selector for a given signature string.
	//   Equivalent to bytes4(keccak256(bytes(sig))).
	//
	//   Example:
	//     tos.selector("transfer(address,uint256)") == "0xa9059cbb"
	L.SetField(tosTable, "selector", L.NewFunction(func(L *lua.LState) int {
		sig := L.CheckString(1)
		h := crypto.Keccak256([]byte(sig))
		L.Push(lua.LString("0x" + common.Bytes2Hex(h[:4])))
		return 1
	}))

	// tos.dispatch(handlers)
	//   Routes the current call to the correct handler function based on the
	//   4-byte ABI function selector in msg.data.
	//
	//   `handlers` is a Lua table mapping Solidity-style ABI signatures to
	//   handler functions. The handler function receives the decoded calldata
	//   arguments as individual Lua values.
	//
	//   Special keys:
	//     "" or "fallback" or "fallback()" — called when no selector matches,
	//     and also when msg.data is empty (receive-like behaviour).
	//
	//   Behaviour:
	//     • msg.data empty or < 4 bytes → call fallback if present, else no-op.
	//     • selector matches a handler  → decode args, call handler.
	//     • no match + no fallback      → tos.revert("no handler for <selector>").
	//
	//   Example:
	//     tos.dispatch({
	//       ["transfer(address,uint256)"] = function(to, amount)
	//         tos.transfer(to, amount)
	//         tos.emit("Transfer", "address", tos.caller, "address", to, "uint256", amount)
	//       end,
	//       ["balanceOf(address)"] = function(addr)
	//         tos.emit("BalanceOf", "address", addr, "uint256", tos.balance(addr))
	//       end,
	//       [""] = function()   -- fallback / receive
	//         tos.emit("Received")
	//       end,
	//     })
	L.SetField(tosTable, "dispatch", L.NewFunction(func(L *lua.LState) int {
		handlers := L.CheckTable(1)

		// Extract msg.sig and msg.data from the Lua global state.
		// These were populated when the tos.msg sub-table was built above.
		var msgSig string
		var calldata []byte // calldata = msg.data bytes after the 4-byte selector

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

		// Build a map: 4-byte selector hex → (handler LValue, type list).
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
			// Compute the 4-byte selector for this signature.
			h := crypto.Keccak256([]byte(string(sigStr)))
			sel := "0x" + common.Bytes2Hex(h[:4])
			handlerMap[sel] = handlerEntry{fn: v, types: types}
		})
		if parseErr != nil {
			L.RaiseError("%v", parseErr)
			return 0
		}

		// Determine which handler to call.
		var entry *handlerEntry
		if len(msgSig) < 10 { // "0x" + 8 hex chars = 10; anything shorter = no selector
			// No selector present: use fallback.
			if fallbackEntry != nil {
				entry = fallbackEntry
			}
			// else: no-op (empty call, no msg.data)
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
			return 0 // no-op
		}

		// Decode calldata arguments using the handler's ABI type list.
		goVals, abiArgs, err := abiDecodeRawArgs(calldata, entry.types)
		if err != nil {
			L.RaiseError("tos.dispatch: decode args for %s: %v", msgSig, err)
			return 0
		}

		// Convert Go values to Lua values and push them as function arguments.
		luaArgs := make([]lua.LValue, len(goVals))
		for i, gv := range goVals {
			lv, err := abiGoToLua(abiArgs[i].Type, gv)
			if err != nil {
				L.RaiseError("tos.dispatch: arg %d: %v", i+1, err)
				return 0
			}
			luaArgs[i] = lv
		}

		// Call the handler using protected mode (pcall semantics).
		// Errors in the handler propagate back to applyLua as a normal Lua error,
		// which triggers the snapshot revert in applyLua.
		callParams := lua.P{Fn: entry.fn, NRet: 0, Protect: true}
		if err := L.CallByParam(callParams, luaArgs...); err != nil {
			L.RaiseError("%v", err)
		}
		return 0
	}))

	// tos.emit(eventName, "type1", val1, "type2", val2, ...)
	//   Emits a structured event into the transaction receipt logs.
	//
	//   topic[0] = keccak256(eventName)  — identifies the event type.
	//   data     = abi.encode(type-value pairs)  — ABI-encoded non-indexed fields.
	//
	//   Events are visible in receipts and can be indexed by standard Ethereum
	//   tooling (topic0 = event signature hash, data = ABI-encoded payload).
	//
	//   Example:
	//     tos.emit("Transfer", "address", tos.caller, "address", recipient, "uint256", amount)
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

	// tos.setStr(key, val)
	//   Stores an arbitrary UTF-8 string in contract storage.
	//   The string length is stored in the "length slot"; data is packed into
	//   consecutive 32-byte "chunk slots" derived deterministically from the key.
	//   No length limit is enforced here; very large strings consume many slots
	//   and therefore consume proportionally more gas (Phase 3 will meter this).
	L.SetField(tosTable, "setStr", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		val := L.CheckString(2)
		data := []byte(val)

		base := luaStrLenSlot(key)

		// Store (byte-length + 1) at the base slot (big-endian uint64 in high bytes).
		// Adding 1 distinguishes "empty string" (slot=1) from "key not set" (slot=0).
		var lenSlot common.Hash
		binary.BigEndian.PutUint64(lenSlot[24:], uint64(len(data))+1)
		st.state.SetState(contractAddr, base, lenSlot)

		// Store data packed into 32-byte chunks.
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
	//   Reads a string previously stored with tos.setStr.
	//   Returns nil if the key has never been set.
	L.SetField(tosTable, "getStr", L.NewFunction(func(L *lua.LState) int {
		key := L.CheckString(1)
		base := luaStrLenSlot(key)

		// Read length.
		lenSlot := st.state.GetState(contractAddr, base)
		if lenSlot == (common.Hash{}) {
			L.Push(lua.LNil)
			return 1
		}
		// Stored value is length+1; slot==0 means "not set" (handled above).
		length := binary.BigEndian.Uint64(lenSlot[24:]) - 1

		// Read and reassemble chunks.
		data := make([]byte, length)
		for i := 0; i < int(length); i += 32 {
			slot := st.state.GetState(contractAddr, luaStrChunkSlot(base, i/32))
			copy(data[i:], slot[:])
		}
		L.Push(lua.LString(string(data)))
		return 1
	}))

	L.SetGlobal("tos", tosTable)

	// Inject every tos.* field as a global so the tos. prefix is optional.
	// tos.caller / caller, tos.set() / set(), tos.block.number / block.number, …
	// all work identically. tos.* remains available for explicit use.
	tosTable.ForEach(func(k, v lua.LValue) {
		if name, ok := k.(lua.LString); ok {
			L.SetGlobal(string(name), v)
		}
	})

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
