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
