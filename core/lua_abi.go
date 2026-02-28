package core

// Ethereum ABI encoding/decoding for TOS Lua contracts.
//
// Standard encode/decode delegates to accounts/abi (Arguments.Pack /
// Arguments.Unpack), which is battle-tested and supports arrays and tuples.
//
// encodePacked is implemented here because accounts/abi does not expose it.
//
// API (all accessible as bare globals and via tos.abi.* prefix):
//
//	abi.encode("type", val, ...)         → "0x" hex  (standard ABI encoding)
//	abi.encodePacked("type", val, ...)   → "0x" hex  (tight, no slot padding)
//	abi.decode(hexData, "type", ...)     → val, val, ...

import (
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/tos-network/gtos/accounts/abi"
	"github.com/tos-network/gtos/common"
	lua "github.com/tos-network/gopher-lua"
)

// ── Lua ↔ Go value conversion ─────────────────────────────────────────────────

// abiLuaToGo converts a Lua value to the Go type expected by accounts/abi Pack.
//
// Integer semantics (EVM / Lua VM are both uint256):
//   - Lua -1  == LNumber("2^256-1") after the OP_UNM two's complement fix.
//   - For unsigned types (uint8..64): low N bits of the uint256 value.
//   - For signed types (int8..64): low N bits with two's complement reinterpretation.
//   - For uint128/256 and int256: pass *big.Int directly.
//   - accounts/abi typeCheck requires native Go int types for sizes ≤ 64.
//
// FixedBytesTy: accounts/abi typeCheck requires [N]byte (Array kind), not []byte (Slice).
func abiLuaToGo(typ abi.Type, val lua.LValue) (interface{}, error) {
	switch typ.T {
	case abi.UintTy, abi.IntTy:
		var s string
		switch u := val.(type) {
		case lua.LNumber:
			s = string(u)
		case lua.LString:
			s = string(u)
		default:
			return nil, fmt.Errorf("expected number or string, got %T", val)
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("invalid integer %q", s)
		}
		// For sizes ≤ 64, accounts/abi typeCheck requires native Go integer types.
		// Mask to N bits to handle uint256 two's complement (Lua -1 == 2^256-1).
		if typ.Size <= 64 {
			bitSize := uint(typ.Size)
			mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), bitSize), big.NewInt(1))
			low := new(big.Int).And(n, mask) // low N bits, always non-negative
			if typ.T == abi.IntTy && low.Bit(int(bitSize)-1) == 1 {
				// Sign bit set: negative in N-bit two's complement.
				low.Sub(low, new(big.Int).Lsh(big.NewInt(1), bitSize))
			}
			i64 := low.Int64()
			switch typ.Size {
			case 8:
				if typ.T == abi.IntTy {
					return int8(i64), nil
				}
				return uint8(low.Uint64()), nil
			case 16:
				if typ.T == abi.IntTy {
					return int16(i64), nil
				}
				return uint16(low.Uint64()), nil
			case 32:
				if typ.T == abi.IntTy {
					return int32(i64), nil
				}
				return uint32(low.Uint64()), nil
			case 64:
				if typ.T == abi.IntTy {
					return i64, nil
				}
				return low.Uint64(), nil
			}
		}
		return n, nil

	case abi.BoolTy:
		switch u := val.(type) {
		case lua.LBool:
			return bool(u), nil
		case lua.LNumber:
			return string(u) != "0", nil
		default:
			return nil, fmt.Errorf("bool: expected boolean or number, got %T", val)
		}

	case abi.AddressTy:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("address: expected hex string")
		}
		b := common.FromHex(string(s))
		var addr common.Address
		if len(b) > common.AddressLength {
			return nil, fmt.Errorf("address: hex string too long")
		}
		copy(addr[common.AddressLength-len(b):], b)
		return addr, nil

	case abi.StringTy:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("string: expected string value, got %T", val)
		}
		return string(s), nil

	case abi.BytesTy:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("bytes: expected string value, got %T", val)
		}
		str := string(s)
		if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
			return common.FromHex(str), nil
		}
		return []byte(str), nil

	case abi.FixedBytesTy:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("bytes%d: expected string value, got %T", typ.Size, val)
		}
		str := string(s)
		var raw []byte
		if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
			raw = common.FromHex(str)
		} else {
			raw = []byte(str)
		}
		if len(raw) > typ.Size {
			return nil, fmt.Errorf("bytes%d: data too long (%d bytes)", typ.Size, len(raw))
		}
		// accounts/abi typeCheck requires Array kind ([N]byte), not Slice ([]byte).
		// Build a [N]byte reflect array right-padded with zeros.
		arrType := reflect.ArrayOf(typ.Size, reflect.TypeOf(byte(0)))
		arr := reflect.New(arrType).Elem()
		reflect.Copy(arr, reflect.ValueOf(raw))
		return arr.Interface(), nil

	default:
		return nil, fmt.Errorf("unsupported type for encode: %v", typ)
	}
}

// uint256Mod = 2^256, used for signed→uint256 sign-extension.
var uint256Mod = new(big.Int).Lsh(big.NewInt(1), 256)

// signedToLNumber converts a signed integer value to LNumber using two's
// complement uint256 representation, consistent with the Lua VM's own unary
// minus semantics (-1 == 2^256-1).
func signedToLNumber(n *big.Int) lua.LNumber {
	if n.Sign() < 0 {
		n = new(big.Int).Add(n, uint256Mod)
	}
	return lua.LNumber(n.Text(10))
}

// abiGoToLua converts a Go value returned by accounts/abi Unpack to a Lua value.
//
// Signed integer types (intN) are returned as their two's complement uint256
// representation so they are valid LNumber values in the Lua VM:
//
//	int8(-1)   → LNumber("2^256-1")   — matches Lua's own -1 literal
//	int8(-128) → LNumber("2^256-128")
func abiGoToLua(typ abi.Type, val interface{}) (lua.LValue, error) {
	switch typ.T {
	case abi.UintTy:
		switch v := val.(type) {
		case uint8:
			return lua.LNumber(fmt.Sprintf("%d", v)), nil
		case uint16:
			return lua.LNumber(fmt.Sprintf("%d", v)), nil
		case uint32:
			return lua.LNumber(fmt.Sprintf("%d", v)), nil
		case uint64:
			return lua.LNumber(fmt.Sprintf("%d", v)), nil
		case *big.Int:
			return lua.LNumber(v.Text(10)), nil
		default:
			return nil, fmt.Errorf("unexpected Go uint type %T", val)
		}

	case abi.IntTy:
		switch v := val.(type) {
		case int8:
			return signedToLNumber(big.NewInt(int64(v))), nil
		case int16:
			return signedToLNumber(big.NewInt(int64(v))), nil
		case int32:
			return signedToLNumber(big.NewInt(int64(v))), nil
		case int64:
			return signedToLNumber(big.NewInt(v)), nil
		case *big.Int:
			return signedToLNumber(new(big.Int).Set(v)), nil
		default:
			return nil, fmt.Errorf("unexpected Go int type %T", val)
		}

	case abi.BoolTy:
		b, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("expected bool, got %T", val)
		}
		return lua.LBool(b), nil

	case abi.AddressTy:
		addr, ok := val.(common.Address)
		if !ok {
			return nil, fmt.Errorf("expected common.Address, got %T", val)
		}
		return lua.LString(addr.Hex()), nil

	case abi.StringTy:
		s, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("expected string, got %T", val)
		}
		return lua.LString(s), nil

	case abi.BytesTy:
		b, ok := val.([]byte)
		if !ok {
			return nil, fmt.Errorf("expected []byte, got %T", val)
		}
		return lua.LString("0x" + common.Bytes2Hex(b)), nil

	case abi.FixedBytesTy:
		// Unpack returns a [N]byte reflect.Array
		rv := reflect.ValueOf(val)
		if rv.Kind() != reflect.Array {
			return nil, fmt.Errorf("expected [N]byte array, got %T", val)
		}
		b := make([]byte, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			b[i] = byte(rv.Index(i).Uint())
		}
		return lua.LString("0x" + common.Bytes2Hex(b)), nil

	default:
		return nil, fmt.Errorf("unsupported type for decode: %v", typ)
	}
}

// ── Standard ABI encoding (abi.encode) ───────────────────────────────────────

// luaABIEncodeBytes encodes Lua arguments starting at startArg (1-based) into
// raw ABI bytes. Arguments are (type-string, value) pairs. Returns empty slice
// if no type-value pairs are provided.
//
// This is the shared engine used by both luaABIEncode (which adds "0x" prefix)
// and tos.emit (which uses the raw bytes as log data).
func luaABIEncodeBytes(L *lua.LState, startArg int) ([]byte, error) {
	nargs := L.GetTop() - (startArg - 1)
	if nargs < 0 {
		nargs = 0
	}
	if nargs == 0 {
		return []byte{}, nil
	}
	if nargs%2 != 0 {
		return nil, fmt.Errorf("expected (type, value) pairs, got %d args", nargs)
	}
	n := nargs / 2
	args := make(abi.Arguments, n)
	vals := make([]interface{}, n)

	for i := 0; i < n; i++ {
		typStr := L.CheckString(startArg + i*2)
		typ, err := abi.NewType(typStr, "", nil)
		if err != nil {
			return nil, fmt.Errorf("invalid type %q: %v", typStr, err)
		}
		args[i] = abi.Argument{Type: typ}
		goVal, err := abiLuaToGo(typ, L.CheckAny(startArg+i*2+1))
		if err != nil {
			return nil, fmt.Errorf("arg %d (%s): %v", i+1, typStr, err)
		}
		vals[i] = goVal
	}

	packed, err := args.Pack(vals...)
	if err != nil {
		return nil, err
	}
	return packed, nil
}

// luaABIEncode implements abi.encode("type", val, ...) → "0x" hex.
// Delegates to accounts/abi Arguments.Pack for spec-correct ABI encoding.
func luaABIEncode(L *lua.LState) int {
	packed, err := luaABIEncodeBytes(L, 1)
	if err != nil {
		L.RaiseError("abi.encode: %v", err)
		return 0
	}
	L.Push(lua.LString("0x" + common.Bytes2Hex(packed)))
	return 1
}

// ── Standard ABI decoding (abi.decode) ───────────────────────────────────────

// luaABIDecode implements abi.decode(hexData, "type", ...) → val, val, ...
// Delegates to accounts/abi Arguments.Unpack for spec-correct ABI decoding.
func luaABIDecode(L *lua.LState) int {
	nargs := L.GetTop()
	if nargs < 2 {
		L.RaiseError("abi.decode: at least 2 arguments required (data, type...)")
		return 0
	}
	data := common.FromHex(L.CheckString(1))

	n := nargs - 1
	args := make(abi.Arguments, n)
	for i := 0; i < n; i++ {
		typStr := L.CheckString(i + 2)
		typ, err := abi.NewType(typStr, "", nil)
		if err != nil {
			L.RaiseError("abi.decode: invalid type %q: %v", typStr, err)
			return 0
		}
		args[i] = abi.Argument{Type: typ}
	}

	goVals, err := args.Unpack(data)
	if err != nil {
		L.RaiseError("abi.decode: %v", err)
		return 0
	}

	for i, goVal := range goVals {
		lv, err := abiGoToLua(args[i].Type, goVal)
		if err != nil {
			L.RaiseError("abi.decode result %d: %v", i+1, err)
			return 0
		}
		L.Push(lv)
	}
	return n
}

// ── Packed ABI encoding (abi.encodePacked) ────────────────────────────────────
//
// accounts/abi does not expose a packed encoder, so this is implemented here.
// Packed encoding concatenates values without 32-byte slot alignment:
//   uintN / intN → N/8 bytes big-endian (two's complement for negatives)
//   bool         → 1 byte (0x00 or 0x01)
//   address      → 32 bytes (gtos uses 32-byte addresses)
//   bytesN       → N bytes, right-padded with zeros
//   bytes        → raw bytes (no length prefix)
//   string       → raw UTF-8 bytes (no length prefix)

// abiPackedOne encodes a single (type, Lua value) pair in packed format.
func abiPackedOne(typ abi.Type, val lua.LValue) ([]byte, error) {
	switch typ.T {
	case abi.UintTy, abi.IntTy:
		var s string
		switch u := val.(type) {
		case lua.LNumber:
			s = string(u)
		case lua.LString:
			s = string(u)
		default:
			return nil, fmt.Errorf("expected number or string, got %T", val)
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return nil, fmt.Errorf("invalid integer %q", s)
		}
		byteLen := typ.Size / 8
		b := make([]byte, byteLen)
		// For sizes < 256, mask to N bits to handle Lua uint256 two's complement
		// (e.g. Lua -1 == 2^256-1; for int8 that must become 0xff, not panic on FillBytes).
		if typ.Size < 256 {
			mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(typ.Size)), big.NewInt(1))
			n.And(n, mask) // now n is in [0, 2^N)
			// For signed types, reinterpret as negative if sign bit is set.
			if typ.T == abi.IntTy && n.Bit(typ.Size-1) == 1 {
				n.Sub(n, new(big.Int).Lsh(big.NewInt(1), uint(typ.Size)))
			}
		}
		if n.Sign() < 0 {
			// two's complement mod 2^(byteLen*8)
			mask := new(big.Int).Lsh(big.NewInt(1), uint(typ.Size))
			new(big.Int).Add(n, mask).FillBytes(b)
		} else {
			n.FillBytes(b)
		}
		return b, nil

	case abi.BoolTy:
		switch u := val.(type) {
		case lua.LBool:
			if u {
				return []byte{1}, nil
			}
			return []byte{0}, nil
		case lua.LNumber:
			if string(u) != "0" {
				return []byte{1}, nil
			}
			return []byte{0}, nil
		default:
			return nil, fmt.Errorf("bool: expected boolean or number, got %T", val)
		}

	case abi.AddressTy:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("address: expected hex string")
		}
		raw := common.FromHex(string(s))
		word := make([]byte, common.AddressLength)
		copy(word[common.AddressLength-len(raw):], raw)
		return word, nil

	case abi.FixedBytesTy:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("bytes%d: expected string, got %T", typ.Size, val)
		}
		str := string(s)
		var raw []byte
		if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
			raw = common.FromHex(str)
		} else {
			raw = []byte(str)
		}
		if len(raw) > typ.Size {
			return nil, fmt.Errorf("bytes%d: data too long (%d bytes)", typ.Size, len(raw))
		}
		out := make([]byte, typ.Size)
		copy(out, raw)
		return out, nil

	case abi.BytesTy:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("bytes: expected string, got %T", val)
		}
		str := string(s)
		if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
			return common.FromHex(str), nil
		}
		return []byte(str), nil

	case abi.StringTy:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("string: expected string, got %T", val)
		}
		return []byte(string(s)), nil

	default:
		return nil, fmt.Errorf("unsupported type for encodePacked: %v", typ)
	}
}

// luaABIEncodePacked implements abi.encodePacked("type", val, ...) → "0x" hex.
func luaABIEncodePacked(L *lua.LState) int {
	nargs := L.GetTop()
	if nargs%2 != 0 {
		L.RaiseError("abi.encodePacked: expected (type, value) pairs, got %d args", nargs)
		return 0
	}
	var result []byte
	for i := 0; i < nargs; i += 2 {
		typStr := L.CheckString(i + 1)
		val := L.CheckAny(i + 2)
		typ, err := abi.NewType(typStr, "", nil)
		if err != nil {
			L.RaiseError("abi.encodePacked: invalid type %q: %v", typStr, err)
			return 0
		}
		b, err := abiPackedOne(typ, val)
		if err != nil {
			L.RaiseError("abi.encodePacked arg %d (%s): %v", i/2+1, typStr, err)
			return 0
		}
		result = append(result, b...)
	}
	L.Push(lua.LString("0x" + common.Bytes2Hex(result)))
	return 1
}
