package core

// Ethereum ABI encoding/decoding for TOS Lua contracts.
//
// Supported types
//   Static (32-byte head word): bool, address, uint8..256, int8..256, bytes1..32
//   Dynamic (offset in head + length+data in tail): bytes, string
//
// Arrays and tuples are not yet supported (Phase 3A).
//
// API (all available as bare globals and via tos.abi.* prefix):
//   abi.encode("type", val, ...)          → "0x" hex  (standard ABI encoding)
//   abi.encodePacked("type", val, ...)    → "0x" hex  (tight, no padding)
//   abi.decode(hexData, "type", ...)      → val, val, ...

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/tos-network/gtos/common"
	lua "github.com/tos-network/gopher-lua"
)

// ── Type system ───────────────────────────────────────────────────────────────

type abiTypeKind int

const (
	abiKindUint       abiTypeKind = iota // uintN  (N = 8..256)
	abiKindInt                           // intN   (N = 8..256)
	abiKindBool                          // bool
	abiKindAddress                       // address (32 bytes in gtos)
	abiKindBytesFixed                    // bytesN (N = 1..32)
	abiKindBytes                         // bytes  (dynamic)
	abiKindString                        // string (dynamic)
)

type abiType struct {
	kind    abiTypeKind
	bits    int // uintN / intN: bit width (8..256)
	fixedN  int // bytesN: byte count (1..32)
	dynamic bool
}

// parseABIType parses a Solidity ABI type string.
func parseABIType(t string) (abiType, error) {
	switch t {
	case "bool":
		return abiType{kind: abiKindBool}, nil
	case "address":
		return abiType{kind: abiKindAddress}, nil
	case "bytes":
		return abiType{kind: abiKindBytes, dynamic: true}, nil
	case "string":
		return abiType{kind: abiKindString, dynamic: true}, nil
	case "uint", "uint256":
		return abiType{kind: abiKindUint, bits: 256}, nil
	case "int", "int256":
		return abiType{kind: abiKindInt, bits: 256}, nil
	}

	if strings.HasPrefix(t, "uint") {
		n, err := strconv.Atoi(t[4:])
		if err != nil || n < 8 || n > 256 || n%8 != 0 {
			return abiType{}, fmt.Errorf("invalid type %q", t)
		}
		return abiType{kind: abiKindUint, bits: n}, nil
	}
	if strings.HasPrefix(t, "int") {
		n, err := strconv.Atoi(t[3:])
		if err != nil || n < 8 || n > 256 || n%8 != 0 {
			return abiType{}, fmt.Errorf("invalid type %q", t)
		}
		return abiType{kind: abiKindInt, bits: n}, nil
	}
	if strings.HasPrefix(t, "bytes") {
		n, err := strconv.Atoi(t[5:])
		if err != nil || n < 1 || n > 32 {
			return abiType{}, fmt.Errorf("invalid type %q", t)
		}
		return abiType{kind: abiKindBytesFixed, fixedN: n}, nil
	}
	return abiType{}, fmt.Errorf("unsupported ABI type %q", t)
}

// ── Value helpers ─────────────────────────────────────────────────────────────

func abiLuaToBigInt(v lua.LValue) (*big.Int, error) {
	var s string
	switch u := v.(type) {
	case lua.LNumber:
		s = string(u)
	case lua.LString:
		s = string(u)
	default:
		return nil, fmt.Errorf("expected number or string, got %T", v)
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid integer %q", s)
	}
	return n, nil
}

func abiLuaToBytes(v lua.LValue, typeHint abiTypeKind) ([]byte, error) {
	s, ok := v.(lua.LString)
	if !ok {
		return nil, fmt.Errorf("expected string")
	}
	str := string(s)
	if typeHint == abiKindBytes && (strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X")) {
		return common.FromHex(str), nil
	}
	return []byte(str), nil
}

// ── Standard ABI encoding (abi.encode) ───────────────────────────────────────

// abiEncodeWord encodes a static type into a 32-byte ABI word.
func abiEncodeWord(typ abiType, val lua.LValue) ([]byte, error) {
	word := make([]byte, 32)
	switch typ.kind {
	case abiKindUint:
		n, err := abiLuaToBigInt(val)
		if err != nil {
			return nil, err
		}
		if n.Sign() < 0 {
			return nil, fmt.Errorf("uint cannot be negative")
		}
		n.FillBytes(word)

	case abiKindInt:
		n, err := abiLuaToBigInt(val)
		if err != nil {
			return nil, err
		}
		if n.Sign() < 0 {
			// two's complement: add 2^256
			pos := new(big.Int).Add(n, new(big.Int).Lsh(big.NewInt(1), 256))
			pos.FillBytes(word)
		} else {
			n.FillBytes(word)
		}

	case abiKindBool:
		switch u := val.(type) {
		case lua.LBool:
			if u {
				word[31] = 1
			}
		case lua.LNumber:
			if string(u) != "0" {
				word[31] = 1
			}
		default:
			return nil, fmt.Errorf("bool: expected boolean or number")
		}

	case abiKindAddress:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("address: expected string")
		}
		b := common.FromHex(string(s))
		if len(b) > 32 {
			return nil, fmt.Errorf("address: too long")
		}
		// right-aligned (left-padded with zeros)
		copy(word[32-len(b):], b)

	case abiKindBytesFixed:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("bytes%d: expected string", typ.fixedN)
		}
		str := string(s)
		var b []byte
		if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
			b = common.FromHex(str)
		} else {
			b = []byte(str)
		}
		if len(b) > typ.fixedN {
			return nil, fmt.Errorf("bytes%d: data too long (%d bytes)", typ.fixedN, len(b))
		}
		// left-aligned (right-padded with zeros)
		copy(word[:typ.fixedN], b)

	default:
		return nil, fmt.Errorf("internal: unexpected static type")
	}
	return word, nil
}

// abiEncodeDynamic encodes a dynamic type into length-word + padded data.
func abiEncodeDynamic(typ abiType, val lua.LValue) ([]byte, error) {
	data, err := abiLuaToBytes(val, typ.kind)
	if err != nil {
		return nil, err
	}
	// 32-byte length word
	lenWord := make([]byte, 32)
	new(big.Int).SetInt64(int64(len(data))).FillBytes(lenWord)
	// data padded to 32-byte boundary
	padLen := (len(data) + 31) &^ 31
	padded := make([]byte, padLen)
	copy(padded, data)
	return append(lenWord, padded...), nil
}

// luaABIEncode implements abi.encode("type", val, ...) → "0x" hex.
func luaABIEncode(L *lua.LState) int {
	nargs := L.GetTop()
	if nargs%2 != 0 {
		L.RaiseError("abi.encode: expected (type, value) pairs, got %d args", nargs)
		return 0
	}
	n := nargs / 2
	types := make([]abiType, n)
	vals := make([]lua.LValue, n)
	for i := 0; i < n; i++ {
		typStr := L.CheckString(i*2 + 1)
		typ, err := parseABIType(typStr)
		if err != nil {
			L.RaiseError("abi.encode: %v", err)
			return 0
		}
		types[i] = typ
		vals[i] = L.CheckAny(i*2 + 2)
	}

	headSize := 32 * n
	head := make([]byte, 0, headSize)
	tail := make([]byte, 0)

	for i, typ := range types {
		if !typ.dynamic {
			word, err := abiEncodeWord(typ, vals[i])
			if err != nil {
				L.RaiseError("abi.encode arg %d (%s): %v", i+1, L.CheckString(i*2+1), err)
				return 0
			}
			head = append(head, word...)
		} else {
			// offset = start-of-tail relative to start-of-encoding
			offset := headSize + len(tail)
			offsetWord := make([]byte, 32)
			new(big.Int).SetInt64(int64(offset)).FillBytes(offsetWord)
			head = append(head, offsetWord...)
			dynData, err := abiEncodeDynamic(typ, vals[i])
			if err != nil {
				L.RaiseError("abi.encode arg %d (%s): %v", i+1, L.CheckString(i*2+1), err)
				return 0
			}
			tail = append(tail, dynData...)
		}
	}

	result := append(head, tail...)
	L.Push(lua.LString("0x" + common.Bytes2Hex(result)))
	return 1
}

// ── Packed ABI encoding (abi.encodePacked) ────────────────────────────────────

// abiEncodePackedOne encodes one value in packed (tight) format.
func abiEncodePackedOne(typ abiType, val lua.LValue) ([]byte, error) {
	switch typ.kind {
	case abiKindUint:
		n, err := abiLuaToBigInt(val)
		if err != nil {
			return nil, err
		}
		byteLen := typ.bits / 8
		b := make([]byte, byteLen)
		n.FillBytes(b)
		return b, nil

	case abiKindInt:
		n, err := abiLuaToBigInt(val)
		if err != nil {
			return nil, err
		}
		byteLen := typ.bits / 8
		b := make([]byte, byteLen)
		if n.Sign() < 0 {
			mask := new(big.Int).Lsh(big.NewInt(1), uint(typ.bits))
			new(big.Int).Add(n, mask).FillBytes(b)
		} else {
			n.FillBytes(b)
		}
		return b, nil

	case abiKindBool:
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
		}
		return nil, fmt.Errorf("bool: expected boolean or number")

	case abiKindAddress:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("address: expected string")
		}
		b := common.FromHex(string(s))
		// gtos addresses are 32 bytes; right-align into 32-byte buffer
		word := make([]byte, 32)
		copy(word[32-len(b):], b)
		return word, nil

	case abiKindBytesFixed:
		s, ok := val.(lua.LString)
		if !ok {
			return nil, fmt.Errorf("bytes%d: expected string", typ.fixedN)
		}
		str := string(s)
		var b []byte
		if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
			b = common.FromHex(str)
		} else {
			b = []byte(str)
		}
		if len(b) > typ.fixedN {
			return nil, fmt.Errorf("bytes%d: data too long (%d bytes)", typ.fixedN, len(b))
		}
		// exactly fixedN bytes, right-padded with zeros
		out := make([]byte, typ.fixedN)
		copy(out, b)
		return out, nil

	case abiKindBytes:
		data, err := abiLuaToBytes(val, abiKindBytes)
		return data, err

	case abiKindString:
		data, err := abiLuaToBytes(val, abiKindString)
		return data, err
	}
	return nil, fmt.Errorf("unsupported type")
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
		typ, err := parseABIType(typStr)
		if err != nil {
			L.RaiseError("abi.encodePacked: %v", err)
			return 0
		}
		b, err := abiEncodePackedOne(typ, val)
		if err != nil {
			L.RaiseError("abi.encodePacked arg %d (%s): %v", i/2+1, typStr, err)
			return 0
		}
		result = append(result, b...)
	}
	L.Push(lua.LString("0x" + common.Bytes2Hex(result)))
	return 1
}

// ── Standard ABI decoding (abi.decode) ───────────────────────────────────────

// abiDecodeWord decodes a static type from a 32-byte ABI word.
func abiDecodeWord(typ abiType, word []byte) (lua.LValue, error) {
	switch typ.kind {
	case abiKindUint:
		n := new(big.Int).SetBytes(word)
		return lua.LNumber(n.Text(10)), nil

	case abiKindInt:
		n := new(big.Int).SetBytes(word)
		// sign bit is the MSB of the 32-byte word
		if word[0]&0x80 != 0 {
			n.Sub(n, new(big.Int).Lsh(big.NewInt(1), 256))
		}
		return lua.LNumber(n.Text(10)), nil

	case abiKindBool:
		if word[31] == 0 {
			return lua.LFalse, nil
		}
		return lua.LTrue, nil

	case abiKindAddress:
		return lua.LString(common.BytesToAddress(word).Hex()), nil

	case abiKindBytesFixed:
		return lua.LString("0x" + common.Bytes2Hex(word[:typ.fixedN])), nil
	}
	return nil, fmt.Errorf("internal: unexpected static type")
}

// abiDecodeDynamic decodes a dynamic type from an absolute offset in data.
func abiDecodeDynamic(typ abiType, data []byte, offset int) (lua.LValue, error) {
	if offset+32 > len(data) {
		return nil, fmt.Errorf("dynamic length field out of range (offset %d, data len %d)", offset, len(data))
	}
	length := int(new(big.Int).SetBytes(data[offset : offset+32]).Uint64())
	offset += 32
	if offset+length > len(data) {
		return nil, fmt.Errorf("dynamic data out of range (need %d bytes at offset %d, data len %d)", length, offset, len(data))
	}
	content := data[offset : offset+length]
	if typ.kind == abiKindBytes {
		return lua.LString("0x" + common.Bytes2Hex(content)), nil
	}
	// string: return as-is UTF-8
	return lua.LString(string(content)), nil
}

// luaABIDecode implements abi.decode(hexData, "type", ...) → val, val, ...
func luaABIDecode(L *lua.LState) int {
	nargs := L.GetTop()
	if nargs < 2 {
		L.RaiseError("abi.decode: at least 2 arguments required (data, type...)")
		return 0
	}
	hexData := L.CheckString(1)
	data := common.FromHex(hexData)

	n := nargs - 1
	types := make([]abiType, n)
	for i := 0; i < n; i++ {
		typStr := L.CheckString(i + 2)
		typ, err := parseABIType(typStr)
		if err != nil {
			L.RaiseError("abi.decode: %v", err)
			return 0
		}
		types[i] = typ
	}

	headOffset := 0
	results := make([]lua.LValue, n)
	for i, typ := range types {
		if headOffset+32 > len(data) {
			L.RaiseError("abi.decode: data too short for arg %d (offset %d, data len %d)", i+1, headOffset, len(data))
			return 0
		}
		if !typ.dynamic {
			word := data[headOffset : headOffset+32]
			val, err := abiDecodeWord(typ, word)
			if err != nil {
				L.RaiseError("abi.decode arg %d: %v", i+1, err)
				return 0
			}
			results[i] = val
		} else {
			dynOffset := int(new(big.Int).SetBytes(data[headOffset : headOffset+32]).Uint64())
			val, err := abiDecodeDynamic(typ, data, dynOffset)
			if err != nil {
				L.RaiseError("abi.decode arg %d: %v", i+1, err)
				return 0
			}
			results[i] = val
		}
		headOffset += 32
	}

	for _, v := range results {
		L.Push(v)
	}
	return n
}
