package vm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	cryptopriv "github.com/tos-network/gtos/crypto/priv"
	lua "github.com/tos-network/tolang"
)

// Ristretto255 group order: l = 2^252 + 27742317777372353535851937790883648493
var ristrettoGroupOrder = func() *big.Int {
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	return l
}()

// Proof size constants (matching core/priv/proofs.go — inlined here to avoid
// circular import since core/priv imports core/vm).
const (
	ctValidityProofSize   = 160 // CTValidityProofSizeT1
	commitmentEqProofSize = 192 // CommitmentEqProofSize
)

// Gas costs for ciphertext operations.
const (
	gasCtAdd         uint64 = 8000
	gasCtSub         uint64 = 8000
	gasCtAddScalar   uint64 = 6000
	gasCtSubScalar   uint64 = 6000
	gasCtMulScalar   uint64 = 10000
	gasCtDivScalar   uint64 = 12000
	gasCtZero        uint64 = 100
	gasCtEncrypt     uint64 = 15000
	gasCtFromParts   uint64 = 100
	gasCtMul         uint64 = 200000
	gasCtDiv         uint64 = 200000
	gasCtRem         uint64 = 200000
	gasCtLt          uint64 = 160000
	gasCtGt          uint64 = 160000
	gasCtEq          uint64 = 150000
	gasCtMin         uint64 = 170000
	gasCtMax         uint64 = 170000
	gasCtSelect      uint64 = 160000
	gasCtCommitment  uint64 = 100
	gasCtHandle      uint64 = 100
	gasCtVerifyXfer  uint64 = 100000
	gasCtVerifyEq    uint64 = 100000
)

// parseCiphertextHex decodes a 128-char hex string (with optional "0x" prefix)
// into a [64]byte.
func parseCiphertextHex(s string) ([64]byte, error) {
	var out [64]byte
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s) != 128 {
		return out, fmt.Errorf("ciphertext hex must be 128 chars, got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// ciphertextToHex encodes a [64]byte to "0x" + 128 lowercase hex chars.
func ciphertextToHex(b [64]byte) string {
	return "0x" + hex.EncodeToString(b[:])
}

// parseBytes32Hex decodes a 64-char hex string (with optional "0x" prefix)
// into a [32]byte.
func parseBytes32Hex(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s) != 64 {
		return out, fmt.Errorf("bytes32 hex must be 64 chars, got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// bytes32ToHex encodes a [32]byte to "0x" + 64 lowercase hex chars.
func bytes32ToHex(b [32]byte) string {
	return "0x" + hex.EncodeToString(b[:])
}

// uint64ToScalar32LE encodes a uint64 as a 32-byte little-endian scalar.
func uint64ToScalar32LE(n uint64) [32]byte {
	var s [32]byte
	s[0] = byte(n)
	s[1] = byte(n >> 8)
	s[2] = byte(n >> 16)
	s[3] = byte(n >> 24)
	s[4] = byte(n >> 32)
	s[5] = byte(n >> 40)
	s[6] = byte(n >> 48)
	s[7] = byte(n >> 56)
	return s
}

// bigIntToScalar32LE encodes a big.Int as a 32-byte little-endian scalar.
func bigIntToScalar32LE(n *big.Int) [32]byte {
	var s [32]byte
	b := n.Bytes() // big-endian
	// Reverse into little-endian.
	for i, j := 0, len(b)-1; i <= j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	copy(s[:], b)
	return s
}

// registerCiphertextTable creates the tos.ciphertext sub-table and registers
// all encrypted-type Lua functions on it.
func registerCiphertextTable(L *lua.LState, tosTable *lua.LTable,
	chargePrimGas func(uint64), readonly bool, proofBundle *ProofBundle) {

	ctTable := L.NewTable()

	// ── Tier 1: deterministic crypto operations ──────────────────────────────

	// 1. add(a, b) → ciphertext hex
	L.SetField(ctTable, "add", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtAdd)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.add: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.add: %v", err)
			return 0
		}
		out, err := cryptopriv.AddCompressedCiphertexts(a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.add: %v", err)
			return 0
		}
		var res [64]byte
		copy(res[:], out)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 2. sub(a, b) → ciphertext hex
	L.SetField(ctTable, "sub", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtSub)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.sub: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.sub: %v", err)
			return 0
		}
		out, err := cryptopriv.SubCompressedCiphertexts(a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.sub: %v", err)
			return 0
		}
		var res [64]byte
		copy(res[:], out)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 3. add_scalar(ct, n) → ciphertext hex
	L.SetField(ctTable, "add_scalar", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtAddScalar)
		ctHex := L.CheckString(1)
		n := uint64(L.CheckInt64(2))
		ct, err := parseCiphertextHex(ctHex)
		if err != nil {
			L.RaiseError("ciphertext.add_scalar: %v", err)
			return 0
		}
		out, err := cryptopriv.AddAmountCompressed(ct[:], n)
		if err != nil {
			L.RaiseError("ciphertext.add_scalar: %v", err)
			return 0
		}
		var res [64]byte
		copy(res[:], out)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 4. sub_scalar(ct, n) → ciphertext hex
	L.SetField(ctTable, "sub_scalar", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtSubScalar)
		ctHex := L.CheckString(1)
		n := uint64(L.CheckInt64(2))
		ct, err := parseCiphertextHex(ctHex)
		if err != nil {
			L.RaiseError("ciphertext.sub_scalar: %v", err)
			return 0
		}
		out, err := cryptopriv.SubAmountCompressed(ct[:], n)
		if err != nil {
			L.RaiseError("ciphertext.sub_scalar: %v", err)
			return 0
		}
		var res [64]byte
		copy(res[:], out)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 5. mul_scalar(ct, n) → ciphertext hex
	L.SetField(ctTable, "mul_scalar", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtMulScalar)
		ctHex := L.CheckString(1)
		n := uint64(L.CheckInt64(2))
		ct, err := parseCiphertextHex(ctHex)
		if err != nil {
			L.RaiseError("ciphertext.mul_scalar: %v", err)
			return 0
		}
		scalar := uint64ToScalar32LE(n)
		out, err := cryptopriv.MulScalarCompressed(ct[:], scalar[:])
		if err != nil {
			L.RaiseError("ciphertext.mul_scalar: %v", err)
			return 0
		}
		var res [64]byte
		copy(res[:], out)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 6. div_scalar(ct, n) → ciphertext hex
	//    Computes scalar modular inverse of n mod Ristretto group order,
	//    then calls MulScalarCompressed.
	L.SetField(ctTable, "div_scalar", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtDivScalar)
		ctHex := L.CheckString(1)
		n := uint64(L.CheckInt64(2))
		if n == 0 {
			L.RaiseError("ciphertext.div_scalar: division by zero")
			return 0
		}
		ct, err := parseCiphertextHex(ctHex)
		if err != nil {
			L.RaiseError("ciphertext.div_scalar: %v", err)
			return 0
		}
		nBig := new(big.Int).SetUint64(n)
		inv := new(big.Int).ModInverse(nBig, ristrettoGroupOrder)
		if inv == nil {
			L.RaiseError("ciphertext.div_scalar: modular inverse does not exist")
			return 0
		}
		scalar := bigIntToScalar32LE(inv)
		out, err := cryptopriv.MulScalarCompressed(ct[:], scalar[:])
		if err != nil {
			L.RaiseError("ciphertext.div_scalar: %v", err)
			return 0
		}
		var res [64]byte
		copy(res[:], out)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 7. zero() → ciphertext hex
	L.SetField(ctTable, "zero", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtZero)
		out, err := cryptopriv.ZeroCiphertextCompressed()
		if err != nil {
			L.RaiseError("ciphertext.zero: %v", err)
			return 0
		}
		var res [64]byte
		copy(res[:], out)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 8. encrypt(pk, amt) → ciphertext hex
	L.SetField(ctTable, "encrypt", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtEncrypt)
		pkHex := L.CheckString(1)
		amt := uint64(L.CheckInt64(2))
		pk, err := parseBytes32Hex(pkHex)
		if err != nil {
			L.RaiseError("ciphertext.encrypt: %v", err)
			return 0
		}
		out, err := cryptopriv.Encrypt(pk[:], amt)
		if err != nil {
			L.RaiseError("ciphertext.encrypt: %v", err)
			return 0
		}
		var res [64]byte
		copy(res[:], out)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 9. from_parts(c, h) → ciphertext hex
	L.SetField(ctTable, "from_parts", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtFromParts)
		cHex := L.CheckString(1)
		hHex := L.CheckString(2)
		c, err := parseBytes32Hex(cHex)
		if err != nil {
			L.RaiseError("ciphertext.from_parts: commitment: %v", err)
			return 0
		}
		h, err := parseBytes32Hex(hHex)
		if err != nil {
			L.RaiseError("ciphertext.from_parts: handle: %v", err)
			return 0
		}
		var res [64]byte
		copy(res[:32], c[:])
		copy(res[32:], h[:])
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// ── Tier 2: proof-based operations ───────────────────────────────────────

	// Helper for Tier-2 ciphertext-result ops (mul, div, rem, min, max).
	tier2CtOp := func(opName string, gas uint64) lua.LGFunction {
		return func(L *lua.LState) int {
			chargePrimGas(gas)
			aHex := L.CheckString(1)
			bHex := L.CheckString(2)
			a, err := parseCiphertextHex(aHex)
			if err != nil {
				L.RaiseError("ciphertext.%s: %v", opName, err)
				return 0
			}
			b, err := parseCiphertextHex(bHex)
			if err != nil {
				L.RaiseError("ciphertext.%s: %v", opName, err)
				return 0
			}
			if proofBundle == nil {
				L.RaiseError("ciphertext.%s: proof bundle required", opName)
				return 0
			}
			// TODO: implement ZK proof verification
			entry, err := proofBundle.Next(opName, a[:], b[:])
			if err != nil {
				L.RaiseError("ciphertext.%s: %v", opName, err)
				return 0
			}
			if len(entry.ResultData) != 64 {
				L.RaiseError("ciphertext.%s: result must be 64 bytes", opName)
				return 0
			}
			var res [64]byte
			copy(res[:], entry.ResultData)
			L.Push(lua.LString(ciphertextToHex(res)))
			return 1
		}
	}

	// Helper for Tier-2 boolean-result ops (lt, gt, eq).
	tier2BoolOp := func(opName string, gas uint64) lua.LGFunction {
		return func(L *lua.LState) int {
			chargePrimGas(gas)
			aHex := L.CheckString(1)
			bHex := L.CheckString(2)
			a, err := parseCiphertextHex(aHex)
			if err != nil {
				L.RaiseError("ciphertext.%s: %v", opName, err)
				return 0
			}
			b, err := parseCiphertextHex(bHex)
			if err != nil {
				L.RaiseError("ciphertext.%s: %v", opName, err)
				return 0
			}
			if proofBundle == nil {
				L.RaiseError("ciphertext.%s: proof bundle required", opName)
				return 0
			}
			// TODO: implement ZK proof verification
			entry, err := proofBundle.Next(opName, a[:], b[:])
			if err != nil {
				L.RaiseError("ciphertext.%s: %v", opName, err)
				return 0
			}
			if len(entry.ResultData) != 1 {
				L.RaiseError("ciphertext.%s: bool result must be 1 byte", opName)
				return 0
			}
			if entry.ResultData[0] != 0 {
				L.Push(lua.LTrue)
			} else {
				L.Push(lua.LFalse)
			}
			return 1
		}
	}

	// 10. mul(a, b) → ciphertext
	L.SetField(ctTable, "mul", L.NewFunction(tier2CtOp("mul", gasCtMul)))
	// 11. div(a, b) → ciphertext
	L.SetField(ctTable, "div", L.NewFunction(tier2CtOp("div", gasCtDiv)))
	// 12. rem(a, b) → ciphertext
	L.SetField(ctTable, "rem", L.NewFunction(tier2CtOp("rem", gasCtRem)))
	// 13. lt(a, b) → bool
	L.SetField(ctTable, "lt", L.NewFunction(tier2BoolOp("lt", gasCtLt)))
	// 14. gt(a, b) → bool
	L.SetField(ctTable, "gt", L.NewFunction(tier2BoolOp("gt", gasCtGt)))
	// 15. eq(a, b) → bool
	L.SetField(ctTable, "eq", L.NewFunction(tier2BoolOp("eq", gasCtEq)))
	// 16. min(a, b) → ciphertext
	L.SetField(ctTable, "min", L.NewFunction(tier2CtOp("min", gasCtMin)))
	// 17. max(a, b) → ciphertext
	L.SetField(ctTable, "max", L.NewFunction(tier2CtOp("max", gasCtMax)))

	// 18. select(cond, a, b) → ciphertext
	//     cond is a Lua boolean; selects a if true, b if false.
	L.SetField(ctTable, "select", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtSelect)
		cond := L.CheckBool(1)
		aHex := L.CheckString(2)
		bHex := L.CheckString(3)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.select: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.select: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.select: proof bundle required")
			return 0
		}
		// Encode cond as 1-byte for input hash.
		var condByte [1]byte
		if cond {
			condByte[0] = 1
		}
		// TODO: implement ZK proof verification
		entry, err := proofBundle.Next("select", condByte[:], a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.select: %v", err)
			return 0
		}
		if len(entry.ResultData) != 64 {
			L.RaiseError("ciphertext.select: result must be 64 bytes")
			return 0
		}
		var res [64]byte
		copy(res[:], entry.ResultData)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// ── Accessors ────────────────────────────────────────────────────────────

	// 19. commitment(ct) → bytes32 hex (first 32 bytes)
	L.SetField(ctTable, "commitment", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtCommitment)
		ctHex := L.CheckString(1)
		ct, err := parseCiphertextHex(ctHex)
		if err != nil {
			L.RaiseError("ciphertext.commitment: %v", err)
			return 0
		}
		var c [32]byte
		copy(c[:], ct[:32])
		L.Push(lua.LString(bytes32ToHex(c)))
		return 1
	}))

	// 20. handle(ct) → bytes32 hex (last 32 bytes)
	L.SetField(ctTable, "handle", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtHandle)
		ctHex := L.CheckString(1)
		ct, err := parseCiphertextHex(ctHex)
		if err != nil {
			L.RaiseError("ciphertext.handle: %v", err)
			return 0
		}
		var h [32]byte
		copy(h[:], ct[32:])
		L.Push(lua.LString(bytes32ToHex(h)))
		return 1
	}))

	// ── Verification ─────────────────────────────────────────────────────────

	// 21. verify_transfer(ct, senderPub, receiverPub) → bool
	//     Verifies CT validity proof from the proof bundle.
	//     ct is a 64B ciphertext (commitment[32] + senderHandle[32]).
	//     The proof bundle entry carries:
	//       ResultData = receiverHandle (32B)
	//       Proof      = 160B CT validity proof
	L.SetField(ctTable, "verify_transfer", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtVerifyXfer)
		ctHex := L.CheckString(1)
		senderPubHex := L.CheckString(2)
		receiverPubHex := L.CheckString(3)
		ct, err := parseCiphertextHex(ctHex)
		if err != nil {
			L.RaiseError("ciphertext.verify_transfer: ciphertext: %v", err)
			return 0
		}
		senderPub, err := parseBytes32Hex(senderPubHex)
		if err != nil {
			L.RaiseError("ciphertext.verify_transfer: sender pubkey: %v", err)
			return 0
		}
		receiverPub, err := parseBytes32Hex(receiverPubHex)
		if err != nil {
			L.RaiseError("ciphertext.verify_transfer: receiver pubkey: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.verify_transfer: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("verify_transfer", ct[:], senderPub[:], receiverPub[:])
		if err != nil {
			L.RaiseError("ciphertext.verify_transfer: %v", err)
			return 0
		}
		// ResultData = receiverHandle (32B)
		if len(entry.ResultData) != 32 {
			L.RaiseError("ciphertext.verify_transfer: result must be 32 bytes (receiverHandle)")
			return 0
		}
		// Proof = 160B CT validity proof
		if len(entry.Proof) != ctValidityProofSize {
			L.RaiseError("ciphertext.verify_transfer: proof must be %d bytes, got %d", ctValidityProofSize, len(entry.Proof))
			return 0
		}
		commitment := ct[:32]
		senderHandle := ct[32:]
		receiverHandle := entry.ResultData
		err = cryptopriv.VerifyCTValidityProof(
			entry.Proof,
			commitment,
			senderHandle,
			receiverHandle,
			senderPub[:],
			receiverPub[:],
			true, // T1 version
		)
		if err != nil {
			L.Push(lua.LFalse)
		} else {
			L.Push(lua.LTrue)
		}
		return 1
	}))

	// 22. verify_eq(ct, sourceCommitment, pubkey) → bool
	//     Verifies commitment equality proof from the proof bundle.
	//     ct is a 64B ciphertext, sourceCommitment is a 32B Pedersen commitment,
	//     pubkey is the 32B public key under which ct was encrypted.
	//     The proof bundle entry carries:
	//       Proof = 192B commitment equality proof
	L.SetField(ctTable, "verify_eq", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtVerifyEq)
		ctHex := L.CheckString(1)
		commitHex := L.CheckString(2)
		pkHex := L.CheckString(3)
		ct, err := parseCiphertextHex(ctHex)
		if err != nil {
			L.RaiseError("ciphertext.verify_eq: ciphertext: %v", err)
			return 0
		}
		sourceCommitment, err := parseBytes32Hex(commitHex)
		if err != nil {
			L.RaiseError("ciphertext.verify_eq: commitment: %v", err)
			return 0
		}
		pubkey, err := parseBytes32Hex(pkHex)
		if err != nil {
			L.RaiseError("ciphertext.verify_eq: pubkey: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.verify_eq: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("verify_eq", ct[:], sourceCommitment[:], pubkey[:])
		if err != nil {
			L.RaiseError("ciphertext.verify_eq: %v", err)
			return 0
		}
		// Proof = 192B commitment equality proof
		if len(entry.Proof) != commitmentEqProofSize {
			L.RaiseError("ciphertext.verify_eq: proof must be %d bytes, got %d", commitmentEqProofSize, len(entry.Proof))
			return 0
		}
		err = cryptopriv.VerifyCommitmentEqProof(
			entry.Proof,
			pubkey[:],
			ct[:], // 64B ciphertext
			sourceCommitment[:],
		)
		if err != nil {
			L.Push(lua.LFalse)
		} else {
			L.Push(lua.LTrue)
		}
		return 1
	}))

	// ── Register on tos table ────────────────────────────────────────────────
	L.SetField(tosTable, "ciphertext", ctTable)
}
