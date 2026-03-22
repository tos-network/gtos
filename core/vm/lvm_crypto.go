package vm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
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
	ctValidityProofSize    = 160 // CTValidityProofSizeT1
	commitmentEqProofSize  = 192 // CommitmentEqProofSize
	rangeProofSingle64Size = 672 // single 64-bit Bulletproofs range proof
	mulProofSize           = 160 // multiplication Sigma proof
	// div/rem proof: [Enc(aux) 64B] [mul_proof 160B] [rp_r 672B] [rp_bound 672B]
	divRemProofSize = 64 + mulProofSize + 2*rangeProofSingle64Size // 1568
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
	gasCtLte         uint64 = 160000 // same proof as gt, negated
	gasCtGte         uint64 = 160000 // same proof as lt, negated
	gasCtEq          uint64 = 150000
	gasCtNe          uint64 = 150000 // same proof as eq, negated
	gasCtMin         uint64 = 170000
	gasCtMax         uint64 = 170000
	gasCtSelect      uint64 = 160000
	gasCtCommitment  uint64 = 100
	gasCtHandle      uint64 = 100
	gasCtVerifyXfer  uint64 = 100000
	gasCtVerifyEq    uint64 = 100000
	gasCtBalance     uint64 = 2600  // 2× SLOAD (commitment + handle)
	gasCtTransfer    uint64 = 18000 // 2× SLOAD + homomorphic add + 2× SSTORE + version bump
)

// Encrypted-balance storage slots — mirrored from core/priv/state.go to avoid
// a circular import (core/priv imports core/vm).
var (
	privCommitmentSlot = crypto.Keccak256Hash([]byte("gtos.priv.commitment"))
	privHandleSlot     = crypto.Keccak256Hash([]byte("gtos.priv.handle"))
	privVersionSlot    = crypto.Keccak256Hash([]byte("gtos.priv.version"))
)

// zeroCiphertextHex is the canonical encrypted-zero value as a "0x..." hex string.
// Computed once at init time so every balance/uno_value default shares the same value.
var zeroCiphertextHex string

func init() {
	out, err := cryptopriv.ZeroCiphertextCompressed()
	if err != nil {
		panic("lvm_crypto: failed to compute zero ciphertext: " + err.Error())
	}
	var z [64]byte
	copy(z[:], out)
	zeroCiphertextHex = ciphertextToHex(z)
}

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

// verifyRangeProof64 verifies a single 64-bit Bulletproofs range proof
// against the given 32-byte Pedersen commitment.
func verifyRangeProof64(commitment []byte, proof []byte) error {
	if len(proof) != rangeProofSingle64Size {
		return fmt.Errorf("range proof must be %d bytes, got %d", rangeProofSingle64Size, len(proof))
	}
	if len(commitment) < 32 {
		return fmt.Errorf("commitment must be at least 32 bytes, got %d", len(commitment))
	}
	return cryptopriv.VerifyRangeProof(proof, commitment[:32], []byte{64}, 1)
}

// verifyDivRemProofCore verifies the division relation a = b*q + r.
//
// Inputs:
//   - ctA, ctB: 64-byte ciphertexts for dividend and divisor
//   - encQ, encR: 64-byte ciphertexts for quotient and remainder
//   - subProof: [mul_proof 160B][rp_r 672B][rp_bound 672B] = 1504 bytes
//
// Verification:
//  1. Com(a-r) = Com(a) - Com(r); verify mul_proof proves value(a-r) = value(b)*value(q)
//  2. Verify range proof on Com(r) proves r ∈ [0, 2^64)
//  3. Compute diff = Com(b) - Com(r), shifted = diff - 1*G; verify range proof proves b-r-1 ∈ [0, 2^64) (i.e., r < b)
func verifyDivRemProofCore(ctA, ctB, encQ, encR []byte, subProof []byte) error {
	expectedSubLen := mulProofSize + 2*rangeProofSingle64Size
	if len(subProof) != expectedSubLen {
		return fmt.Errorf("div/rem sub-proof must be %d bytes, got %d", expectedSubLen, len(subProof))
	}

	mulPrf := subProof[:mulProofSize]
	rpR := subProof[mulProofSize : mulProofSize+rangeProofSingle64Size]
	rpBound := subProof[mulProofSize+rangeProofSingle64Size:]

	// 1. Compute Com(a-r) homomorphically and verify multiplication relation.
	comAMinusR, err := cryptopriv.SubCompressedCiphertexts(ctA, encR)
	if err != nil {
		return fmt.Errorf("compute Com(a-r): %v", err)
	}
	// Multiplication proof: proves value(Com(a-r)) = value(Com_b) * value(Com_q)
	if err := cryptopriv.VerifyMulProof(mulPrf, ctB[:32], encQ[:32], comAMinusR[:32]); err != nil {
		return fmt.Errorf("multiplication proof verification failed: %v", err)
	}

	// 2. Range proof on remainder: r ∈ [0, 2^64).
	if err := verifyRangeProof64(encR[:32], rpR); err != nil {
		return fmt.Errorf("remainder range proof failed: %v", err)
	}

	// 3. Range proof on (b - r - 1): proves r < b.
	diff, err := cryptopriv.SubCompressedCiphertexts(ctB, encR)
	if err != nil {
		return fmt.Errorf("compute b-r: %v", err)
	}
	shifted, err := cryptopriv.SubAmountCompressed(diff, 1)
	if err != nil {
		return fmt.Errorf("compute b-r-1: %v", err)
	}
	if err := verifyRangeProof64(shifted[:32], rpBound); err != nil {
		return fmt.Errorf("bound range proof failed (r < b): %v", err)
	}

	return nil
}

// verifyDivRemProof verifies a div proof where ResultData=Enc(q) and
// proof = [Enc(r) 64B][mul_proof 160B][rp_r 672B][rp_bound 672B].
func verifyDivRemProof(ctA, ctB, encQ, proof []byte) error {
	if len(proof) != divRemProofSize {
		return fmt.Errorf("div proof must be %d bytes, got %d", divRemProofSize, len(proof))
	}
	encR := proof[:64]
	return verifyDivRemProofCore(ctA, ctB, encQ, encR, proof[64:])
}

// registerCiphertextTable creates the tos.ciphertext sub-table and registers
// all encrypted-type Lua functions on it.  stateDB and contractAddr are needed
// for the bridge operations (balance, transfer) that read/write native
// encrypted-balance slots.
func registerCiphertextTable(L *lua.LState, tosTable *lua.LTable,
	chargePrimGas func(uint64), readonly bool, proofBundle *ProofBundle,
	stateDB StateDB, contractAddr common.Address) {

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

	// 10. mul(a, b) → ciphertext
	//     Proof = 160B multiplication Sigma proof.
	//     Proves: value(Com_c) = value(Com_a) * value(Com_b).
	L.SetField(ctTable, "mul", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtMul)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.mul: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.mul: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.mul: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("mul", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.mul: %v", err)
			return 0
		}
		if len(entry.ResultData) != 64 {
			L.RaiseError("ciphertext.mul: result must be 64 bytes")
			return 0
		}
		if len(entry.Proof) != mulProofSize {
			L.RaiseError("ciphertext.mul: proof must be %d bytes, got %d", mulProofSize, len(entry.Proof))
			return 0
		}
		// Verify: value(result_commitment) = value(a_commitment) * value(b_commitment)
		if err2 := cryptopriv.VerifyMulProof(entry.Proof, a[:32], b[:32], entry.ResultData[:32]); err2 != nil {
			L.RaiseError("ciphertext.mul: multiplication proof verification failed: %v", err2)
			return 0
		}
		var res [64]byte
		copy(res[:], entry.ResultData)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 11. div(a, b) → ciphertext (quotient)
	//     Proves: a = b*q + r, r ∈ [0, 2^64), r < b.
	//     ResultData = Enc(q) (64B), Proof = [Enc(r) 64B][mul_proof 160B][rp_r 672B][rp_bound 672B]
	L.SetField(ctTable, "div", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtDiv)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.div: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.div: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.div: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("div", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.div: %v", err)
			return 0
		}
		if len(entry.ResultData) != 64 {
			L.RaiseError("ciphertext.div: result must be 64 bytes")
			return 0
		}
		if len(entry.Proof) != divRemProofSize {
			L.RaiseError("ciphertext.div: proof must be %d bytes, got %d", divRemProofSize, len(entry.Proof))
			return 0
		}
		if err2 := verifyDivRemProof(a[:], b[:], entry.ResultData, entry.Proof); err2 != nil {
			L.RaiseError("ciphertext.div: %v", err2)
			return 0
		}
		var res [64]byte
		copy(res[:], entry.ResultData)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 12. rem(a, b) → ciphertext (remainder)
	//     Proves: a = b*q + r, r ∈ [0, 2^64), r < b.
	//     ResultData = Enc(r) (64B), Proof = [Enc(q) 64B][mul_proof 160B][rp_r 672B][rp_bound 672B]
	L.SetField(ctTable, "rem", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtRem)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.rem: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.rem: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.rem: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("rem", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.rem: %v", err)
			return 0
		}
		if len(entry.ResultData) != 64 {
			L.RaiseError("ciphertext.rem: result must be 64 bytes")
			return 0
		}
		if len(entry.Proof) != divRemProofSize {
			L.RaiseError("ciphertext.rem: proof must be %d bytes, got %d", divRemProofSize, len(entry.Proof))
			return 0
		}
		// For rem: ResultData=Enc(r), Proof contains Enc(q) as prefix.
		// Swap roles: quotient is in proof[0:64], remainder is ResultData.
		encQ := entry.Proof[:64]
		encR := entry.ResultData
		if err2 := verifyDivRemProofCore(a[:], b[:], encQ, encR, entry.Proof[64:]); err2 != nil {
			L.RaiseError("ciphertext.rem: %v", err2)
			return 0
		}
		var res [64]byte
		copy(res[:], entry.ResultData)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 13. lt(a, b) → bool
	//     Proof = 672B range proof.
	//     If result == true (a < b):  proves b-a-1 ∈ [0, 2^64), i.e., a < b.
	//     If result == false (a ≥ b): proves a-b ∈ [0, 2^64), i.e., a ≥ b.
	L.SetField(ctTable, "lt", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtLt)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.lt: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.lt: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.lt: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("lt", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.lt: %v", err)
			return 0
		}
		if len(entry.ResultData) != 1 {
			L.RaiseError("ciphertext.lt: bool result must be 1 byte")
			return 0
		}
		result := entry.ResultData[0] != 0
		if result {
			// a < b: diff = b - a, shifted = diff - 1. Prove shifted ∈ [0, 2^64).
			diff, err2 := cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			if err2 != nil {
				L.RaiseError("ciphertext.lt: compute diff: %v", err2)
				return 0
			}
			shifted, err2 := cryptopriv.SubAmountCompressed(diff, 1)
			if err2 != nil {
				L.RaiseError("ciphertext.lt: compute shifted: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(shifted[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.lt: range proof verification failed: %v", err2)
				return 0
			}
		} else {
			// a >= b: diff = a - b. Prove diff ∈ [0, 2^64).
			diff, err2 := cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			if err2 != nil {
				L.RaiseError("ciphertext.lt: compute diff: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diff[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.lt: range proof verification failed: %v", err2)
				return 0
			}
		}
		if result {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))

	// 14. gt(a, b) → bool
	//     Proof = 672B range proof.
	//     If result == true (a > b):  proves a-b-1 ∈ [0, 2^64), i.e., a > b.
	//     If result == false (a ≤ b): proves b-a ∈ [0, 2^64), i.e., a ≤ b.
	L.SetField(ctTable, "gt", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtGt)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.gt: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.gt: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.gt: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("gt", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.gt: %v", err)
			return 0
		}
		if len(entry.ResultData) != 1 {
			L.RaiseError("ciphertext.gt: bool result must be 1 byte")
			return 0
		}
		result := entry.ResultData[0] != 0
		if result {
			// a > b: diff = a - b, shifted = diff - 1. Prove shifted ∈ [0, 2^64).
			diff, err2 := cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			if err2 != nil {
				L.RaiseError("ciphertext.gt: compute diff: %v", err2)
				return 0
			}
			shifted, err2 := cryptopriv.SubAmountCompressed(diff, 1)
			if err2 != nil {
				L.RaiseError("ciphertext.gt: compute shifted: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(shifted[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.gt: range proof verification failed: %v", err2)
				return 0
			}
		} else {
			// a <= b: diff = b - a. Prove diff ∈ [0, 2^64).
			diff, err2 := cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			if err2 != nil {
				L.RaiseError("ciphertext.gt: compute diff: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diff[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.gt: range proof verification failed: %v", err2)
				return 0
			}
		}
		if result {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))

	// 15. eq(a, b) → bool
	//     If result == true: Proof = 1344B (two 672B range proofs).
	//       Proves a-b ∈ [0,2^64) AND b-a ∈ [0,2^64) → diff must be 0.
	//     If result == false: Proof = 673B ([direction 1B] [range_proof 672B]).
	//       direction=0 → a>b, direction=1 → b>a; proves |a-b| ≥ 1.
	L.SetField(ctTable, "eq", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtEq)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.eq: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.eq: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.eq: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("eq", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.eq: %v", err)
			return 0
		}
		if len(entry.ResultData) != 1 {
			L.RaiseError("ciphertext.eq: bool result must be 1 byte")
			return 0
		}
		result := entry.ResultData[0] != 0
		if result {
			// Equal: proof = two range proofs (1344B total).
			// Proves a-b ∈ [0,2^64) AND b-a ∈ [0,2^64) → diff = 0.
			if len(entry.Proof) != 2*rangeProofSingle64Size {
				L.RaiseError("ciphertext.eq: eq=true proof must be %d bytes, got %d",
					2*rangeProofSingle64Size, len(entry.Proof))
				return 0
			}
			diffFwd, err2 := cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			if err2 != nil {
				L.RaiseError("ciphertext.eq: compute diff_fwd: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diffFwd[:32], entry.Proof[:rangeProofSingle64Size]); err2 != nil {
				L.RaiseError("ciphertext.eq: forward range proof failed: %v", err2)
				return 0
			}
			diffBwd, err2 := cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			if err2 != nil {
				L.RaiseError("ciphertext.eq: compute diff_bwd: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diffBwd[:32], entry.Proof[rangeProofSingle64Size:]); err2 != nil {
				L.RaiseError("ciphertext.eq: backward range proof failed: %v", err2)
				return 0
			}
		} else {
			// Not equal: proof = 1B direction + 672B range proof.
			// direction=0 → a>b; direction=1 → b>a. Proves |a-b| ≥ 1.
			if len(entry.Proof) != 1+rangeProofSingle64Size {
				L.RaiseError("ciphertext.eq: eq=false proof must be %d bytes, got %d",
					1+rangeProofSingle64Size, len(entry.Proof))
				return 0
			}
			direction := entry.Proof[0]
			rangeProof := entry.Proof[1:]
			var diff []byte
			var err2 error
			if direction == 0 {
				// a > b
				diff, err2 = cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			} else {
				// b > a
				diff, err2 = cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			}
			if err2 != nil {
				L.RaiseError("ciphertext.eq: compute diff: %v", err2)
				return 0
			}
			shifted, err2 := cryptopriv.SubAmountCompressed(diff, 1)
			if err2 != nil {
				L.RaiseError("ciphertext.eq: compute shifted: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(shifted[:32], rangeProof); err2 != nil {
				L.RaiseError("ciphertext.eq: range proof failed: %v", err2)
				return 0
			}
		}
		if result {
			L.Push(lua.LTrue)
		} else {
			L.Push(lua.LFalse)
		}
		return 1
	}))

	// 15b. lte(a, b) → bool — sugar for !gt(a, b), reuses gt proof bundle.
	L.SetField(ctTable, "lte", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtLte)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.lte: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.lte: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.lte: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("lte", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.lte: %v", err)
			return 0
		}
		if len(entry.ResultData) != 1 {
			L.RaiseError("ciphertext.lte: bool result must be 1 byte")
			return 0
		}
		// lte(a,b) == !gt(a,b). Proof format identical to gt.
		gtResult := entry.ResultData[0] != 0
		if gtResult {
			// Claimed a > b: proves a-b-1 ∈ [0, 2^64).
			diff, err2 := cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			if err2 != nil {
				L.RaiseError("ciphertext.lte: compute diff: %v", err2)
				return 0
			}
			shifted, err2 := cryptopriv.SubAmountCompressed(diff, 1)
			if err2 != nil {
				L.RaiseError("ciphertext.lte: compute shifted: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(shifted[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.lte: range proof verification failed: %v", err2)
				return 0
			}
		} else {
			// Claimed a <= b: proves b-a ∈ [0, 2^64).
			diff, err2 := cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			if err2 != nil {
				L.RaiseError("ciphertext.lte: compute diff: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diff[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.lte: range proof verification failed: %v", err2)
				return 0
			}
		}
		// Negate: lte = !gt
		if gtResult {
			L.Push(lua.LFalse)
		} else {
			L.Push(lua.LTrue)
		}
		return 1
	}))

	// 15c. gte(a, b) → bool — sugar for !lt(a, b), reuses lt proof bundle.
	L.SetField(ctTable, "gte", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtGte)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.gte: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.gte: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.gte: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("gte", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.gte: %v", err)
			return 0
		}
		if len(entry.ResultData) != 1 {
			L.RaiseError("ciphertext.gte: bool result must be 1 byte")
			return 0
		}
		// gte(a,b) == !lt(a,b). Proof format identical to lt.
		ltResult := entry.ResultData[0] != 0
		if ltResult {
			// Claimed a < b: proves b-a-1 ∈ [0, 2^64).
			diff, err2 := cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			if err2 != nil {
				L.RaiseError("ciphertext.gte: compute diff: %v", err2)
				return 0
			}
			shifted, err2 := cryptopriv.SubAmountCompressed(diff, 1)
			if err2 != nil {
				L.RaiseError("ciphertext.gte: compute shifted: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(shifted[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.gte: range proof verification failed: %v", err2)
				return 0
			}
		} else {
			// Claimed a >= b: proves a-b ∈ [0, 2^64).
			diff, err2 := cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			if err2 != nil {
				L.RaiseError("ciphertext.gte: compute diff: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diff[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.gte: range proof verification failed: %v", err2)
				return 0
			}
		}
		// Negate: gte = !lt
		if ltResult {
			L.Push(lua.LFalse)
		} else {
			L.Push(lua.LTrue)
		}
		return 1
	}))

	// 15d. ne(a, b) → bool — sugar for !eq(a, b), reuses eq proof bundle.
	L.SetField(ctTable, "ne", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtNe)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.ne: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.ne: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.ne: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("ne", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.ne: %v", err)
			return 0
		}
		if len(entry.ResultData) != 1 {
			L.RaiseError("ciphertext.ne: bool result must be 1 byte")
			return 0
		}
		// ne(a,b) == !eq(a,b). Proof format identical to eq.
		eqResult := entry.ResultData[0] != 0
		if eqResult {
			// Equal: proof = two range proofs (1344B).
			if len(entry.Proof) != 2*rangeProofSingle64Size {
				L.RaiseError("ciphertext.ne: eq=true proof must be %d bytes, got %d",
					2*rangeProofSingle64Size, len(entry.Proof))
				return 0
			}
			diffFwd, err2 := cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			if err2 != nil {
				L.RaiseError("ciphertext.ne: compute diff_fwd: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diffFwd[:32], entry.Proof[:rangeProofSingle64Size]); err2 != nil {
				L.RaiseError("ciphertext.ne: forward range proof failed: %v", err2)
				return 0
			}
			diffBwd, err2 := cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			if err2 != nil {
				L.RaiseError("ciphertext.ne: compute diff_bwd: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diffBwd[:32], entry.Proof[rangeProofSingle64Size:]); err2 != nil {
				L.RaiseError("ciphertext.ne: backward range proof failed: %v", err2)
				return 0
			}
		} else {
			// Not equal: proof = 1B direction + 672B range proof.
			if len(entry.Proof) != 1+rangeProofSingle64Size {
				L.RaiseError("ciphertext.ne: eq=false proof must be %d bytes, got %d",
					1+rangeProofSingle64Size, len(entry.Proof))
				return 0
			}
			direction := entry.Proof[0]
			rangeProof := entry.Proof[1:]
			var diff []byte
			var err2 error
			if direction == 0 {
				diff, err2 = cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			} else {
				diff, err2 = cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			}
			if err2 != nil {
				L.RaiseError("ciphertext.ne: compute diff: %v", err2)
				return 0
			}
			shifted, err2 := cryptopriv.SubAmountCompressed(diff, 1)
			if err2 != nil {
				L.RaiseError("ciphertext.ne: compute shifted: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(shifted[:32], rangeProof); err2 != nil {
				L.RaiseError("ciphertext.ne: range proof failed: %v", err2)
				return 0
			}
		}
		// Negate: ne = !eq
		if eqResult {
			L.Push(lua.LFalse)
		} else {
			L.Push(lua.LTrue)
		}
		return 1
	}))

	// 16. min(a, b) → ciphertext
	//     Proof = 672B range proof. ResultData must equal a or b.
	//     If result==a: proves b≥a (range proof on (b-a)). If result==b: proves a≥b.
	L.SetField(ctTable, "min", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtMin)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.min: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.min: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.min: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("min", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.min: %v", err)
			return 0
		}
		if len(entry.ResultData) != 64 {
			L.RaiseError("ciphertext.min: result must be 64 bytes")
			return 0
		}
		if bytes.Equal(entry.ResultData, a[:]) {
			// result == a → prove b ≥ a: range proof on (b - a)
			diff, err2 := cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			if err2 != nil {
				L.RaiseError("ciphertext.min: compute diff: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diff[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.min: range proof failed: %v", err2)
				return 0
			}
		} else if bytes.Equal(entry.ResultData, b[:]) {
			// result == b → prove a ≥ b: range proof on (a - b)
			diff, err2 := cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			if err2 != nil {
				L.RaiseError("ciphertext.min: compute diff: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diff[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.min: range proof failed: %v", err2)
				return 0
			}
		} else {
			L.RaiseError("ciphertext.min: result must equal one of the inputs")
			return 0
		}
		var res [64]byte
		copy(res[:], entry.ResultData)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 17. max(a, b) → ciphertext
	//     Proof = 672B range proof. ResultData must equal a or b.
	//     If result==a: proves a≥b (range proof on (a-b)). If result==b: proves b≥a.
	L.SetField(ctTable, "max", L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtMax)
		aHex := L.CheckString(1)
		bHex := L.CheckString(2)
		a, err := parseCiphertextHex(aHex)
		if err != nil {
			L.RaiseError("ciphertext.max: %v", err)
			return 0
		}
		b, err := parseCiphertextHex(bHex)
		if err != nil {
			L.RaiseError("ciphertext.max: %v", err)
			return 0
		}
		if proofBundle == nil {
			L.RaiseError("ciphertext.max: proof bundle required")
			return 0
		}
		entry, err := proofBundle.Next("max", a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.max: %v", err)
			return 0
		}
		if len(entry.ResultData) != 64 {
			L.RaiseError("ciphertext.max: result must be 64 bytes")
			return 0
		}
		if bytes.Equal(entry.ResultData, a[:]) {
			// result == a → prove a ≥ b: range proof on (a - b)
			diff, err2 := cryptopriv.SubCompressedCiphertexts(a[:], b[:])
			if err2 != nil {
				L.RaiseError("ciphertext.max: compute diff: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diff[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.max: range proof failed: %v", err2)
				return 0
			}
		} else if bytes.Equal(entry.ResultData, b[:]) {
			// result == b → prove b ≥ a: range proof on (b - a)
			diff, err2 := cryptopriv.SubCompressedCiphertexts(b[:], a[:])
			if err2 != nil {
				L.RaiseError("ciphertext.max: compute diff: %v", err2)
				return 0
			}
			if err2 = verifyRangeProof64(diff[:32], entry.Proof); err2 != nil {
				L.RaiseError("ciphertext.max: range proof failed: %v", err2)
				return 0
			}
		} else {
			L.RaiseError("ciphertext.max: result must equal one of the inputs")
			return 0
		}
		var res [64]byte
		copy(res[:], entry.ResultData)
		L.Push(lua.LString(ciphertextToHex(res)))
		return 1
	}))

	// 18. select(cond, a, b) → ciphertext
	//     cond is a Lua boolean; selects a if true, b if false.
	//     Verification: byte-compare result against the selected input (no ZK proof needed).
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
		entry, err := proofBundle.Next("select", condByte[:], a[:], b[:])
		if err != nil {
			L.RaiseError("ciphertext.select: %v", err)
			return 0
		}
		if len(entry.ResultData) != 64 {
			L.RaiseError("ciphertext.select: result must be 64 bytes")
			return 0
		}
		// Verify result matches the selected input.
		if cond {
			if !bytes.Equal(entry.ResultData, a[:]) {
				L.RaiseError("ciphertext.select: result must equal input a when cond is true")
				return 0
			}
		} else {
			if !bytes.Equal(entry.ResultData, b[:]) {
				L.RaiseError("ciphertext.select: result must equal input b when cond is false")
				return 0
			}
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

	// ── Bridge: native encrypted-balance ↔ contract ciphertext ──────────────

	// 23. balance(addr) → ciphertext hex | nil
	//   Reads the on-chain encrypted balance (commitment || handle) of any account.
	//   Returns encrypted zero when the account has no private balance so the
	//   returned value remains type-closed for contract arithmetic.
	//   Desugared from TOL: uno.balance(addr) → tos.uno_balance(addr)
	balanceFn := L.NewFunction(func(L *lua.LState) int {
		chargePrimGas(gasCtBalance)
		addrHex := L.CheckString(1)
		addr, err := parseStrictHexAddress(addrHex)
		if err != nil {
			L.RaiseError("ciphertext.balance: %v", err)
			return 0
		}
		commitment := stateDB.GetState(addr, privCommitmentSlot)
		handle := stateDB.GetState(addr, privHandleSlot)
		if commitment == (common.Hash{}) && handle == (common.Hash{}) {
			// No encrypted balance → return encrypted zero (not nil) to
			// preserve type closure: uno.balance(addr).add(x) always works.
			L.Push(lua.LString(zeroCiphertextHex))
			return 1
		}
		var ct [64]byte
		copy(ct[:32], commitment[:])
		copy(ct[32:], handle[:])
		L.Push(lua.LString(ciphertextToHex(ct)))
		return 1
	})
	L.SetField(ctTable, "balance", balanceFn)

	// 24. transfer(toAddr, ciphertextHex)
	//   Adds a ciphertext to the recipient's native encrypted balance via
	//   homomorphic addition and increments the recipient's encrypted-balance
	//   version.  This is the encrypted-balance analogue of tos.transfer().
	//   Desugared from TOL: uno.transfer(to, ct) → tos.uno_transfer(to, ct)
	transferFn := L.NewFunction(func(L *lua.LState) int {
		if readonly {
			L.RaiseError("ciphertext.transfer: state modification not allowed in staticcall")
			return 0
		}
		chargePrimGas(gasCtTransfer)
		addrHex := L.CheckString(1)
		ctHex := L.CheckString(2)
		to, err := parseStrictHexAddress(addrHex)
		if err != nil {
			L.RaiseError("ciphertext.transfer: %v", err)
			return 0
		}
		deposit, err := parseCiphertextHex(ctHex)
		if err != nil {
			L.RaiseError("ciphertext.transfer: %v", err)
			return 0
		}

		// Read recipient's current encrypted balance.
		curCommit := stateDB.GetState(to, privCommitmentSlot)
		curHandle := stateDB.GetState(to, privHandleSlot)
		var curCt [64]byte
		copy(curCt[:32], curCommit[:])
		copy(curCt[32:], curHandle[:])

		// Homomorphic addition: newBalance = currentBalance + deposit
		var newCt [64]byte
		if curCommit == (common.Hash{}) && curHandle == (common.Hash{}) {
			// Recipient has no encrypted balance — deposit becomes the balance.
			newCt = deposit
		} else {
			out, err := cryptopriv.AddCompressedCiphertexts(curCt[:], deposit[:])
			if err != nil {
				L.RaiseError("ciphertext.transfer: homomorphic add failed: %v", err)
				return 0
			}
			copy(newCt[:], out)
		}

		// Write updated encrypted balance.
		stateDB.SetState(to, privCommitmentSlot, common.BytesToHash(newCt[:32]))
		stateDB.SetState(to, privHandleSlot, common.BytesToHash(newCt[32:]))

		// Increment recipient's encrypted-balance version.
		versionWord := stateDB.GetState(to, privVersionSlot)
		version := binary.BigEndian.Uint64(versionWord[24:])
		if version == math.MaxUint64 {
			L.RaiseError("ciphertext.transfer: recipient version overflow")
			return 0
		}
		var newVersionWord common.Hash
		binary.BigEndian.PutUint64(newVersionWord[24:], version+1)
		stateDB.SetState(to, privVersionSlot, newVersionWord)

		return 0
	})
	L.SetField(ctTable, "transfer", transferFn)

	// ── Register on tos table ────────────────────────────────────────────────
	L.SetField(tosTable, "ciphertext", ctTable)
	L.SetField(tosTable, "uno_balance", balanceFn)
	L.SetField(tosTable, "uno_transfer", transferFn)
}
