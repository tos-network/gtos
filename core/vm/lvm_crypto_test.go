package vm

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/tos-network/gtos/common"
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

// testKeypair generates an ElGamal keypair for testing.
func testKeypair(t *testing.T) (pub [32]byte, priv [32]byte) {
	t.Helper()
	pubSlice, privSlice, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	copy(pub[:], pubSlice)
	copy(priv[:], privSlice)
	return
}

func TestCtZero(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xC0}

	src := `
local z = tos.ciphertext.zero()
if type(z) ~= "string" then
  error("expected string, got " .. type(z))
end
-- 0x prefix + 128 hex chars = 130 total
if #z ~= 130 then
  error("expected 130 chars, got " .. #z)
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("tos.ciphertext.zero: %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtFromParts(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xC1}

	// Two known bytes32 values.
	c := strings.Repeat("aa", 32)
	h := strings.Repeat("bb", 32)
	expected := "0x" + c + h

	src := `
local ct = tos.ciphertext.from_parts("0x` + c + `", "0x` + h + `")
if ct ~= "` + expected + `" then
  error("from_parts mismatch: got " .. ct)
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("tos.ciphertext.from_parts: %v", err)
	}
}

func TestCtAddSub(t *testing.T) {
	pub, _ := testKeypair(t)
	pubHex := "0x" + hex.EncodeToString(pub[:])

	st := newAgentTestState()
	contractAddr := common.Address{0xC2}

	// Encrypt 10 and 5, add them, sub the second, result should equal encrypt(10).
	// We can't compare ciphertexts directly (randomised encryption), but we can
	// verify the operations don't error and produce valid-length output.
	src := `
local ct = tos.ciphertext
local a = ct.encrypt("` + pubHex + `", 10)
local b = ct.encrypt("` + pubHex + `", 5)
local sum = ct.add(a, b)
local diff = ct.sub(sum, b)
-- Verify all are valid 130-char hex strings.
if #sum ~= 130 then error("sum length: " .. #sum) end
if #diff ~= 130 then error("diff length: " .. #diff) end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("tos.ciphertext.add/sub: %v", err)
	}
}

func TestCtAddSubScalar(t *testing.T) {
	pub, _ := testKeypair(t)
	pubHex := "0x" + hex.EncodeToString(pub[:])

	st := newAgentTestState()
	contractAddr := common.Address{0xC3}

	src := `
local ct = tos.ciphertext
local a = ct.encrypt("` + pubHex + `", 100)
local added = ct.add_scalar(a, 50)
local back = ct.sub_scalar(added, 50)
if #added ~= 130 then error("add_scalar length: " .. #added) end
if #back ~= 130 then error("sub_scalar length: " .. #back) end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("tos.ciphertext.add_scalar/sub_scalar: %v", err)
	}
}

func TestCtMulScalar(t *testing.T) {
	pub, _ := testKeypair(t)
	pubHex := "0x" + hex.EncodeToString(pub[:])

	st := newAgentTestState()
	contractAddr := common.Address{0xC4}

	src := `
local ct = tos.ciphertext
local a = ct.encrypt("` + pubHex + `", 7)
local scaled = ct.mul_scalar(a, 3)
if #scaled ~= 130 then error("mul_scalar length: " .. #scaled) end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("tos.ciphertext.mul_scalar: %v", err)
	}
}

func TestCtCommitmentHandle(t *testing.T) {
	pub, _ := testKeypair(t)
	pubHex := "0x" + hex.EncodeToString(pub[:])

	st := newAgentTestState()
	contractAddr := common.Address{0xC5}

	src := `
local ct = tos.ciphertext
local a = ct.encrypt("` + pubHex + `", 42)
local c = ct.commitment(a)
local h = ct.handle(a)
-- Both should be 66 chars (0x + 64 hex).
if #c ~= 66 then error("commitment length: " .. #c) end
if #h ~= 66 then error("handle length: " .. #h) end
-- from_parts roundtrip.
local rebuilt = ct.from_parts(c, h)
if rebuilt ~= a then
  error("from_parts roundtrip mismatch")
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("tos.ciphertext.commitment/handle: %v", err)
	}
}

func TestCtTier2NoBundleReverts(t *testing.T) {
	pub, _ := testKeypair(t)
	pubHex := "0x" + hex.EncodeToString(pub[:])

	st := newAgentTestState()
	contractAddr := common.Address{0xC6}

	// Call mul without a proof bundle — should error.
	src := `
local ct = tos.ciphertext
local a = ct.encrypt("` + pubHex + `", 10)
local b = ct.encrypt("` + pubHex + `", 5)
ct.mul(a, b)
`
	_, _, _, err := runLua(st, contractAddr, src, 2_000_000)
	if err == nil {
		t.Fatal("expected error when calling mul without proof bundle")
	}
	if !strings.Contains(err.Error(), "proof bundle required") {
		t.Fatalf("expected 'proof bundle required' error, got: %v", err)
	}
}

func TestCtTier2WithBundle(t *testing.T) {
	pub, _ := testKeypair(t)

	st := newAgentTestState()
	contractAddr := common.Address{0xC7}

	valA, valB := uint64(10), uint64(5)
	valC := valA * valB

	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	openC, _ := cryptopriv.GenerateOpening()

	aBytes := buildCtFromOpening(t, pub[:], openA, valA)
	bBytes := buildCtFromOpening(t, pub[:], openB, valB)
	cBytes := buildCtFromOpening(t, pub[:], openC, valC)

	// Generate real multiplication proof.
	mulProof, err := cryptopriv.ProveMulProof(aBytes[:32], bBytes[:32], cBytes[:32], valA, openA, openB, openC)
	if err != nil {
		t.Fatalf("ProveMulProof: %v", err)
	}

	inputHash := makeInputHash("mul", aBytes, bBytes)
	entries := []ProofEntry{
		{
			Op:         "mul",
			InputHash:  inputHash,
			ResultData: cBytes,
			Proof:      mulProof,
		},
	}
	bundleBytes := EncodeProofBundle(entries)

	aHex := "0x" + hex.EncodeToString(aBytes)
	bHex := "0x" + hex.EncodeToString(bBytes)
	expectedResult := "0x" + hex.EncodeToString(cBytes)

	src := `
local ct = tos.ciphertext
local result = ct.mul("` + aHex + `", "` + bHex + `")
if result ~= "` + expectedResult + `" then
  error("mul result mismatch: got " .. result)
end
tos.sstore("ok", 1)
`

	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       contractAddr,
		Value:    big.NewInt(0),
		Data:     bundleBytes,
		TxOrigin: common.Address{0xFF},
		TxPrice:  big.NewInt(1),
	}
	_, _, _, err = Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), 2_000_000)
	if err != nil {
		t.Fatalf("tos.ciphertext.mul with bundle: %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtVerifyTransferReal(t *testing.T) {
	senderPub, _, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	receiverPub, _, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	opening, err := cryptopriv.GenerateOpening()
	if err != nil {
		t.Fatal(err)
	}
	amount := uint64(42)

	// Generate a real CT validity proof.
	ctProof, commitment, senderHandle, receiverHandle, err := cryptopriv.ProveCTValidityProof(
		senderPub, receiverPub, amount, opening, true,
	)
	if err != nil {
		t.Fatalf("ProveCTValidityProof: %v", err)
	}

	// Build the ciphertext as commitment+senderHandle (what the contract sees).
	var ct [64]byte
	copy(ct[:32], commitment)
	copy(ct[32:], senderHandle)

	// Build proof bundle entry: ResultData=receiverHandle, Proof=ctProof
	inputHash := makeInputHash("verify_transfer", ct[:], senderPub, receiverPub)
	entries := []ProofEntry{{
		Op:         "verify_transfer",
		InputHash:  inputHash,
		ResultData: receiverHandle,
		Proof:      ctProof,
	}}
	bundleBytes := EncodeProofBundle(entries)

	st := newAgentTestState()
	contractAddr := common.Address{0xD0}

	ctHex := "0x" + hex.EncodeToString(ct[:])
	sPubHex := "0x" + hex.EncodeToString(senderPub)
	rPubHex := "0x" + hex.EncodeToString(receiverPub)

	src := `
local result = tos.ciphertext.verify_transfer("` + ctHex + `", "` + sPubHex + `", "` + rPubHex + `")
if result ~= true then
  error("verify_transfer should return true for valid proof")
end
tos.sstore("ok", 1)
`
	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       contractAddr,
		Value:    big.NewInt(0),
		Data:     bundleBytes,
		TxOrigin: common.Address{0xFF},
		TxPrice:  big.NewInt(1),
	}
	_, _, _, err = Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), 2_000_000)
	if err != nil {
		t.Fatalf("verify_transfer with valid proof: %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtVerifyTransferInvalidProof(t *testing.T) {
	senderPub, _, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	receiverPub, _, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	opening, err := cryptopriv.GenerateOpening()
	if err != nil {
		t.Fatal(err)
	}

	_, commitment, senderHandle, receiverHandle, err := cryptopriv.ProveCTValidityProof(
		senderPub, receiverPub, 42, opening, true,
	)
	if err != nil {
		t.Fatal(err)
	}

	var ct [64]byte
	copy(ct[:32], commitment)
	copy(ct[32:], senderHandle)

	// Tamper the proof — fill with zeros (still 160B).
	badProof := make([]byte, 160)

	inputHash := makeInputHash("verify_transfer", ct[:], senderPub, receiverPub)
	entries := []ProofEntry{{
		Op:         "verify_transfer",
		InputHash:  inputHash,
		ResultData: receiverHandle,
		Proof:      badProof,
	}}
	bundleBytes := EncodeProofBundle(entries)

	st := newAgentTestState()
	contractAddr := common.Address{0xD1}

	ctHex := "0x" + hex.EncodeToString(ct[:])
	sPubHex := "0x" + hex.EncodeToString(senderPub)
	rPubHex := "0x" + hex.EncodeToString(receiverPub)

	src := `
local result = tos.ciphertext.verify_transfer("` + ctHex + `", "` + sPubHex + `", "` + rPubHex + `")
if result ~= false then
  error("verify_transfer should return false for invalid proof")
end
tos.sstore("ok", 1)
`
	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       contractAddr,
		Value:    big.NewInt(0),
		Data:     bundleBytes,
		TxOrigin: common.Address{0xFF},
		TxPrice:  big.NewInt(1),
	}
	_, _, _, err = Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), 2_000_000)
	if err != nil {
		t.Fatalf("verify_transfer with invalid proof: %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtVerifyEqReal(t *testing.T) {
	pub, priv, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	opening, err := cryptopriv.GenerateOpening()
	if err != nil {
		t.Fatal(err)
	}
	amount := uint64(29)

	// Build ciphertext from opening.
	commitment, err := cryptopriv.PedersenCommitmentWithOpening(opening, amount)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := cryptopriv.DecryptHandleWithOpening(pub, opening)
	if err != nil {
		t.Fatal(err)
	}
	var ct [64]byte
	copy(ct[:32], commitment)
	copy(ct[32:], handle)

	// Generate commitment equality proof (no transcript context for LVM).
	eqProof, err := cryptopriv.ProveCommitmentEqProof(priv, pub, ct[:], commitment, opening, amount, nil)
	if err != nil {
		t.Fatalf("ProveCommitmentEqProof: %v", err)
	}

	var sourceCommit [32]byte
	copy(sourceCommit[:], commitment)

	inputHash := makeInputHash("verify_eq", ct[:], sourceCommit[:], pub)
	entries := []ProofEntry{{
		Op:        "verify_eq",
		InputHash: inputHash,
		Proof:     eqProof,
	}}
	bundleBytes := EncodeProofBundle(entries)

	st := newAgentTestState()
	contractAddr := common.Address{0xD2}

	ctHex := "0x" + hex.EncodeToString(ct[:])
	commitHex := "0x" + hex.EncodeToString(sourceCommit[:])
	pkHex := "0x" + hex.EncodeToString(pub)

	src := `
local result = tos.ciphertext.verify_eq("` + ctHex + `", "` + commitHex + `", "` + pkHex + `")
if result ~= true then
  error("verify_eq should return true for valid proof")
end
tos.sstore("ok", 1)
`
	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       contractAddr,
		Value:    big.NewInt(0),
		Data:     bundleBytes,
		TxOrigin: common.Address{0xFF},
		TxPrice:  big.NewInt(1),
	}
	_, _, _, err = Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), 2_000_000)
	if err != nil {
		t.Fatalf("verify_eq with valid proof: %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtVerifyEqInvalidProof(t *testing.T) {
	pub, _, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	opening, err := cryptopriv.GenerateOpening()
	if err != nil {
		t.Fatal(err)
	}

	commitment, err := cryptopriv.PedersenCommitmentWithOpening(opening, 29)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := cryptopriv.DecryptHandleWithOpening(pub, opening)
	if err != nil {
		t.Fatal(err)
	}
	var ct [64]byte
	copy(ct[:32], commitment)
	copy(ct[32:], handle)

	var sourceCommit [32]byte
	copy(sourceCommit[:], commitment)

	// Tampered proof — all zeros, still 192B.
	badProof := make([]byte, 192)

	inputHash := makeInputHash("verify_eq", ct[:], sourceCommit[:], pub)
	entries := []ProofEntry{{
		Op:        "verify_eq",
		InputHash: inputHash,
		Proof:     badProof,
	}}
	bundleBytes := EncodeProofBundle(entries)

	st := newAgentTestState()
	contractAddr := common.Address{0xD3}

	ctHex := "0x" + hex.EncodeToString(ct[:])
	commitHex := "0x" + hex.EncodeToString(sourceCommit[:])
	pkHex := "0x" + hex.EncodeToString(pub)

	src := `
local result = tos.ciphertext.verify_eq("` + ctHex + `", "` + commitHex + `", "` + pkHex + `")
if result ~= false then
  error("verify_eq should return false for invalid proof")
end
tos.sstore("ok", 1)
`
	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       contractAddr,
		Value:    big.NewInt(0),
		Data:     bundleBytes,
		TxOrigin: common.Address{0xFF},
		TxPrice:  big.NewInt(1),
	}
	_, _, _, err = Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), 2_000_000)
	if err != nil {
		t.Fatalf("verify_eq with invalid proof: %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

// --- Tier-2 real verification tests ---

// buildCtFromOpening constructs a ciphertext from a known opening and amount.
func buildCtFromOpening(t *testing.T, pub []byte, opening []byte, amount uint64) []byte {
	t.Helper()
	commitment, err := cryptopriv.PedersenCommitmentWithOpening(opening, amount)
	if err != nil {
		t.Fatalf("PedersenCommitmentWithOpening: %v", err)
	}
	handle, err := cryptopriv.DecryptHandleWithOpening(pub, opening)
	if err != nil {
		t.Fatalf("DecryptHandleWithOpening: %v", err)
	}
	ct := make([]byte, 64)
	copy(ct[:32], commitment)
	copy(ct[32:], handle)
	return ct
}

// scalarSub computes (a - b) mod ristrettoGroupOrder, returning 32-byte LE scalar.
func scalarSub(a, b []byte) []byte {
	aBig := new(big.Int).SetBytes(reverseBytes32(a))
	bBig := new(big.Int).SetBytes(reverseBytes32(b))
	diff := new(big.Int).Sub(aBig, bBig)
	diff.Mod(diff, ristrettoGroupOrder)
	s := bigIntToScalar32LE(diff)
	return s[:]
}

func reverseBytes32(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[len(in)-1-i] = b
	}
	return out
}

// runLuaWithBundle runs Lua source with a proof bundle attached to calldata.
func runLuaWithBundle(t *testing.T, st StateDB, contractAddr common.Address,
	src string, bundleBytes []byte, gas uint64) error {
	t.Helper()
	ctx := CallCtx{
		From: common.Address{0xFF}, To: contractAddr,
		Value: big.NewInt(0), Data: bundleBytes,
		TxOrigin: common.Address{0xFF}, TxPrice: big.NewInt(1),
	}
	_, _, _, err := Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), gas)
	return err
}

func TestCtLtReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	valA, valB := uint64(3), uint64(7)

	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)

	// lt(a, b)=true: diff=sub(b,a), shifted=sub_scalar(diff,1), prove shifted ∈ [0,2^64)
	diff, _ := cryptopriv.SubCompressedCiphertexts(ctB, ctA)
	shifted, _ := cryptopriv.SubAmountCompressed(diff, 1)
	openDiff := scalarSub(openB, openA)
	rangeProof, err := cryptopriv.ProveRangeProof(shifted[:32], valB-valA-1, openDiff)
	if err != nil {
		t.Fatalf("ProveRangeProof: %v", err)
	}

	inputHash := makeInputHash("lt", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "lt", InputHash: inputHash, ResultData: []byte{1}, Proof: rangeProof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xE0}
	src := `
local r = tos.ciphertext.lt("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= true then error("expected true") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000); err != nil {
		t.Fatalf("lt valid: %v", err)
	}
}

func TestCtLtInvalidProof(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	ctA := buildCtFromOpening(t, pub, openA, 3)
	ctB := buildCtFromOpening(t, pub, openB, 7)

	inputHash := makeInputHash("lt", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "lt", InputHash: inputHash, ResultData: []byte{1}, Proof: make([]byte, 672),
	}})

	st := newAgentTestState()
	addr := common.Address{0xE1}
	src := `tos.ciphertext.lt("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")`
	err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000)
	if err == nil || !strings.Contains(err.Error(), "range proof") {
		t.Fatalf("expected range proof error, got: %v", err)
	}
}

func TestCtGtReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	valA, valB := uint64(7), uint64(3)

	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)

	diff, _ := cryptopriv.SubCompressedCiphertexts(ctA, ctB)
	shifted, _ := cryptopriv.SubAmountCompressed(diff, 1)
	openDiff := scalarSub(openA, openB)
	rangeProof, _ := cryptopriv.ProveRangeProof(shifted[:32], valA-valB-1, openDiff)

	inputHash := makeInputHash("gt", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "gt", InputHash: inputHash, ResultData: []byte{1}, Proof: rangeProof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xE2}
	src := `
local r = tos.ciphertext.gt("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= true then error("expected true") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000); err != nil {
		t.Fatalf("gt valid: %v", err)
	}
}

func TestCtEqTrueReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	val := uint64(5)

	ctA := buildCtFromOpening(t, pub, openA, val)
	ctB := buildCtFromOpening(t, pub, openB, val)

	diffFwd, _ := cryptopriv.SubCompressedCiphertexts(ctA, ctB)
	diffBwd, _ := cryptopriv.SubCompressedCiphertexts(ctB, ctA)
	openFwd := scalarSub(openA, openB)
	openBwd := scalarSub(openB, openA)
	rpFwd, _ := cryptopriv.ProveRangeProof(diffFwd[:32], 0, openFwd)
	rpBwd, _ := cryptopriv.ProveRangeProof(diffBwd[:32], 0, openBwd)

	inputHash := makeInputHash("eq", ctA, ctB)
	proof := append(rpFwd, rpBwd...)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "eq", InputHash: inputHash, ResultData: []byte{1}, Proof: proof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xE3}
	src := `
local r = tos.ciphertext.eq("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= true then error("expected true") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000); err != nil {
		t.Fatalf("eq=true valid: %v", err)
	}
}

func TestCtEqFalseReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	valA, valB := uint64(5), uint64(8)

	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)

	// direction=1 (b > a)
	diff, _ := cryptopriv.SubCompressedCiphertexts(ctB, ctA)
	shifted, _ := cryptopriv.SubAmountCompressed(diff, 1)
	openDiff := scalarSub(openB, openA)
	rp, _ := cryptopriv.ProveRangeProof(shifted[:32], valB-valA-1, openDiff)

	inputHash := makeInputHash("eq", ctA, ctB)
	proof := append([]byte{1}, rp...) // direction=1
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "eq", InputHash: inputHash, ResultData: []byte{0}, Proof: proof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xE4}
	src := `
local r = tos.ciphertext.eq("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= false then error("expected false") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000); err != nil {
		t.Fatalf("eq=false valid: %v", err)
	}
}

func TestCtMinReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	valA, valB := uint64(3), uint64(7)

	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)

	// min=ctA → prove b ≥ a: range proof on sub(b, a)
	diff, _ := cryptopriv.SubCompressedCiphertexts(ctB, ctA)
	openDiff := scalarSub(openB, openA)
	rp, _ := cryptopriv.ProveRangeProof(diff[:32], valB-valA, openDiff)

	inputHash := makeInputHash("min", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "min", InputHash: inputHash, ResultData: ctA, Proof: rp,
	}})

	st := newAgentTestState()
	addr := common.Address{0xE5}
	src := `
local r = tos.ciphertext.min("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= "0x` + hex.EncodeToString(ctA) + `" then error("expected ctA") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000); err != nil {
		t.Fatalf("min valid: %v", err)
	}
}

func TestCtMaxReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	valA, valB := uint64(3), uint64(7)

	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)

	// max=ctB → prove b ≥ a: range proof on sub(b, a)
	diff, _ := cryptopriv.SubCompressedCiphertexts(ctB, ctA)
	openDiff := scalarSub(openB, openA)
	rp, _ := cryptopriv.ProveRangeProof(diff[:32], valB-valA, openDiff)

	inputHash := makeInputHash("max", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "max", InputHash: inputHash, ResultData: ctB, Proof: rp,
	}})

	st := newAgentTestState()
	addr := common.Address{0xE6}
	src := `
local r = tos.ciphertext.max("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= "0x` + hex.EncodeToString(ctB) + `" then error("expected ctB") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000); err != nil {
		t.Fatalf("max valid: %v", err)
	}
}

func TestCtSelectReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	ctA := buildCtFromOpening(t, pub, openA, 10)
	ctB := buildCtFromOpening(t, pub, openB, 20)

	inputHash := makeInputHash("select", []byte{1}, ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "select", InputHash: inputHash, ResultData: ctA,
	}})

	st := newAgentTestState()
	addr := common.Address{0xE7}
	src := `
local r = tos.ciphertext.select(true, "0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= "0x` + hex.EncodeToString(ctA) + `" then error("expected ctA") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000); err != nil {
		t.Fatalf("select valid: %v", err)
	}
}

func TestCtSelectWrongResult(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	ctA := buildCtFromOpening(t, pub, func() []byte { o, _ := cryptopriv.GenerateOpening(); return o }(), 10)
	ctB := buildCtFromOpening(t, pub, func() []byte { o, _ := cryptopriv.GenerateOpening(); return o }(), 20)

	// cond=true but result=ctB (wrong)
	inputHash := makeInputHash("select", []byte{1}, ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "select", InputHash: inputHash, ResultData: ctB,
	}})

	st := newAgentTestState()
	addr := common.Address{0xE8}
	src := `tos.ciphertext.select(true, "0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")`
	err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000)
	if err == nil || !strings.Contains(err.Error(), "must equal input a") {
		t.Fatalf("expected 'must equal input a' error, got: %v", err)
	}
}

func TestCtMinWrongResult(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	ctA := buildCtFromOpening(t, pub, func() []byte { o, _ := cryptopriv.GenerateOpening(); return o }(), 3)
	ctB := buildCtFromOpening(t, pub, func() []byte { o, _ := cryptopriv.GenerateOpening(); return o }(), 7)

	fakeResult := make([]byte, 64)
	fakeResult[0] = 0xFF
	inputHash := makeInputHash("min", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "min", InputHash: inputHash, ResultData: fakeResult, Proof: make([]byte, 672),
	}})

	st := newAgentTestState()
	addr := common.Address{0xE9}
	src := `tos.ciphertext.min("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")`
	err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000)
	if err == nil || !strings.Contains(err.Error(), "must equal one of the inputs") {
		t.Fatalf("expected 'must equal one of the inputs' error, got: %v", err)
	}
}

// --- Mul/Div/Rem real proof tests ---

// scalarMul computes (a * b) mod ristrettoGroupOrder, returning 32-byte LE scalar.
func scalarMul(a, b []byte) []byte {
	aBig := new(big.Int).SetBytes(reverseBytes32(a))
	bBig := new(big.Int).SetBytes(reverseBytes32(b))
	product := new(big.Int).Mul(aBig, bBig)
	product.Mod(product, ristrettoGroupOrder)
	s := bigIntToScalar32LE(product)
	return s[:]
}

// scalarAdd computes (a + b) mod ristrettoGroupOrder, returning 32-byte LE scalar.
func scalarAdd(a, b []byte) []byte {
	aBig := new(big.Int).SetBytes(reverseBytes32(a))
	bBig := new(big.Int).SetBytes(reverseBytes32(b))
	sum := new(big.Int).Add(aBig, bBig)
	sum.Mod(sum, ristrettoGroupOrder)
	s := bigIntToScalar32LE(sum)
	return s[:]
}

// buildDivRemProof builds the proof bytes for div/rem operations.
// a = b*q + r.
// Returns (encQ, encR, proof) where proof = [enc_aux 64B][mul_proof 160B][rp_r 672B][rp_bound 672B].
// For div: enc_aux=encR, result=encQ. For rem: enc_aux=encQ, result=encR.
func buildDivRemProof(t *testing.T, pub []byte,
	valA, valB, valQ, valR uint64,
	openA, openB, openQ, openR []byte,
	forRem bool) (resultData []byte, proof []byte) {
	t.Helper()

	ctQ := buildCtFromOpening(t, pub, openQ, valQ)
	ctR := buildCtFromOpening(t, pub, openR, valR)
	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)

	// Com(a-r) commitment
	comAMinusR, err := cryptopriv.SubCompressedCiphertexts(ctA, ctR)
	if err != nil {
		t.Fatalf("SubCompressedCiphertexts: %v", err)
	}

	// Blinding for Com(a-r) = r_a - r_r
	openAR := scalarSub(openA, openR)

	// Multiplication proof: value(Com(a-r)) = value(Com_b) * value(Com_q)
	// Prover knows: b (plaintext of first arg), r_b, r_q, r_{a-r}
	mulPrf, err := cryptopriv.ProveMulProof(ctB[:32], ctQ[:32], comAMinusR[:32], valB, openB, openQ, openAR)
	if err != nil {
		t.Fatalf("ProveMulProof: %v", err)
	}

	// Range proof on r: r ∈ [0, 2^64)
	rpR, err := cryptopriv.ProveRangeProof(ctR[:32], valR, openR)
	if err != nil {
		t.Fatalf("ProveRangeProof(r): %v", err)
	}

	// Range proof on b-r-1: proves r < b
	diff, err := cryptopriv.SubCompressedCiphertexts(ctB, ctR)
	if err != nil {
		t.Fatalf("SubCompressedCiphertexts(b-r): %v", err)
	}
	shifted, err := cryptopriv.SubAmountCompressed(diff, 1)
	if err != nil {
		t.Fatalf("SubAmountCompressed: %v", err)
	}
	openDiff := scalarSub(openB, openR)
	rpBound, err := cryptopriv.ProveRangeProof(shifted[:32], valB-valR-1, openDiff)
	if err != nil {
		t.Fatalf("ProveRangeProof(bound): %v", err)
	}

	if forRem {
		// rem: ResultData=encR, proof=[encQ 64B][mul 160B][rpR 672B][rpBound 672B]
		proof = make([]byte, 0, 64+len(mulPrf)+len(rpR)+len(rpBound))
		proof = append(proof, ctQ...)
		proof = append(proof, mulPrf...)
		proof = append(proof, rpR...)
		proof = append(proof, rpBound...)
		return ctR, proof
	}
	// div: ResultData=encQ, proof=[encR 64B][mul 160B][rpR 672B][rpBound 672B]
	proof = make([]byte, 0, 64+len(mulPrf)+len(rpR)+len(rpBound))
	proof = append(proof, ctR...)
	proof = append(proof, mulPrf...)
	proof = append(proof, rpR...)
	proof = append(proof, rpBound...)
	return ctQ, proof
}

func TestCtMulReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	openC, _ := cryptopriv.GenerateOpening()
	valA, valB := uint64(3), uint64(7)
	valC := valA * valB

	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)
	ctC := buildCtFromOpening(t, pub, openC, valC)

	mulProof, err := cryptopriv.ProveMulProof(ctA[:32], ctB[:32], ctC[:32], valA, openA, openB, openC)
	if err != nil {
		t.Fatalf("ProveMulProof: %v", err)
	}

	inputHash := makeInputHash("mul", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "mul", InputHash: inputHash, ResultData: ctC, Proof: mulProof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xF0}
	src := `
local r = tos.ciphertext.mul("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= "0x` + hex.EncodeToString(ctC) + `" then error("mul result mismatch") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000); err != nil {
		t.Fatalf("mul valid: %v", err)
	}
	raw := st.GetState(addr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtMulInvalidProof(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	openC, _ := cryptopriv.GenerateOpening()

	ctA := buildCtFromOpening(t, pub, openA, 3)
	ctB := buildCtFromOpening(t, pub, openB, 7)
	ctC := buildCtFromOpening(t, pub, openC, 21)

	// Zero-filled 160B proof (invalid).
	badProof := make([]byte, 160)

	inputHash := makeInputHash("mul", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "mul", InputHash: inputHash, ResultData: ctC, Proof: badProof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xF1}
	src := `tos.ciphertext.mul("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")`
	err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000)
	if err == nil || !strings.Contains(err.Error(), "multiplication proof verification failed") {
		t.Fatalf("expected multiplication proof error, got: %v", err)
	}
}

func TestCtDivReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	openQ, _ := cryptopriv.GenerateOpening()
	openR, _ := cryptopriv.GenerateOpening()
	valA, valB := uint64(17), uint64(5)
	valQ, valR := valA/valB, valA%valB // 3, 2

	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)

	resultData, proof := buildDivRemProof(t, pub, valA, valB, valQ, valR, openA, openB, openQ, openR, false)

	inputHash := makeInputHash("div", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "div", InputHash: inputHash, ResultData: resultData, Proof: proof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xF2}
	src := `
local r = tos.ciphertext.div("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= "0x` + hex.EncodeToString(resultData) + `" then error("div result mismatch") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 4_000_000); err != nil {
		t.Fatalf("div valid: %v", err)
	}
	raw := st.GetState(addr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtRemReal(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	openQ, _ := cryptopriv.GenerateOpening()
	openR, _ := cryptopriv.GenerateOpening()
	valA, valB := uint64(17), uint64(5)
	valQ, valR := valA/valB, valA%valB // 3, 2

	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)

	resultData, proof := buildDivRemProof(t, pub, valA, valB, valQ, valR, openA, openB, openQ, openR, true)

	inputHash := makeInputHash("rem", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "rem", InputHash: inputHash, ResultData: resultData, Proof: proof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xF3}
	src := `
local r = tos.ciphertext.rem("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
if r ~= "0x` + hex.EncodeToString(resultData) + `" then error("rem result mismatch") end
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 4_000_000); err != nil {
		t.Fatalf("rem valid: %v", err)
	}
	raw := st.GetState(addr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtDivExact(t *testing.T) {
	// Test exact division: 21 / 7 = 3, remainder = 0.
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	openQ, _ := cryptopriv.GenerateOpening()
	openR, _ := cryptopriv.GenerateOpening()
	valA, valB := uint64(21), uint64(7)
	valQ, valR := uint64(3), uint64(0)

	ctA := buildCtFromOpening(t, pub, openA, valA)
	ctB := buildCtFromOpening(t, pub, openB, valB)

	resultData, proof := buildDivRemProof(t, pub, valA, valB, valQ, valR, openA, openB, openQ, openR, false)

	inputHash := makeInputHash("div", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "div", InputHash: inputHash, ResultData: resultData, Proof: proof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xF4}
	src := `
local r = tos.ciphertext.div("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")
tos.sstore("ok", 1)
`
	if err := runLuaWithBundle(t, st, addr, src, bundleBytes, 4_000_000); err != nil {
		t.Fatalf("div exact: %v", err)
	}
}

func TestCtDivInvalidProof(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	openQ, _ := cryptopriv.GenerateOpening()

	ctA := buildCtFromOpening(t, pub, openA, 17)
	ctB := buildCtFromOpening(t, pub, openB, 5)
	ctQ := buildCtFromOpening(t, pub, openQ, 3)

	// Fake proof with correct size but all zeros.
	badProof := make([]byte, 1568) // divRemProofSize

	inputHash := makeInputHash("div", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "div", InputHash: inputHash, ResultData: ctQ, Proof: badProof,
	}})

	st := newAgentTestState()
	addr := common.Address{0xF5}
	src := `tos.ciphertext.div("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")`
	err := runLuaWithBundle(t, st, addr, src, bundleBytes, 4_000_000)
	if err == nil {
		t.Fatal("expected error for invalid div proof")
	}
}

// --- Missing coverage tests ---

func TestCtDivScalar(t *testing.T) {
	pub, _ := testKeypair(t)
	pubHex := "0x" + hex.EncodeToString(pub[:])

	st := newAgentTestState()
	contractAddr := common.Address{0xF6}

	// mul_scalar(ct, 6) then div_scalar(ct, 3) should give mul_scalar(ct, 2)
	src := `
local ct = tos.ciphertext
local a = ct.encrypt("` + pubHex + `", 1)
local x6 = ct.mul_scalar(a, 6)
local x2 = ct.div_scalar(x6, 3)
local expected = ct.mul_scalar(a, 2)
if x2 ~= expected then error("div_scalar mismatch") end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("div_scalar: %v", err)
	}
}

func TestCtDivScalarByZero(t *testing.T) {
	pub, _ := testKeypair(t)
	pubHex := "0x" + hex.EncodeToString(pub[:])

	st := newAgentTestState()
	contractAddr := common.Address{0xF7}

	src := `
local ct = tos.ciphertext
local a = ct.encrypt("` + pubHex + `", 10)
ct.div_scalar(a, 0)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err == nil {
		t.Fatal("expected error for division by zero")
	}
	if !strings.Contains(err.Error(), "division by zero") {
		t.Fatalf("expected division by zero error, got: %v", err)
	}
}

func TestCtGtInvalidProof(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	ctA := buildCtFromOpening(t, pub, openA, 7)
	ctB := buildCtFromOpening(t, pub, openB, 3)

	inputHash := makeInputHash("gt", ctA, ctB)
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "gt", InputHash: inputHash, ResultData: []byte{1}, Proof: make([]byte, 672),
	}})

	st := newAgentTestState()
	addr := common.Address{0xF8}
	src := `tos.ciphertext.gt("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")`
	err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000)
	if err == nil || !strings.Contains(err.Error(), "range proof") {
		t.Fatalf("expected range proof error, got: %v", err)
	}
}

func TestCtEqInvalidProof(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	ctA := buildCtFromOpening(t, pub, openA, 5)
	ctB := buildCtFromOpening(t, pub, openB, 5)

	inputHash := makeInputHash("eq", ctA, ctB)
	// eq=true needs 1344B, provide wrong size
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "eq", InputHash: inputHash, ResultData: []byte{1}, Proof: make([]byte, 672),
	}})

	st := newAgentTestState()
	addr := common.Address{0xF9}
	src := `tos.ciphertext.eq("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")`
	err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000)
	if err == nil {
		t.Fatal("expected error for wrong eq proof size")
	}
}

func TestCtMaxInvalidProof(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	ctA := buildCtFromOpening(t, pub, openA, 3)
	ctB := buildCtFromOpening(t, pub, openB, 7)

	inputHash := makeInputHash("max", ctA, ctB)
	// result=ctB but bad range proof
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "max", InputHash: inputHash, ResultData: ctB, Proof: make([]byte, 672),
	}})

	st := newAgentTestState()
	addr := common.Address{0xFA}
	src := `tos.ciphertext.max("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")`
	err := runLuaWithBundle(t, st, addr, src, bundleBytes, 2_000_000)
	if err == nil || !strings.Contains(err.Error(), "range proof") {
		t.Fatalf("expected range proof error, got: %v", err)
	}
}

func TestCtRemInvalidProof(t *testing.T) {
	pub, _, _ := cryptopriv.GenerateKeypair()
	openA, _ := cryptopriv.GenerateOpening()
	openB, _ := cryptopriv.GenerateOpening()
	ctA := buildCtFromOpening(t, pub, openA, 17)
	ctB := buildCtFromOpening(t, pub, openB, 5)

	inputHash := makeInputHash("rem", ctA, ctB)
	// Wrong proof size
	bundleBytes := EncodeProofBundle([]ProofEntry{{
		Op: "rem", InputHash: inputHash, ResultData: make([]byte, 64), Proof: make([]byte, 100),
	}})

	st := newAgentTestState()
	addr := common.Address{0xFB}
	src := `tos.ciphertext.rem("0x` + hex.EncodeToString(ctA) + `", "0x` + hex.EncodeToString(ctB) + `")`
	err := runLuaWithBundle(t, st, addr, src, bundleBytes, 4_000_000)
	if err == nil {
		t.Fatal("expected error for invalid rem proof")
	}
}

// ── Bridge: native encrypted-balance ↔ contract ciphertext ──────────────────

func TestCtBalanceEmpty(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xD0}
	targetAddr := common.Address{0xD1}

	// Balance of an account with no encrypted balance should return encrypted
	// zero (type closure), not nil.  This ensures bal.add(x) always works.
	src := `
local bal = tos.ciphertext.balance("` + targetAddr.Hex() + `")
if type(bal) ~= "string" then
  error("expected string (encrypted zero), got " .. type(bal))
end
-- Must be a valid 130-char ciphertext hex (0x + 128 hex chars)
if #bal ~= 130 then
  error("expected 130-char ciphertext hex, got " .. #bal)
end
-- Must equal tos.ciphertext.zero()
local z = tos.ciphertext.zero()
if bal ~= z then
  error("empty balance should equal encrypted zero")
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("balance(empty): %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtBalanceReadWrite(t *testing.T) {
	pub, _ := testKeypair(t)
	st := newAgentTestState()
	contractAddr := common.Address{0xD2}
	targetAddr := common.Address{0xD3}

	// Pre-seed the target account with an encrypted balance (encrypt 42).
	ct, err := cryptopriv.Encrypt(pub[:], 42)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	st.SetState(targetAddr, privCommitmentSlot, common.BytesToHash(ct[:32]))
	st.SetState(targetAddr, privHandleSlot, common.BytesToHash(ct[32:]))

	expectedHex := "0x" + hex.EncodeToString(ct)

	src := `
local bal = tos.ciphertext.balance("` + targetAddr.Hex() + `")
if bal == nil then
  error("expected non-nil balance")
end
if bal ~= "` + expectedHex + `" then
  error("balance mismatch: got " .. bal)
end
tos.sstore("ok", 1)
`
	_, _, _, err = runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("balance(seeded): %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestCtTransferToEmpty(t *testing.T) {
	pub, priv := testKeypair(t)
	st := newAgentTestState()
	contractAddr := common.Address{0xD4}
	recipientAddr := common.Address{0xD5}

	// Encrypt 100 as the deposit amount.
	deposit, err := cryptopriv.Encrypt(pub[:], 100)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	depositHex := "0x" + hex.EncodeToString(deposit)

	// Transfer to an account with no existing encrypted balance.
	src := `tos.ciphertext.transfer("` + recipientAddr.Hex() + `", "` + depositHex + `")`
	_, _, _, err = runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("transfer(empty recipient): %v", err)
	}

	// Verify the recipient now has the deposited ciphertext.
	commit := st.GetState(recipientAddr, privCommitmentSlot)
	handle := st.GetState(recipientAddr, privHandleSlot)
	if commit != common.BytesToHash(deposit[:32]) {
		t.Error("stored commitment doesn't match deposit")
	}
	if handle != common.BytesToHash(deposit[32:]) {
		t.Error("stored handle doesn't match deposit")
	}

	// Version should be 1.
	versionWord := st.GetState(recipientAddr, privVersionSlot)
	version := new(big.Int).SetBytes(versionWord[:]).Uint64()
	if version != 1 {
		t.Errorf("expected version=1, got %d", version)
	}

	// Decrypt via DecryptToPoint + SolveDiscreteLog and verify amount.
	msgPoint, err := cryptopriv.DecryptToPoint(priv[:], deposit)
	if err != nil {
		t.Fatalf("DecryptToPoint: %v", err)
	}
	plaintext, ok, err := cryptopriv.SolveDiscreteLog(msgPoint, 1<<20)
	if err != nil {
		t.Fatalf("SolveDiscreteLog: %v", err)
	}
	if !ok {
		t.Fatal("SolveDiscreteLog: not found")
	}
	if plaintext != 100 {
		t.Errorf("expected plaintext=100, got %d", plaintext)
	}
}

func TestCtTransferHomomorphicAdd(t *testing.T) {
	pub, priv := testKeypair(t)
	st := newAgentTestState()
	contractAddr := common.Address{0xD6}
	recipientAddr := common.Address{0xD7}

	// Pre-seed recipient with encrypted balance of 50.
	existingCt, err := cryptopriv.Encrypt(pub[:], 50)
	if err != nil {
		t.Fatalf("Encrypt existing: %v", err)
	}
	st.SetState(recipientAddr, privCommitmentSlot, common.BytesToHash(existingCt[:32]))
	st.SetState(recipientAddr, privHandleSlot, common.BytesToHash(existingCt[32:]))

	// Encrypt 30 as deposit.
	deposit, err := cryptopriv.Encrypt(pub[:], 30)
	if err != nil {
		t.Fatalf("Encrypt deposit: %v", err)
	}
	depositHex := "0x" + hex.EncodeToString(deposit)

	// Transfer 30 to recipient (already has 50).
	src := `tos.ciphertext.transfer("` + recipientAddr.Hex() + `", "` + depositHex + `")`
	_, _, _, err = runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("transfer(existing recipient): %v", err)
	}

	// Read final balance and decrypt — should be 80 (50+30).
	commit := st.GetState(recipientAddr, privCommitmentSlot)
	handle := st.GetState(recipientAddr, privHandleSlot)
	var finalCt [64]byte
	copy(finalCt[:32], commit[:])
	copy(finalCt[32:], handle[:])
	msgPoint, err := cryptopriv.DecryptToPoint(priv[:], finalCt[:])
	if err != nil {
		t.Fatalf("DecryptToPoint: %v", err)
	}
	plaintext, ok, err := cryptopriv.SolveDiscreteLog(msgPoint, 1<<20)
	if err != nil {
		t.Fatalf("SolveDiscreteLog: %v", err)
	}
	if !ok {
		t.Fatal("SolveDiscreteLog: not found")
	}
	if plaintext != 80 {
		t.Errorf("expected plaintext=80 (50+30), got %d", plaintext)
	}
}

func TestCtTransferReadonlyRejected(t *testing.T) {
	pub, _ := testKeypair(t)
	st := newAgentTestState()
	contractAddr := common.Address{0xD8}
	recipientAddr := common.Address{0xD9}

	deposit, err := cryptopriv.Encrypt(pub[:], 10)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	depositHex := "0x" + hex.EncodeToString(deposit)

	// Execute in readonly mode — transfer must fail.
	ctx := CallCtx{
		From: common.Address{0xFF}, To: contractAddr,
		Value: big.NewInt(0), Data: []byte{},
		TxOrigin: common.Address{0xFF}, TxPrice: big.NewInt(1),
		Readonly: true,
	}
	src := `tos.ciphertext.transfer("` + recipientAddr.Hex() + `", "` + depositHex + `")`
	_, _, _, err = Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), 1_000_000)
	if err == nil {
		t.Fatal("expected error for transfer in readonly mode")
	}
}

func TestUnoValueExposed(t *testing.T) {
	pub, _ := testKeypair(t)
	st := newAgentTestState()
	contractAddr := common.Address{0xDA}

	// Encrypt a deposit and attach as UnoValue.
	deposit, err := cryptopriv.Encrypt(pub[:], 77)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	depositHex := "0x" + hex.EncodeToString(deposit)

	ctx := CallCtx{
		From: common.Address{0xFF}, To: contractAddr,
		Value: big.NewInt(0), Data: []byte{},
		TxOrigin: common.Address{0xFF}, TxPrice: big.NewInt(1),
		UnoValue: depositHex,
	}
	src := `
local uv = tos.uno_value
if uv == nil then
  error("expected non-nil uno_value")
end
if uv ~= "` + depositHex + `" then
  error("uno_value mismatch: got " .. uv)
end
tos.sstore("ok", 1)
`
	_, _, _, err = Execute(st, newBlockCtx(), testChainConfig, ctx, []byte(src), 1_000_000)
	if err != nil {
		t.Fatalf("uno_value: %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}

func TestUnoValueZeroWhenEmpty(t *testing.T) {
	st := newAgentTestState()
	contractAddr := common.Address{0xDB}

	// uno_value without a deposit should return encrypted zero (not nil)
	// so that msg.value.add(x) always works without nil checks.
	src := `
local uv = tos.uno_value
if type(uv) ~= "string" then
  error("expected string (encrypted zero), got " .. type(uv))
end
local z = tos.ciphertext.zero()
if uv ~= z then
  error("empty uno_value should equal encrypted zero")
end
tos.sstore("ok", 1)
`
	_, _, _, err := runLua(st, contractAddr, src, 1_000_000)
	if err != nil {
		t.Fatalf("uno_value(zero): %v", err)
	}
	raw := st.GetState(contractAddr, StorageSlot("ok"))
	if raw.Big().Int64() != 1 {
		t.Error("expected ok=1")
	}
}
