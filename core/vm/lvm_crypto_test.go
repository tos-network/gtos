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

	// Encrypt two values to get valid ciphertext bytes.
	aBytes, err := cryptopriv.Encrypt(pub[:], 10)
	if err != nil {
		t.Fatalf("Encrypt(10): %v", err)
	}
	bBytes, err := cryptopriv.Encrypt(pub[:], 5)
	if err != nil {
		t.Fatalf("Encrypt(5): %v", err)
	}
	// Prepare a fake result (just use aBytes as result).
	resultBytes := make([]byte, 64)
	copy(resultBytes, aBytes)

	// Build the proof bundle with the correct input hash.
	inputHash := makeInputHash("mul", aBytes, bBytes)
	entries := []ProofEntry{
		{
			Op:         "mul",
			InputHash:  inputHash,
			ResultData: resultBytes,
			Proof:      []byte("fake-proof"),
		},
	}
	bundleBytes := EncodeProofBundle(entries)

	// Build calldata = empty ABI data + bundle.
	calldata := bundleBytes

	aHex := "0x" + hex.EncodeToString(aBytes)
	bHex := "0x" + hex.EncodeToString(bBytes)
	expectedResult := "0x" + hex.EncodeToString(resultBytes)

	src := `
local ct = tos.ciphertext
local result = ct.mul("` + aHex + `", "` + bHex + `")
if result ~= "` + expectedResult + `" then
  error("mul result mismatch: got " .. result)
end
tos.sstore("ok", 1)
`

	// Use Execute directly so we can pass calldata with the bundle.
	ctx := CallCtx{
		From:     common.Address{0xFF},
		To:       contractAddr,
		Value:    big.NewInt(0),
		Data:     calldata,
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
