package priv

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

func batchArray32(tb testing.TB, in []byte) [32]byte {
	tb.Helper()
	if len(in) != 32 {
		tb.Fatalf("array32 len = %d, want 32", len(in))
	}
	var out [32]byte
	copy(out[:], in)
	return out
}

func batchCiphertext(tb testing.TB, compressed []byte) Ciphertext {
	tb.Helper()
	if len(compressed) != 64 {
		tb.Fatalf("ciphertext len = %d, want 64", len(compressed))
	}
	var out Ciphertext
	copy(out.Commitment[:], compressed[:32])
	copy(out.Handle[:], compressed[32:])
	return out
}

func mustBatchKeypair(tb testing.TB) (pub, privkey [32]byte) {
	tb.Helper()
	pubBytes, privBytes, err := cryptopriv.GenerateKeypair()
	if err != nil {
		tb.Fatalf("GenerateKeypair: %v", err)
	}
	copy(pub[:], pubBytes)
	copy(privkey[:], privBytes)
	return pub, privkey
}

func makeTransferProofBundle(tb testing.TB, chainID *big.Int) ([32]byte, [32]byte, [32]byte, [32]byte, [32]byte, []byte, []byte, []byte, Ciphertext, [32]byte, []byte) {
	tb.Helper()

	senderPub, senderPriv := mustBatchKeypair(tb)
	receiverPub, _ := mustBatchKeypair(tb)
	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	receiverAddr := common.BytesToAddress(crypto.Keccak256(receiverPub[:]))

	senderBalance := uint64(900)
	amount := uint64(210)
	feeLimit := uint64(35)
	newBalance := senderBalance - amount - feeLimit

	senderCtCompressed, _, err := cryptopriv.EncryptWithGeneratedOpening(senderPub[:], senderBalance)
	if err != nil {
		tb.Fatalf("EncryptWithGeneratedOpening: %v", err)
	}
	senderCiphertext := batchCiphertext(tb, senderCtCompressed)

	commitmentBytes, opening, err := cryptopriv.CommitmentNew(amount)
	if err != nil {
		tb.Fatalf("CommitmentNew(amount): %v", err)
	}
	commitment := batchArray32(tb, commitmentBytes)

	senderHandleBytes, err := cryptopriv.DecryptHandleWithOpening(senderPub[:], opening)
	if err != nil {
		tb.Fatalf("DecryptHandleWithOpening(sender): %v", err)
	}
	senderHandle := batchArray32(tb, senderHandleBytes)

	receiverHandleBytes, err := cryptopriv.DecryptHandleWithOpening(receiverPub[:], opening)
	if err != nil {
		tb.Fatalf("DecryptHandleWithOpening(receiver): %v", err)
	}
	receiverHandle := batchArray32(tb, receiverHandleBytes)

	sourceCommitmentBytes, sourceOpening, err := cryptopriv.CommitmentNew(newBalance)
	if err != nil {
		tb.Fatalf("CommitmentNew(source): %v", err)
	}
	sourceCommitment := batchArray32(tb, sourceCommitmentBytes)

	transferCt := Ciphertext{Commitment: commitment, Handle: senderHandle}
	outputCt, err := AddScalarToCiphertext(transferCt, feeLimit)
	if err != nil {
		tb.Fatalf("AddScalarToCiphertext: %v", err)
	}
	newSenderBalanceCt, err := SubCiphertexts(senderCiphertext, outputCt)
	if err != nil {
		tb.Fatalf("SubCiphertexts: %v", err)
	}

	receiverCt := Ciphertext{Commitment: commitment, Handle: receiverHandle}
	ctx := BuildPrivTransferTranscriptContext(
		chainID,
		0,
		feeLimit,
		feeLimit,
		senderAddr,
		receiverAddr,
		transferCt,
		receiverCt,
		sourceCommitment,
	)

	ctValidityProof, _, _, _, err := cryptopriv.ProveCTValidityProofWithContext(
		senderPub[:], receiverPub[:], amount, opening, true, ctx,
	)
	if err != nil {
		tb.Fatalf("ProveCTValidityProofWithContext: %v", err)
	}
	updatedCt64 := append(append([]byte{}, newSenderBalanceCt.Commitment[:]...), newSenderBalanceCt.Handle[:]...)
	commitmentEqProof, err := cryptopriv.ProveCommitmentEqProof(
		senderPriv[:], senderPub[:],
		updatedCt64,
		sourceCommitmentBytes, sourceOpening,
		newBalance,
		ctx,
	)
	if err != nil {
		tb.Fatalf("ProveCommitmentEqProof: %v", err)
	}
	rangeProof, err := cryptopriv.ProveAggregatedRangeProof(
		[][]byte{sourceCommitmentBytes, commitmentBytes},
		[]uint64{newBalance, amount},
		[][]byte{sourceOpening, opening},
	)
	if err != nil {
		tb.Fatalf("ProveAggregatedRangeProof: %v", err)
	}

	return senderPub, receiverPub, commitment, senderHandle, receiverHandle, ctValidityProof, commitmentEqProof, rangeProof, newSenderBalanceCt, sourceCommitment, ctx
}

func makeShieldProofBundle(tb testing.TB, chainID *big.Int, senderPub, receiverPub [32]byte) ([32]byte, [32]byte, []byte, []byte, []byte) {
	tb.Helper()

	const amount = uint64(77)
	const fee = uint64(9)

	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	opening, err := cryptopriv.GenerateOpening()
	if err != nil {
		tb.Fatalf("GenerateOpening: %v", err)
	}
	commitmentBytes, err := cryptopriv.PedersenCommitmentWithOpening(opening, amount)
	if err != nil {
		tb.Fatalf("PedersenCommitmentWithOpening: %v", err)
	}
	handleBytes, err := cryptopriv.DecryptHandleWithOpening(receiverPub[:], opening)
	if err != nil {
		tb.Fatalf("DecryptHandleWithOpening: %v", err)
	}
	commitment := batchArray32(tb, commitmentBytes)
	handle := batchArray32(tb, handleBytes)
	ctx := BuildShieldTranscriptContext(chainID, 0, fee, amount, senderAddr, commitment, handle)
	proof, _, _, err := cryptopriv.ProveShieldProofWithContext(receiverPub[:], amount, opening, ctx)
	if err != nil {
		tb.Fatalf("ProveShieldProofWithContext: %v", err)
	}
	rangeProof, err := cryptopriv.ProveRangeProof(commitmentBytes, amount, opening)
	if err != nil {
		tb.Fatalf("ProveRangeProof: %v", err)
	}
	return commitment, handle, proof, rangeProof, ctx
}

func makeUnshieldProofBundle(tb testing.TB, chainID *big.Int) ([32]byte, Ciphertext, [32]byte, []byte, []byte, []byte) {
	tb.Helper()

	senderPub, senderPriv := mustBatchKeypair(tb)
	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	senderBalance := uint64(640)
	amount := uint64(91)
	senderCtCompressed, _, err := cryptopriv.EncryptWithGeneratedOpening(senderPub[:], senderBalance)
	if err != nil {
		tb.Fatalf("EncryptWithGeneratedOpening: %v", err)
	}
	senderCt := batchCiphertext(tb, senderCtCompressed)
	amountCt, err := AddScalarToCiphertext(ZeroCiphertext(), amount)
	if err != nil {
		tb.Fatalf("AddScalarToCiphertext: %v", err)
	}
	zeroedCt, err := SubCiphertexts(senderCt, amountCt)
	if err != nil {
		tb.Fatalf("SubCiphertexts: %v", err)
	}
	newBalance := senderBalance - amount
	sourceCommitmentBytes, sourceOpening, err := cryptopriv.CommitmentNew(newBalance)
	if err != nil {
		tb.Fatalf("CommitmentNew: %v", err)
	}
	sourceCommitment := batchArray32(tb, sourceCommitmentBytes)
	ctx := BuildUnshieldTranscriptContext(chainID, 0, 0, amount, senderAddr, zeroedCt, sourceCommitment)
	zeroedCt64 := append(append([]byte{}, zeroedCt.Commitment[:]...), zeroedCt.Handle[:]...)
	commitmentEqProof, err := cryptopriv.ProveCommitmentEqProof(
		senderPriv[:], senderPub[:], zeroedCt64, sourceCommitmentBytes, sourceOpening, newBalance, ctx,
	)
	if err != nil {
		tb.Fatalf("ProveCommitmentEqProof: %v", err)
	}
	rangeProof, err := cryptopriv.ProveRangeProof(sourceCommitmentBytes, newBalance, sourceOpening)
	if err != nil {
		tb.Fatalf("ProveRangeProof: %v", err)
	}
	return senderPub, zeroedCt, sourceCommitment, commitmentEqProof, rangeProof, ctx
}

func makeBalanceProofBundle(tb testing.TB) ([32]byte, Ciphertext, []byte, []byte) {
	tb.Helper()

	senderPub, senderPriv := mustBatchKeypair(tb)
	amount := uint64(144)
	senderCtCompressed, _, err := cryptopriv.EncryptWithGeneratedOpening(senderPub[:], amount)
	if err != nil {
		tb.Fatalf("EncryptWithGeneratedOpening: %v", err)
	}
	senderCt := batchCiphertext(tb, senderCtCompressed)
	sourceCt64 := append(append([]byte{}, senderCt.Commitment[:]...), senderCt.Handle[:]...)
	ctx := []byte("balance-batch-context")
	proof, err := cryptopriv.ProveBalanceProofWithContext(senderPriv[:], sourceCt64, amount, ctx)
	if err != nil {
		tb.Fatalf("ProveBalanceProofWithContext: %v", err)
	}
	return senderPub, senderCt, proof, ctx
}

func makeLegacyTransferRangeProofBundle(tb testing.TB) ([32]byte, [32]byte, []byte) {
	tb.Helper()

	sourceValue := uint64(400)
	transferValue := uint64(125)

	sourceCommitmentBytes, sourceOpening, err := cryptopriv.CommitmentNew(sourceValue)
	if err != nil {
		tb.Fatalf("CommitmentNew(source): %v", err)
	}
	transferCommitmentBytes, transferOpening, err := cryptopriv.CommitmentNew(transferValue)
	if err != nil {
		tb.Fatalf("CommitmentNew(transfer): %v", err)
	}
	sourceRangeProof, err := cryptopriv.ProveRangeProof(sourceCommitmentBytes, sourceValue, sourceOpening)
	if err != nil {
		tb.Fatalf("ProveRangeProof(source): %v", err)
	}
	transferRangeProof, err := cryptopriv.ProveRangeProof(transferCommitmentBytes, transferValue, transferOpening)
	if err != nil {
		tb.Fatalf("ProveRangeProof(transfer): %v", err)
	}
	legacy := append(append([]byte{}, sourceRangeProof...), transferRangeProof...)
	return batchArray32(tb, sourceCommitmentBytes), batchArray32(tb, transferCommitmentBytes), legacy
}

func TestBatchVerifierAcceptsTransferAndShieldProofs(t *testing.T) {
	t.Parallel()

	chainID := big.NewInt(1337)
	senderPub, receiverPub, commitment, senderHandle, receiverHandle, ctValidityProof, commitmentEqProof, rangeProof, newSenderBalanceCt, sourceCommitment, ctx := makeTransferProofBundle(t, chainID)
	shieldCommitment, shieldHandle, shieldProof, shieldRange, shieldCtx := makeShieldProofBundle(t, chainID, senderPub, receiverPub)

	batch := NewBatchVerifier()
	if err := batch.AddCiphertextValidityProofWithContext(commitment, senderHandle, receiverHandle, senderPub, receiverPub, ctValidityProof, ctx); err != nil {
		t.Fatalf("AddCiphertextValidityProofWithContext: %v", err)
	}
	if err := batch.AddCommitmentEqProofWithContext(senderPub, newSenderBalanceCt, sourceCommitment, commitmentEqProof, ctx); err != nil {
		t.Fatalf("AddCommitmentEqProofWithContext: %v", err)
	}
	if err := batch.AddRangeProof(sourceCommitment, commitment, rangeProof); err != nil {
		t.Fatalf("AddRangeProof: %v", err)
	}
	if err := batch.AddShieldProofWithContext(shieldCommitment, shieldHandle, receiverPub, 77, shieldProof, shieldCtx); err != nil {
		t.Fatalf("AddShieldProofWithContext: %v", err)
	}
	if err := batch.AddSingleRangeProof(shieldCommitment, shieldRange); err != nil {
		t.Fatalf("AddSingleRangeProof: %v", err)
	}
	if err := batch.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestBatchVerifierRejectsInvalidTransferProof(t *testing.T) {
	t.Parallel()

	chainID := big.NewInt(1337)
	senderPub, receiverPub, commitment, senderHandle, receiverHandle, ctValidityProof, commitmentEqProof, rangeProof, newSenderBalanceCt, sourceCommitment, ctx := makeTransferProofBundle(t, chainID)
	ctValidityProof[96] ^= 0x01

	batch := NewBatchVerifier()
	if err := batch.AddCiphertextValidityProofWithContext(commitment, senderHandle, receiverHandle, senderPub, receiverPub, ctValidityProof, ctx); err != nil {
		t.Fatalf("AddCiphertextValidityProofWithContext: %v", err)
	}
	if err := batch.AddCommitmentEqProofWithContext(senderPub, newSenderBalanceCt, sourceCommitment, commitmentEqProof, ctx); err != nil {
		t.Fatalf("AddCommitmentEqProofWithContext: %v", err)
	}
	if err := batch.AddRangeProof(sourceCommitment, commitment, rangeProof); err != nil {
		t.Fatalf("AddRangeProof: %v", err)
	}
	if err := batch.Verify(); err == nil {
		t.Fatal("Verify succeeded with invalid proof")
	}
}

func TestBatchVerifierAcceptsBalanceProof(t *testing.T) {
	t.Parallel()

	pubkey, ciphertext, proof, ctx := makeBalanceProofBundle(t)

	batch := NewBatchVerifier()
	if err := batch.AddBalanceProofWithContext(pubkey, ciphertext, proof, ctx); err != nil {
		t.Fatalf("AddBalanceProofWithContext: %v", err)
	}
	if err := batch.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestBatchVerifierRejectsInvalidBalanceProof(t *testing.T) {
	t.Parallel()

	pubkey, ciphertext, proof, ctx := makeBalanceProofBundle(t)
	proof[7] ^= 0x01

	batch := NewBatchVerifier()
	if err := batch.AddBalanceProofWithContext(pubkey, ciphertext, proof, ctx); err != nil {
		t.Fatalf("AddBalanceProofWithContext: %v", err)
	}
	if err := batch.Verify(); err == nil {
		t.Fatal("Verify succeeded with invalid proof")
	}
}

func TestBatchVerifierAcceptsLegacyTransferRangeEncoding(t *testing.T) {
	t.Parallel()

	sourceCommitment, transferCommitment, legacyProof := makeLegacyTransferRangeProofBundle(t)

	if err := VerifyRangeProof(sourceCommitment, transferCommitment, legacyProof); err != nil {
		t.Fatalf("VerifyRangeProof(legacy): %v", err)
	}

	batch := NewBatchVerifier()
	if err := batch.AddRangeProof(sourceCommitment, transferCommitment, legacyProof); err != nil {
		t.Fatalf("AddRangeProof(legacy): %v", err)
	}
	if err := batch.Verify(); err != nil {
		t.Fatalf("Verify(legacy): %v", err)
	}
}
