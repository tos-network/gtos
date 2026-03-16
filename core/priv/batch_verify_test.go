package priv

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/crypto"
	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

func batchArray32(t *testing.T, in []byte) [32]byte {
	t.Helper()
	if len(in) != 32 {
		t.Fatalf("array32 len = %d, want 32", len(in))
	}
	var out [32]byte
	copy(out[:], in)
	return out
}

func batchCiphertext(t *testing.T, compressed []byte) Ciphertext {
	t.Helper()
	if len(compressed) != 64 {
		t.Fatalf("ciphertext len = %d, want 64", len(compressed))
	}
	var out Ciphertext
	copy(out.Commitment[:], compressed[:32])
	copy(out.Handle[:], compressed[32:])
	return out
}

func mustBatchKeypair(t *testing.T) (pub, privkey [32]byte) {
	t.Helper()
	pubBytes, privBytes, err := cryptopriv.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	copy(pub[:], pubBytes)
	copy(privkey[:], privBytes)
	return pub, privkey
}

func makeTransferProofBundle(t *testing.T, chainID *big.Int) ([32]byte, [32]byte, [32]byte, [32]byte, [32]byte, []byte, []byte, []byte, Ciphertext, [32]byte, []byte) {
	t.Helper()

	senderPub, senderPriv := mustBatchKeypair(t)
	receiverPub, _ := mustBatchKeypair(t)
	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	receiverAddr := common.BytesToAddress(crypto.Keccak256(receiverPub[:]))

	senderBalance := uint64(900)
	amount := uint64(210)
	feeLimit := uint64(35)
	newBalance := senderBalance - amount - feeLimit

	senderCtCompressed, _, err := cryptopriv.EncryptWithGeneratedOpening(senderPub[:], senderBalance)
	if err != nil {
		t.Fatalf("EncryptWithGeneratedOpening: %v", err)
	}
	senderCiphertext := batchCiphertext(t, senderCtCompressed)

	commitmentBytes, opening, err := cryptopriv.CommitmentNew(amount)
	if err != nil {
		t.Fatalf("CommitmentNew(amount): %v", err)
	}
	commitment := batchArray32(t, commitmentBytes)

	senderHandleBytes, err := cryptopriv.DecryptHandleWithOpening(senderPub[:], opening)
	if err != nil {
		t.Fatalf("DecryptHandleWithOpening(sender): %v", err)
	}
	senderHandle := batchArray32(t, senderHandleBytes)

	receiverHandleBytes, err := cryptopriv.DecryptHandleWithOpening(receiverPub[:], opening)
	if err != nil {
		t.Fatalf("DecryptHandleWithOpening(receiver): %v", err)
	}
	receiverHandle := batchArray32(t, receiverHandleBytes)

	sourceCommitmentBytes, sourceOpening, err := cryptopriv.CommitmentNew(newBalance)
	if err != nil {
		t.Fatalf("CommitmentNew(source): %v", err)
	}
	sourceCommitment := batchArray32(t, sourceCommitmentBytes)

	transferCt := Ciphertext{Commitment: commitment, Handle: senderHandle}
	outputCt, err := AddScalarToCiphertext(transferCt, feeLimit)
	if err != nil {
		t.Fatalf("AddScalarToCiphertext: %v", err)
	}
	newSenderBalanceCt, err := SubCiphertexts(senderCiphertext, outputCt)
	if err != nil {
		t.Fatalf("SubCiphertexts: %v", err)
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
		t.Fatalf("ProveCTValidityProofWithContext: %v", err)
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
		t.Fatalf("ProveCommitmentEqProof: %v", err)
	}
	rangeProof, err := cryptopriv.ProveAggregatedRangeProof(
		[][]byte{sourceCommitmentBytes, commitmentBytes},
		[]uint64{newBalance, amount},
		[][]byte{sourceOpening, opening},
	)
	if err != nil {
		t.Fatalf("ProveAggregatedRangeProof: %v", err)
	}

	return senderPub, receiverPub, commitment, senderHandle, receiverHandle, ctValidityProof, commitmentEqProof, rangeProof, newSenderBalanceCt, sourceCommitment, ctx
}

func makeShieldProofBundle(t *testing.T, chainID *big.Int, senderPub, receiverPub [32]byte) ([32]byte, [32]byte, []byte, []byte, []byte) {
	t.Helper()

	const amount = uint64(77)
	const fee = uint64(9)

	senderAddr := common.BytesToAddress(crypto.Keccak256(senderPub[:]))
	opening, err := cryptopriv.GenerateOpening()
	if err != nil {
		t.Fatalf("GenerateOpening: %v", err)
	}
	commitmentBytes, err := cryptopriv.PedersenCommitmentWithOpening(opening, amount)
	if err != nil {
		t.Fatalf("PedersenCommitmentWithOpening: %v", err)
	}
	handleBytes, err := cryptopriv.DecryptHandleWithOpening(receiverPub[:], opening)
	if err != nil {
		t.Fatalf("DecryptHandleWithOpening: %v", err)
	}
	commitment := batchArray32(t, commitmentBytes)
	handle := batchArray32(t, handleBytes)
	ctx := BuildShieldTranscriptContext(chainID, 0, fee, amount, senderAddr, commitment, handle)
	proof, _, _, err := cryptopriv.ProveShieldProofWithContext(receiverPub[:], amount, opening, ctx)
	if err != nil {
		t.Fatalf("ProveShieldProofWithContext: %v", err)
	}
	rangeProof, err := cryptopriv.ProveRangeProof(commitmentBytes, amount, opening)
	if err != nil {
		t.Fatalf("ProveRangeProof: %v", err)
	}
	return commitment, handle, proof, rangeProof, ctx
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
