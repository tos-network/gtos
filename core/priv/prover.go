package priv

import (
	"fmt"

	cryptopriv "github.com/tos-network/gtos/crypto/priv"
)

// BuildTransferProofs generates the three proofs required for a PrivTransferTx.
// This is a client-side operation requiring the sender's private key and plaintext amounts.
//
// Parameters:
//   - senderPriv: sender's ElGamal private key (32 bytes)
//   - senderPub: sender's ElGamal public key (32 bytes)
//   - receiverPub: receiver's ElGamal public key (32 bytes)
//   - amount: transfer amount (plaintext, known only to sender)
//   - senderBalance: sender's current plaintext balance (decrypted client-side)
//   - feeLimit: fee limit locked into the source commitment
//   - senderCiphertext: sender's current on-chain encrypted balance
//   - context: Merlin transcript context bytes
//
// Returns:
//   - commitment, senderHandle, receiverHandle: transfer ciphertext fields
//   - sourceCommitment: sender's new balance commitment
//   - ctValidityProof, commitmentEqProof, rangeProof: the three ZK proofs
//   - err: error if proof generation fails
func BuildTransferProofs(
	senderPriv, senderPub, receiverPub [32]byte,
	amount, senderBalance, feeLimit uint64,
	senderCiphertext Ciphertext,
	context []byte,
) (
	commitment, senderHandle, receiverHandle [32]byte,
	sourceCommitment [32]byte,
	ctValidityProof, commitmentEqProof, rangeProof []byte,
	err error,
) {
	// Verify sufficient balance
	if senderBalance < amount+feeLimit {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("insufficient balance: have %d, need %d (amount %d + fee_limit %d)",
				senderBalance, amount+feeLimit, amount, feeLimit)
	}

	newBalance := senderBalance - amount - feeLimit

	// 1. Generate transfer ciphertext (commitment + two handles)
	//    Uses crypto backend to create Pedersen commitment with random opening.
	//    CommitmentNew returns (commitment32, opening32, err).
	commitmentBytes, opening, err := cryptopriv.CommitmentNew(amount)
	if err != nil {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("commitment generation failed: %w", err)
	}
	copy(commitment[:], commitmentBytes)

	// Generate decrypt handles
	sHandle, err := cryptopriv.DecryptHandleWithOpening(senderPub[:], opening)
	if err != nil {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("sender handle generation failed: %w", err)
	}
	copy(senderHandle[:], sHandle)

	rHandle, err := cryptopriv.DecryptHandleWithOpening(receiverPub[:], opening)
	if err != nil {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("receiver handle generation failed: %w", err)
	}
	copy(receiverHandle[:], rHandle)

	// 2. Generate source commitment (new balance after transfer + fee_limit)
	srcCommitmentBytes, srcOpening, err := cryptopriv.CommitmentNew(newBalance)
	if err != nil {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("source commitment generation failed: %w", err)
	}
	copy(sourceCommitment[:], srcCommitmentBytes)

	// 3. Generate CT validity proof using the UNO-style backend.
	//    ProveCTValidityProofWithContext returns (proof, commitment32, senderHandle32, receiverHandle32, err).
	ctValidityProof, _, _, _, err = cryptopriv.ProveCTValidityProofWithContext(
		senderPub[:], receiverPub[:], amount, opening, true, context,
	)
	if err != nil {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("ct validity proof failed: %w", err)
	}

	// 4. Generate commitment equality proof.
	//    Proves the source commitment commits to the same value as the sender's
	//    updated ciphertext. We must compute the updated sender ciphertext as the
	//    verifier would: newSenderCt = senderCiphertext - (transferCt + feeLimit).
	var transferCt Ciphertext
	copy(transferCt.Commitment[:], commitmentBytes)
	copy(transferCt.Handle[:], sHandle)
	outputCt, err := AddScalarToCiphertext(transferCt, feeLimit)
	if err != nil {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("output ciphertext computation failed: %w", err)
	}
	newSenderBalanceCt, err := SubCiphertexts(senderCiphertext, outputCt)
	if err != nil {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("updated sender ciphertext computation failed: %w", err)
	}
	updatedCt64 := append(newSenderBalanceCt.Commitment[:], newSenderBalanceCt.Handle[:]...)
	commitmentEqProof, err = cryptopriv.ProveCommitmentEqProof(
		senderPriv[:], senderPub[:],
		updatedCt64,
		srcCommitmentBytes, srcOpening,
		newBalance, context,
	)
	if err != nil {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("commitment eq proof failed: %w", err)
	}

	// 5. Generate aggregated range proof over source commitment + transfer commitment.
	rangeProof, err = cryptopriv.ProveAggregatedRangeProof(
		[][]byte{srcCommitmentBytes, commitmentBytes},
		[]uint64{newBalance, amount},
		[][]byte{srcOpening, opening},
	)
	if err != nil {
		return commitment, senderHandle, receiverHandle, sourceCommitment,
			nil, nil, nil, fmt.Errorf("range proof failed: %w", err)
	}

	return
}
