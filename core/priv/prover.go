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
	// All values (amount, feeLimit, senderBalance) are in UNO base units.
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

	// 3. Generate CT validity proof using the priv backend.
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
	//    verifier would: newSenderCt = senderCiphertext - (transferCt + feeLimitWei).
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

	// 5. Generate the aggregated transfer range proof covering both the
	//    source commitment and transfer commitment.
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

// BuildShieldProofs generates the proofs required for a ShieldTx.
// recipientPub is the ElGamal pubkey under which the deposit is encrypted.
//
// Returns:
//   - commitment, handle: encrypted form of Amount under recipientPub
//   - shieldProof: proves (commitment, handle) is valid encryption of amount
//   - rangeProof: proves committed amount in [0, 2^64)
func BuildShieldProofs(
	recipientPub [32]byte,
	amount uint64,
	context []byte,
) (
	commitment, handle [32]byte,
	shieldProof, rangeProof []byte,
	err error,
) {
	// 1. Generate opening (randomness).
	opening, err := cryptopriv.GenerateOpening()
	if err != nil {
		return commitment, handle, nil, nil, fmt.Errorf("opening generation failed: %w", err)
	}

	// 2. Generate shield proof (proves encryption under recipient's key).
	shieldProof, commitmentBytes, handleBytes, err := cryptopriv.ProveShieldProofWithContext(
		recipientPub[:], amount, opening, context,
	)
	if err != nil {
		return commitment, handle, nil, nil, fmt.Errorf("shield proof failed: %w", err)
	}
	copy(commitment[:], commitmentBytes)
	copy(handle[:], handleBytes)

	// 3. Generate range proof (single commitment).
	rangeProof, err = cryptopriv.ProveRangeProof(commitmentBytes, amount, opening)
	if err != nil {
		return commitment, handle, nil, nil, fmt.Errorf("range proof failed: %w", err)
	}

	return
}

// BuildUnshieldProofs generates the proofs required for an UnshieldTx.
// This is a client-side operation requiring the sender's private key, plaintext
// balance, and the current encrypted balance.
//
// Returns:
//   - sourceCommitment: new encrypted balance commitment after withdrawal
//   - commitmentEqProof: proves sourceCommitment matches the computed new balance
//   - rangeProof: proves committed amount in [0, 2^64)
func BuildUnshieldProofs(
	senderPriv, senderPub [32]byte,
	amount, senderBalance uint64,
	senderCiphertext Ciphertext,
	context []byte,
) (
	sourceCommitment [32]byte,
	commitmentEqProof, rangeProof []byte,
	err error,
) {
	if senderBalance < amount {
		return sourceCommitment, nil, nil, fmt.Errorf("insufficient balance: have %d, need %d",
			senderBalance, amount)
	}

	newBalance := senderBalance - amount

	// 1. Compute zeroedCt = senderCiphertext - AddScalarToCiphertext(Zero(), amount)
	amountCt, err := AddScalarToCiphertext(ZeroCiphertext(), amount)
	if err != nil {
		return sourceCommitment, nil, nil, fmt.Errorf("amount ciphertext computation failed: %w", err)
	}
	zeroedCt, err := SubCiphertexts(senderCiphertext, amountCt)
	if err != nil {
		return sourceCommitment, nil, nil, fmt.Errorf("zeroed ciphertext computation failed: %w", err)
	}

	// 2. Generate source commitment (new balance after withdrawal).
	srcCommitmentBytes, srcOpening, err := cryptopriv.CommitmentNew(newBalance)
	if err != nil {
		return sourceCommitment, nil, nil, fmt.Errorf("source commitment generation failed: %w", err)
	}
	copy(sourceCommitment[:], srcCommitmentBytes)

	// 3. Generate commitment equality proof.
	zeroedCt64 := append(zeroedCt.Commitment[:], zeroedCt.Handle[:]...)
	commitmentEqProof, err = cryptopriv.ProveCommitmentEqProof(
		senderPriv[:], senderPub[:],
		zeroedCt64,
		srcCommitmentBytes, srcOpening,
		newBalance, context,
	)
	if err != nil {
		return sourceCommitment, nil, nil, fmt.Errorf("commitment eq proof failed: %w", err)
	}

	// 4. Generate single-commitment range proof.
	rangeProof, err = cryptopriv.ProveRangeProof(srcCommitmentBytes, newBalance, srcOpening)
	if err != nil {
		return sourceCommitment, nil, nil, fmt.Errorf("range proof failed: %w", err)
	}

	return
}
