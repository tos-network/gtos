package priv

import (
	"math/big"
	"testing"
)

type transferProofBundle struct {
	senderPub          [32]byte
	receiverPub        [32]byte
	commitment         [32]byte
	senderHandle       [32]byte
	receiverHandle     [32]byte
	ctValidityProof    []byte
	commitmentEqProof  []byte
	rangeProof         []byte
	newSenderBalanceCt Ciphertext
	sourceCommitment   [32]byte
	ctx                []byte
}

type shieldProofBundle struct {
	commitment [32]byte
	handle     [32]byte
	pubkey     [32]byte
	proof      []byte
	rangeProof []byte
	ctx        []byte
}

type unshieldProofBundle struct {
	zeroedCt          Ciphertext
	pubkey            [32]byte
	sourceCommitment  [32]byte
	commitmentEqProof []byte
	rangeProof        []byte
	ctx               []byte
}

func benchmarkTransferBundle(tb testing.TB, chainID *big.Int) transferProofBundle {
	tb.Helper()
	senderPub, receiverPub, commitment, senderHandle, receiverHandle, ctValidityProof, commitmentEqProof, rangeProof, newSenderBalanceCt, sourceCommitment, ctx := makeTransferProofBundle(tb, chainID)
	return transferProofBundle{
		senderPub:          senderPub,
		receiverPub:        receiverPub,
		commitment:         commitment,
		senderHandle:       senderHandle,
		receiverHandle:     receiverHandle,
		ctValidityProof:    ctValidityProof,
		commitmentEqProof:  commitmentEqProof,
		rangeProof:         rangeProof,
		newSenderBalanceCt: newSenderBalanceCt,
		sourceCommitment:   sourceCommitment,
		ctx:                ctx,
	}
}

func benchmarkShieldBundle(tb testing.TB, chainID *big.Int) shieldProofBundle {
	tb.Helper()
	senderPub, _ := mustBatchKeypair(tb)
	receiverPub, _ := mustBatchKeypair(tb)
	commitment, handle, proof, rangeProof, ctx := makeShieldProofBundle(tb, chainID, senderPub, receiverPub)
	return shieldProofBundle{
		commitment: commitment,
		handle:     handle,
		pubkey:     receiverPub,
		proof:      proof,
		rangeProof: rangeProof,
		ctx:        ctx,
	}
}

func benchmarkUnshieldBundle(tb testing.TB, chainID *big.Int) unshieldProofBundle {
	tb.Helper()
	pubkey, zeroedCt, sourceCommitment, commitmentEqProof, rangeProof, ctx := makeUnshieldProofBundle(tb, chainID)
	return unshieldProofBundle{
		zeroedCt:          zeroedCt,
		pubkey:            pubkey,
		sourceCommitment:  sourceCommitment,
		commitmentEqProof: commitmentEqProof,
		rangeProof:        rangeProof,
		ctx:               ctx,
	}
}

func BenchmarkPrivacyVerificationSequentialTransferBatch8(b *testing.B) {
	chainID := big.NewInt(1337)
	bundles := make([]transferProofBundle, 8)
	for i := range bundles {
		bundles[i] = benchmarkTransferBundle(b, chainID)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, bundle := range bundles {
			if err := VerifyCiphertextValidityProofWithContext(bundle.commitment, bundle.senderHandle, bundle.receiverHandle, bundle.senderPub, bundle.receiverPub, bundle.ctValidityProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := VerifyCommitmentEqProofWithContext(bundle.senderPub, bundle.newSenderBalanceCt, bundle.sourceCommitment, bundle.commitmentEqProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := VerifyRangeProof(bundle.sourceCommitment, bundle.commitment, bundle.rangeProof); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkPrivacyVerificationBatchTransferBatch8(b *testing.B) {
	chainID := big.NewInt(1337)
	bundles := make([]transferProofBundle, 8)
	for i := range bundles {
		bundles[i] = benchmarkTransferBundle(b, chainID)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := NewBatchVerifier()
		for _, bundle := range bundles {
			if err := batch.AddCiphertextValidityProofWithContext(bundle.commitment, bundle.senderHandle, bundle.receiverHandle, bundle.senderPub, bundle.receiverPub, bundle.ctValidityProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := batch.AddCommitmentEqProofWithContext(bundle.senderPub, bundle.newSenderBalanceCt, bundle.sourceCommitment, bundle.commitmentEqProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := batch.AddRangeProof(bundle.sourceCommitment, bundle.commitment, bundle.rangeProof); err != nil {
				b.Fatal(err)
			}
		}
		if err := batch.Verify(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrivacyVerificationSequentialMixedSet(b *testing.B) {
	chainID := big.NewInt(1337)
	transfers := make([]transferProofBundle, 4)
	for i := range transfers {
		transfers[i] = benchmarkTransferBundle(b, chainID)
	}
	shields := make([]shieldProofBundle, 2)
	for i := range shields {
		shields[i] = benchmarkShieldBundle(b, chainID)
	}
	unshields := make([]unshieldProofBundle, 2)
	for i := range unshields {
		unshields[i] = benchmarkUnshieldBundle(b, chainID)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, bundle := range transfers {
			if err := VerifyCiphertextValidityProofWithContext(bundle.commitment, bundle.senderHandle, bundle.receiverHandle, bundle.senderPub, bundle.receiverPub, bundle.ctValidityProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := VerifyCommitmentEqProofWithContext(bundle.senderPub, bundle.newSenderBalanceCt, bundle.sourceCommitment, bundle.commitmentEqProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := VerifyRangeProof(bundle.sourceCommitment, bundle.commitment, bundle.rangeProof); err != nil {
				b.Fatal(err)
			}
		}
		for _, bundle := range shields {
			if err := VerifyShieldProofWithContext(bundle.commitment, bundle.handle, bundle.pubkey, 77, bundle.proof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := VerifySingleRangeProof(bundle.commitment, bundle.rangeProof); err != nil {
				b.Fatal(err)
			}
		}
		for _, bundle := range unshields {
			if err := VerifyCommitmentEqProofWithContext(bundle.pubkey, bundle.zeroedCt, bundle.sourceCommitment, bundle.commitmentEqProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := VerifySingleRangeProof(bundle.sourceCommitment, bundle.rangeProof); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkPrivacyVerificationBatchMixedSet(b *testing.B) {
	chainID := big.NewInt(1337)
	transfers := make([]transferProofBundle, 4)
	for i := range transfers {
		transfers[i] = benchmarkTransferBundle(b, chainID)
	}
	shields := make([]shieldProofBundle, 2)
	for i := range shields {
		shields[i] = benchmarkShieldBundle(b, chainID)
	}
	unshields := make([]unshieldProofBundle, 2)
	for i := range unshields {
		unshields[i] = benchmarkUnshieldBundle(b, chainID)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := NewBatchVerifier()
		for _, bundle := range transfers {
			if err := batch.AddCiphertextValidityProofWithContext(bundle.commitment, bundle.senderHandle, bundle.receiverHandle, bundle.senderPub, bundle.receiverPub, bundle.ctValidityProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := batch.AddCommitmentEqProofWithContext(bundle.senderPub, bundle.newSenderBalanceCt, bundle.sourceCommitment, bundle.commitmentEqProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := batch.AddRangeProof(bundle.sourceCommitment, bundle.commitment, bundle.rangeProof); err != nil {
				b.Fatal(err)
			}
		}
		for _, bundle := range shields {
			if err := batch.AddShieldProofWithContext(bundle.commitment, bundle.handle, bundle.pubkey, 77, bundle.proof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := batch.AddSingleRangeProof(bundle.commitment, bundle.rangeProof); err != nil {
				b.Fatal(err)
			}
		}
		for _, bundle := range unshields {
			if err := batch.AddCommitmentEqProofWithContext(bundle.pubkey, bundle.zeroedCt, bundle.sourceCommitment, bundle.commitmentEqProof, bundle.ctx); err != nil {
				b.Fatal(err)
			}
			if err := batch.AddSingleRangeProof(bundle.sourceCommitment, bundle.rangeProof); err != nil {
				b.Fatal(err)
			}
		}
		if err := batch.Verify(); err != nil {
			b.Fatal(err)
		}
	}
}
