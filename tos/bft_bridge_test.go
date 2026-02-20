package tos

import (
	"math/big"
	"testing"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/bft"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
)

func TestShouldAdvanceFinality(t *testing.T) {
	block := func(number uint64) *types.Block {
		return types.NewBlockWithHeader(&types.Header{Number: new(big.Int).SetUint64(number)})
	}
	tests := []struct {
		name      string
		current   *types.Block
		candidate *types.Block
		want      bool
	}{
		{
			name:      "nil candidate",
			current:   block(10),
			candidate: nil,
			want:      false,
		},
		{
			name:      "first finalized",
			current:   nil,
			candidate: block(1),
			want:      true,
		},
		{
			name:      "same height",
			current:   block(12),
			candidate: block(12),
			want:      false,
		},
		{
			name:      "lower height",
			current:   block(12),
			candidate: block(11),
			want:      false,
		},
		{
			name:      "higher height",
			current:   block(12),
			candidate: block(13),
			want:      true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldAdvanceFinality(tc.current, tc.candidate); got != tc.want {
				t.Fatalf("shouldAdvanceFinality() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestVerifyVoteSignature(t *testing.T) {
	chainID := big.NewInt(1)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	validator := crypto.PubkeyToAddress(key.PublicKey)
	digest, err := voteDigestTOSv1(chainID, 9, 0, common.HexToHash("0x99"))
	if err != nil {
		t.Fatalf("vote digest: %v", err)
	}
	sig, err := crypto.Sign(digest.Bytes(), key)
	if err != nil {
		t.Fatalf("sign vote digest: %v", err)
	}
	vote := bft.Vote{
		Height:    9,
		Round:     0,
		BlockHash: common.HexToHash("0x99"),
		Validator: validator,
		Weight:    1,
		Signature: sig,
	}
	if err := verifyVoteSignature(chainID, vote); err != nil {
		t.Fatalf("verify vote signature failed: %v", err)
	}
}

func TestVerifyVoteSignatureRejectsWrongValidator(t *testing.T) {
	chainID := big.NewInt(1)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	digest, err := voteDigestTOSv1(chainID, 10, 0, common.HexToHash("0x100"))
	if err != nil {
		t.Fatalf("vote digest: %v", err)
	}
	sig, err := crypto.Sign(digest.Bytes(), key)
	if err != nil {
		t.Fatalf("sign vote digest: %v", err)
	}
	vote := bft.Vote{
		Height:    10,
		Round:     0,
		BlockHash: common.HexToHash("0x100"),
		Validator: common.HexToAddress("0x1234"),
		Weight:    1,
		Signature: sig,
	}
	if err := verifyVoteSignature(chainID, vote); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestVerifyQCAttestations(t *testing.T) {
	chainID := big.NewInt(1)
	key1, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key1: %v", err)
	}
	key2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}
	blockHash := common.HexToHash("0x777")
	digest, err := voteDigestTOSv1(chainID, 11, 0, blockHash)
	if err != nil {
		t.Fatalf("vote digest: %v", err)
	}
	sig1, err := crypto.Sign(digest.Bytes(), key1)
	if err != nil {
		t.Fatalf("sign1: %v", err)
	}
	sig2, err := crypto.Sign(digest.Bytes(), key2)
	if err != nil {
		t.Fatalf("sign2: %v", err)
	}
	qc := &bft.QC{
		Height:      11,
		Round:       0,
		BlockHash:   blockHash,
		TotalWeight: 2,
		Required:    2,
		Attestations: []bft.QCAttestation{
			{Validator: crypto.PubkeyToAddress(key1.PublicKey), Weight: 1, Signature: sig1},
			{Validator: crypto.PubkeyToAddress(key2.PublicKey), Weight: 1, Signature: sig2},
		},
	}
	if err := qc.Verify(); err != nil {
		t.Fatalf("qc verify: %v", err)
	}
	if err := verifyQCAttestations(chainID, qc); err != nil {
		t.Fatalf("verifyQCAttestations failed: %v", err)
	}
}
