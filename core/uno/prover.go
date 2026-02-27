package uno

import (
	"bytes"
	"math/big"

	"github.com/tos-network/gtos/common"
	cryptouno "github.com/tos-network/gtos/crypto/uno"
)

type ShieldBuildArgs struct {
	ChainID   *big.Int
	From      common.Address
	Nonce     uint64
	SenderOld Ciphertext
	SenderPub []byte
	Amount    uint64
}

type TransferBuildArgs struct {
	ChainID     *big.Int
	From        common.Address
	To          common.Address
	Nonce       uint64
	SenderOld   Ciphertext
	ReceiverOld Ciphertext
	SenderPriv  []byte
	ReceiverPub []byte
	Amount      uint64
}

type UnshieldBuildArgs struct {
	ChainID    *big.Int
	From       common.Address
	To         common.Address
	Nonce      uint64
	SenderOld  Ciphertext
	SenderPriv []byte
	Amount     uint64
}

func makeCiphertext(commitment32, handle32 []byte) (Ciphertext, error) {
	if len(commitment32) != 32 || len(handle32) != 32 {
		return Ciphertext{}, ErrInvalidPayload
	}
	var out Ciphertext
	copy(out.Commitment[:], commitment32)
	copy(out.Handle[:], handle32)
	return out, nil
}

func BuildShieldPayloadProof(args ShieldBuildArgs) (ShieldPayload, []byte, error) {
	if args.Amount == 0 || len(args.SenderPub) != 32 {
		return ShieldPayload{}, nil, ErrInvalidPayload
	}
	opening, err := cryptouno.GenerateOpening()
	if err != nil {
		return ShieldPayload{}, nil, ErrInvalidPayload
	}
	commitment, err := cryptouno.PedersenCommitmentWithOpening(opening, args.Amount)
	if err != nil {
		return ShieldPayload{}, nil, ErrInvalidPayload
	}
	handle, err := cryptouno.DecryptHandleWithOpening(args.SenderPub, opening)
	if err != nil {
		return ShieldPayload{}, nil, ErrInvalidPayload
	}
	delta, err := makeCiphertext(commitment, handle)
	if err != nil {
		return ShieldPayload{}, nil, err
	}
	ctx := BuildUNOShieldTranscriptContext(args.ChainID, args.From, args.Nonce, args.Amount, args.SenderOld, delta)
	proof, proofCommitment, proofHandle, err := cryptouno.ProveShieldProofWithContext(args.SenderPub, args.Amount, opening, ctx)
	if err != nil {
		return ShieldPayload{}, nil, ErrInvalidPayload
	}
	if !bytes.Equal(proofCommitment, commitment) || !bytes.Equal(proofHandle, handle) {
		return ShieldPayload{}, nil, ErrInvalidPayload
	}
	return ShieldPayload{
		Amount:      args.Amount,
		NewSender:   delta,
		ProofBundle: proof,
	}, opening, nil
}

func BuildTransferPayloadProof(args TransferBuildArgs) (TransferPayload, []byte, error) {
	if args.Amount == 0 || args.To == (common.Address{}) || len(args.SenderPriv) != 32 || len(args.ReceiverPub) != 32 {
		return TransferPayload{}, nil, ErrInvalidPayload
	}
	senderPub, err := cryptouno.PublicKeyFromPrivate(args.SenderPriv)
	if err != nil {
		return TransferPayload{}, nil, ErrInvalidPayload
	}
	opening, err := cryptouno.GenerateOpening()
	if err != nil {
		return TransferPayload{}, nil, ErrInvalidPayload
	}
	commitment, err := cryptouno.PedersenCommitmentWithOpening(opening, args.Amount)
	if err != nil {
		return TransferPayload{}, nil, ErrInvalidPayload
	}
	senderHandle, err := cryptouno.DecryptHandleWithOpening(senderPub, opening)
	if err != nil {
		return TransferPayload{}, nil, ErrInvalidPayload
	}
	receiverHandle, err := cryptouno.DecryptHandleWithOpening(args.ReceiverPub, opening)
	if err != nil {
		return TransferPayload{}, nil, ErrInvalidPayload
	}
	senderDelta, err := makeCiphertext(commitment, senderHandle)
	if err != nil {
		return TransferPayload{}, nil, err
	}
	receiverDelta, err := makeCiphertext(commitment, receiverHandle)
	if err != nil {
		return TransferPayload{}, nil, err
	}
	newSender, err := SubCiphertexts(args.SenderOld, senderDelta)
	if err != nil {
		return TransferPayload{}, nil, err
	}
	ctx := BuildUNOTransferTranscriptContext(args.ChainID, args.From, args.To, args.Nonce, args.SenderOld, newSender, args.ReceiverOld, receiverDelta)
	ctProof, proofCommitment, proofSenderHandle, proofReceiverHandle, err := cryptouno.ProveCTValidityProofWithContext(
		senderPub, args.ReceiverPub, args.Amount, opening, true, ctx,
	)
	if err != nil {
		return TransferPayload{}, nil, ErrInvalidPayload
	}
	if !bytes.Equal(proofCommitment, commitment) || !bytes.Equal(proofSenderHandle, senderHandle) || !bytes.Equal(proofReceiverHandle, receiverHandle) {
		return TransferPayload{}, nil, ErrInvalidPayload
	}
	balanceProof, err := cryptouno.ProveBalanceProofWithContext(args.SenderPriv, ciphertextToCompressed(senderDelta), args.Amount, ctx)
	if err != nil {
		return TransferPayload{}, nil, ErrInvalidPayload
	}
	proofBundle := make([]byte, 0, len(ctProof)+len(balanceProof))
	proofBundle = append(proofBundle, ctProof...)
	proofBundle = append(proofBundle, balanceProof...)
	return TransferPayload{
		To:            args.To,
		NewSender:     newSender,
		ReceiverDelta: receiverDelta,
		ProofBundle:   proofBundle,
	}, opening, nil
}

func BuildUnshieldPayloadProof(args UnshieldBuildArgs) (UnshieldPayload, []byte, error) {
	if args.Amount == 0 || args.To == (common.Address{}) || len(args.SenderPriv) != 32 {
		return UnshieldPayload{}, nil, ErrInvalidPayload
	}
	senderPub, err := cryptouno.PublicKeyFromPrivate(args.SenderPriv)
	if err != nil {
		return UnshieldPayload{}, nil, ErrInvalidPayload
	}
	opening, err := cryptouno.GenerateOpening()
	if err != nil {
		return UnshieldPayload{}, nil, ErrInvalidPayload
	}
	commitment, err := cryptouno.PedersenCommitmentWithOpening(opening, args.Amount)
	if err != nil {
		return UnshieldPayload{}, nil, ErrInvalidPayload
	}
	senderHandle, err := cryptouno.DecryptHandleWithOpening(senderPub, opening)
	if err != nil {
		return UnshieldPayload{}, nil, ErrInvalidPayload
	}
	senderDelta, err := makeCiphertext(commitment, senderHandle)
	if err != nil {
		return UnshieldPayload{}, nil, err
	}
	newSender, err := SubCiphertexts(args.SenderOld, senderDelta)
	if err != nil {
		return UnshieldPayload{}, nil, err
	}
	ctx := BuildUNOUnshieldTranscriptContext(args.ChainID, args.From, args.To, args.Nonce, args.Amount, args.SenderOld, newSender)
	balanceProof, err := cryptouno.ProveBalanceProofWithContext(args.SenderPriv, ciphertextToCompressed(senderDelta), args.Amount, ctx)
	if err != nil {
		return UnshieldPayload{}, nil, ErrInvalidPayload
	}
	return UnshieldPayload{
		To:          args.To,
		Amount:      args.Amount,
		NewSender:   newSender,
		ProofBundle: balanceProof,
	}, opening, nil
}
