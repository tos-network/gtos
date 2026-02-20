package tos

import (
	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/bft"
	"github.com/tos-network/gtos/core/types"
	tosp "github.com/tos-network/gtos/tos/protocols/tos"
)

type handlerBFTBroadcaster struct {
	h *handler
}

type localVoteSigner interface {
	ValidatorAddress() common.Address
	CanSignVotes() bool
	SignVote(digest common.Hash) ([]byte, error)
}

func (b *handlerBFTBroadcaster) BroadcastVote(v bft.Vote) error {
	packet := bftVoteToPacket(v)
	var lastErr error
	for _, peer := range b.h.peers.allPeers() {
		if err := peer.SendVote(packet); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (b *handlerBFTBroadcaster) BroadcastQC(qc *bft.QC) error {
	return b.h.broadcastQC(qc)
}

func (h *handler) handleVotePacket(packet *tosp.VotePacket) error {
	if packet == nil || h.bftReactor == nil {
		return nil
	}
	vote := packetToBFTVote(packet)
	if err := verifyVoteSignature(chainIDFromBlockChain(h.chain), vote); err != nil {
		return err
	}
	_, err := h.bftReactor.HandleIncomingVote(vote)
	return err
}

func (h *handler) handleQCPacket(packet *tosp.QCPacket) error {
	if packet == nil {
		return nil
	}
	qc := packetToBFTQC(packet)
	if err := qc.Verify(); err != nil {
		return err
	}
	if err := verifyQCAttestations(chainIDFromBlockChain(h.chain), qc); err != nil {
		return err
	}
	h.markQCSeen(qc)
	h.setLatestQC(qc)
	return nil
}

func (h *handler) broadcastQC(qc *bft.QC) error {
	if qc == nil {
		return nil
	}
	if !h.markQCSeen(qc) {
		return nil
	}
	packet := bftQCToPacket(qc)
	var lastErr error
	for _, peer := range h.peers.allPeers() {
		if err := peer.SendQC(packet); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func (h *handler) proposeVoteForBlock(block *types.Block) error {
	if block == nil || h.bftReactor == nil || h.chain == nil {
		return nil
	}
	engine := h.chain.Engine()
	signer, ok := engine.(localVoteSigner)
	if !ok || !signer.CanSignVotes() {
		return nil
	}
	validator := signer.ValidatorAddress()
	if validator == (common.Address{}) {
		return nil
	}
	height := block.NumberU64()
	round := uint64(0)
	chainID := chainIDFromBlockChain(h.chain)
	digest, err := voteDigestTOSv1(chainID, height, round, block.Hash())
	if err != nil {
		return err
	}
	signature, err := signer.SignVote(digest)
	if err != nil {
		return err
	}
	vote := bft.Vote{
		Height:    height,
		Round:     round,
		BlockHash: block.Hash(),
		Validator: validator,
		Weight:    1,
		Signature: signature,
	}
	if err := verifyVoteSignature(chainID, vote); err != nil {
		return err
	}
	return h.bftReactor.ProposeVote(vote)
}
