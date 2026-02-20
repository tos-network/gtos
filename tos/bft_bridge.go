package tos

import (
	"errors"
	"fmt"

	"github.com/tos-network/gtos/common"
	"github.com/tos-network/gtos/consensus/bft"
	"github.com/tos-network/gtos/core/types"
	"github.com/tos-network/gtos/crypto"
	"github.com/tos-network/gtos/rlp"
	tosp "github.com/tos-network/gtos/tos/protocols/tos"
)

type handlerBFTBroadcaster struct {
	h *handler
}

var errInvalidBFTVoteSignature = errors.New("invalid bft vote signature")

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
	if err := verifyVoteSignature(vote); err != nil {
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
	if err := verifyQCAttestations(qc); err != nil {
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

func (h *handler) setLatestQC(qc *bft.QC) {
	h.bftMu.Lock()
	h.bftLatestQC = cloneQC(qc)
	h.bftMu.Unlock()
	h.applyQCFinality(qc)
}

func (h *handler) markQCSeen(qc *bft.QC) bool {
	if qc == nil {
		return false
	}
	key := qcCacheKey(qc.Height, qc.Round, qc.BlockHash)
	h.bftMu.Lock()
	defer h.bftMu.Unlock()
	if _, ok := h.bftSeenQCs[key]; ok {
		return false
	}
	h.bftSeenQCs[key] = struct{}{}
	return true
}

func (h *handler) applyQCFinality(qc *bft.QC) {
	if qc == nil || h.chain == nil {
		return
	}
	block := h.chain.GetBlockByHash(qc.BlockHash)
	if block == nil {
		return
	}
	// Only advance finality on canonical blocks.
	if canonical := h.chain.GetBlockByNumber(block.NumberU64()); canonical == nil || canonical.Hash() != block.Hash() {
		return
	}
	if !shouldAdvanceFinality(h.chain.CurrentFinalizedBlock(), block) {
		return
	}
	h.chain.SetSafe(block)
	h.chain.SetFinalized(block)
	if h.onQCFinalized != nil {
		go h.onQCFinalized(block)
	}
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
	digest, err := voteDigest(height, round, block.Hash())
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
	if err := verifyVoteSignature(vote); err != nil {
		return err
	}
	return h.bftReactor.ProposeVote(vote)
}

func voteDigest(height, round uint64, blockHash common.Hash) (common.Hash, error) {
	payload, err := rlp.EncodeToBytes([]interface{}{
		"gtos-bft-vote-v1",
		height,
		round,
		blockHash,
	})
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(payload), nil
}

func verifyVoteSignature(v bft.Vote) error {
	digest, err := voteDigest(v.Height, v.Round, v.BlockHash)
	if err != nil {
		return err
	}
	recovered, err := recoverSignerAddress(digest, v.Signature)
	if err != nil {
		return errInvalidBFTVoteSignature
	}
	if recovered != v.Validator {
		return errInvalidBFTVoteSignature
	}
	return nil
}

func verifyQCAttestations(qc *bft.QC) error {
	if qc == nil {
		return bft.ErrInsufficientQuorum
	}
	var (
		total uint64
		seen  = make(map[common.Address]struct{}, len(qc.Attestations))
	)
	for _, att := range qc.Attestations {
		if att.Validator == (common.Address{}) || att.Weight == 0 || len(att.Signature) == 0 {
			return bft.ErrInvalidVote
		}
		if _, exists := seen[att.Validator]; exists {
			return bft.ErrInvalidVote
		}
		seen[att.Validator] = struct{}{}

		vote := bft.Vote{
			Height:    qc.Height,
			Round:     qc.Round,
			BlockHash: qc.BlockHash,
			Validator: att.Validator,
			Weight:    att.Weight,
			Signature: att.Signature,
		}
		if err := verifyVoteSignature(vote); err != nil {
			return err
		}
		total += att.Weight
	}
	if total != qc.TotalWeight {
		return bft.ErrInsufficientQuorum
	}
	return nil
}

func recoverSignerAddress(digest common.Hash, signature []byte) (common.Address, error) {
	if len(signature) != crypto.SignatureLength {
		return common.Address{}, errInvalidBFTVoteSignature
	}
	sig := append([]byte(nil), signature...)
	pub, err := crypto.SigToPub(digest.Bytes(), sig)
	if err != nil && sig[64] >= 27 {
		sig[64] -= 27
		pub, err = crypto.SigToPub(digest.Bytes(), sig)
	}
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pub), nil
}

func shouldAdvanceFinality(currentFinalized, candidate *types.Block) bool {
	if candidate == nil {
		return false
	}
	if currentFinalized == nil {
		return true
	}
	return candidate.NumberU64() > currentFinalized.NumberU64()
}

func qcCacheKey(height, round uint64, blockHash common.Hash) string {
	return fmt.Sprintf("%d/%d/%s", height, round, blockHash.Hex())
}

func packetToBFTVote(packet *tosp.VotePacket) bft.Vote {
	return bft.Vote{
		Height:    packet.Height,
		Round:     packet.Round,
		BlockHash: packet.BlockHash,
		Validator: packet.Validator,
		Weight:    packet.Weight,
		Signature: append([]byte(nil), packet.Signature...),
	}
}

func bftVoteToPacket(v bft.Vote) *tosp.VotePacket {
	return &tosp.VotePacket{
		Height:    v.Height,
		Round:     v.Round,
		BlockHash: v.BlockHash,
		Validator: v.Validator,
		Weight:    v.Weight,
		Signature: append([]byte(nil), v.Signature...),
	}
}

func packetToBFTQC(packet *tosp.QCPacket) *bft.QC {
	att := make([]bft.QCAttestation, 0, len(packet.Attestations))
	for _, a := range packet.Attestations {
		att = append(att, bft.QCAttestation{
			Validator: a.Validator,
			Weight:    a.Weight,
			Signature: append([]byte(nil), a.Signature...),
		})
	}
	return &bft.QC{
		Height:       packet.Height,
		Round:        packet.Round,
		BlockHash:    packet.BlockHash,
		TotalWeight:  packet.TotalWeight,
		Required:     packet.Required,
		Attestations: att,
	}
}

func bftQCToPacket(qc *bft.QC) *tosp.QCPacket {
	if qc == nil {
		return nil
	}
	att := make([]tosp.QCAttestationPacket, 0, len(qc.Attestations))
	for _, a := range qc.Attestations {
		att = append(att, tosp.QCAttestationPacket{
			Validator: a.Validator,
			Weight:    a.Weight,
			Signature: append([]byte(nil), a.Signature...),
		})
	}
	return &tosp.QCPacket{
		Height:       qc.Height,
		Round:        qc.Round,
		BlockHash:    qc.BlockHash,
		TotalWeight:  qc.TotalWeight,
		Required:     qc.Required,
		Attestations: att,
	}
}

func cloneQC(qc *bft.QC) *bft.QC {
	if qc == nil {
		return nil
	}
	att := make([]bft.QCAttestation, 0, len(qc.Attestations))
	for _, a := range qc.Attestations {
		att = append(att, bft.QCAttestation{
			Validator: a.Validator,
			Weight:    a.Weight,
			Signature: append([]byte(nil), a.Signature...),
		})
	}
	return &bft.QC{
		Height:       qc.Height,
		Round:        qc.Round,
		BlockHash:    qc.BlockHash,
		TotalWeight:  qc.TotalWeight,
		Required:     qc.Required,
		Attestations: att,
	}
}
