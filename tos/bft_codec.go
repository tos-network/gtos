package tos

import (
	"github.com/tos-network/gtos/consensus/bft"
	tosp "github.com/tos-network/gtos/tos/protocols/tos"
)

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
