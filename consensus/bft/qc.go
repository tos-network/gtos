package bft

// RequiredQuorumWeight returns the minimum weight for a 2/3+1 quorum.
func RequiredQuorumWeight(total uint64) uint64 {
	if total == 0 {
		return 1
	}
	return (2*total)/3 + 1
}

// Verify performs basic structural validation on a QC.
func (qc *QC) Verify() error {
	if qc == nil {
		return ErrInsufficientQuorum
	}
	if qc.TotalWeight < qc.Required {
		return ErrInsufficientQuorum
	}
	if qc.Required == 0 || len(qc.Attestations) == 0 {
		return ErrInsufficientQuorum
	}
	return nil
}
