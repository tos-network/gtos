package bft

// VoteBroadcaster can be implemented by networking layer adapters.
type VoteBroadcaster interface {
	BroadcastVote(v Vote) error
	BroadcastQC(qc *QC) error
}

// Reactor glues vote ingestion and QC assembly.
// The type is intentionally transport-agnostic for Phase-1.
type Reactor struct {
	pool        *VotePool
	broadcaster VoteBroadcaster
	onQC        func(*QC)
}

func NewReactor(pool *VotePool, broadcaster VoteBroadcaster, onQC func(*QC)) *Reactor {
	return &Reactor{
		pool:        pool,
		broadcaster: broadcaster,
		onQC:        onQC,
	}
}

func (r *Reactor) HandleIncomingVote(v Vote) (*QC, error) {
	_, err := r.pool.AddVote(v)
	if err != nil {
		return nil, err
	}
	qc, ok := r.pool.BuildQC(v.Height, v.Round, v.BlockHash)
	if !ok {
		return nil, nil
	}
	if r.onQC != nil {
		r.onQC(qc)
	}
	if r.broadcaster != nil {
		_ = r.broadcaster.BroadcastQC(qc)
	}
	return qc, nil
}

func (r *Reactor) ProposeVote(v Vote) error {
	_, err := r.pool.AddVote(v)
	if err != nil {
		return err
	}
	if r.broadcaster != nil {
		return r.broadcaster.BroadcastVote(v)
	}
	return nil
}
