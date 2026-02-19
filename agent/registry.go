package agent

import (
	"strings"
	"sync"
	"time"
)

// Registry is the in-memory agent index maintained by a gtos node.
// It is populated by the Indexer which consumes on-chain system action events.
type Registry struct {
	mu        sync.RWMutex
	records   map[string]*AgentRecord  // agentID → record
	manifests map[string]*ToolManifest // agentID → manifest
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		records:   make(map[string]*AgentRecord),
		manifests: make(map[string]*ToolManifest),
	}
}

// Upsert inserts or replaces an AgentRecord in the index.
func (r *Registry) Upsert(rec AgentRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := rec
	r.records[rec.AgentID] = &clone
}

// UpsertManifest inserts or replaces a ToolManifest in the index.
func (r *Registry) UpsertManifest(m ToolManifest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	clone := m
	r.manifests[m.AgentID] = &clone
}

// Get returns the AgentRecord for agentID, or false if not found.
func (r *Registry) Get(agentID string) (AgentRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.records[agentID]
	if !ok {
		return AgentRecord{}, false
	}
	return *p, true
}

// GetManifest returns the ToolManifest for agentID, or false if not found.
func (r *Registry) GetManifest(agentID string) (ToolManifest, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.manifests[agentID]
	if !ok {
		return ToolManifest{}, false
	}
	return *p, true
}

// Remove deletes the record and manifest for agentID.
func (r *Registry) Remove(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.records, agentID)
	delete(r.manifests, agentID)
}

// Query returns agents matching req, ordered by descending score.
func (r *Registry) Query(req QueryRequest) []QueryResult {
	now := time.Now().Unix()
	if req.Limit <= 0 {
		req.Limit = 20
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []QueryResult
	for _, rec := range r.records {
		if rec.ExpiresAt > 0 && rec.ExpiresAt < now {
			continue // expired
		}
		score := scoreRecord(rec, r.manifests[rec.AgentID], &req)
		if score <= 0 {
			continue
		}
		results = append(results, QueryResult{Record: *rec, Score: score})
	}

	// Sort descending by score
	sortQueryResults(results)

	if len(results) > req.Limit {
		results = results[:req.Limit]
	}
	return results
}

// Len returns the number of agent records in the registry.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.records)
}

// scoreRecord produces a relevance score for a record given a query.
// Returns 0 if the record doesn't match mandatory filters.
func scoreRecord(rec *AgentRecord, manifest *ToolManifest, req *QueryRequest) int {
	score := 10 // base

	// Category filter
	if req.Category != "" && !strings.EqualFold(rec.CapabilityDigest, "") {
		if manifest != nil {
			matched := false
			for _, t := range manifest.Tools {
				if strings.EqualFold(t.Category, req.Category) {
					matched = true
					break
				}
			}
			if !matched {
				return 0
			}
			score += 20
		}
	}

	// ToolID filter
	if req.ToolID != "" && manifest != nil {
		matched := false
		for _, t := range manifest.Tools {
			if t.ToolID == req.ToolID {
				matched = true
				break
			}
		}
		if !matched {
			return 0
		}
		score += 30
	}

	// Text query — naive substring match against tool names/descriptions
	if req.Query != "" && manifest != nil {
		q := strings.ToLower(req.Query)
		for _, t := range manifest.Tools {
			if strings.Contains(strings.ToLower(t.Name), q) ||
				strings.Contains(strings.ToLower(t.Description), q) {
				score += 10
				break
			}
		}
	}

	// Region preference
	if req.PreferredRegion != "" && strings.EqualFold(rec.Region, req.PreferredRegion) {
		score += 5
	}

	// Provider tier filter
	if len(req.ProviderTiers) > 0 {
		matched := false
		for _, tier := range req.ProviderTiers {
			if strings.EqualFold(rec.ProviderTier, tier) {
				matched = true
				break
			}
		}
		if !matched {
			return 0
		}
	}

	return score
}

func sortQueryResults(rs []QueryResult) {
	// Insertion sort — typical result sets are small
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j].Score > rs[j-1].Score; j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}
