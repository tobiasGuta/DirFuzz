package knowledge

import (
	"dirfuzz/pkg/ui/models"
	"sync"
	"time"
)

type KnowledgeResult struct {
	ConfidenceBoost      int
	ConfidencePenalty    int
	SuggestedValidations []models.ValidationType
}

type KnowledgeContext struct {
	TargetID   string
	ProjectID  string
	CampaignID string
}

type KnowledgeStore interface {
	RecordDecision(decision AnalystDecision, sig PatternSignature, ctx KnowledgeContext, scope KnowledgeScope) error
	LookupPattern(sig PatternSignature, ctx KnowledgeContext, at time.Time) KnowledgeResult

	RecordDiffMemory(mem DiffMemory) error
	LookupDiffMemory(diffHash string) (DiffMemory, bool)
}

type MemoryStore struct {
	mu           sync.RWMutex
	entries      map[string][]KnowledgeEntry
	diffMemories map[string]DiffMemory
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		entries:      make(map[string][]KnowledgeEntry),
		diffMemories: make(map[string]DiffMemory),
	}
}

func (s *MemoryStore) RecordDecision(decision AnalystDecision, sig PatternSignature, ctx KnowledgeContext, scope KnowledgeScope) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := sig.Hash()

	initialWeight := 0
	if decision.Decision == DecisionConfirmed || decision.Decision == DecisionApproved {
		initialWeight = decision.Metadata.Confidence * decision.Metadata.EvidenceCount
		if initialWeight == 0 {
			initialWeight = 5 // fallback
		}
	} else if decision.Decision == DecisionRejected || decision.Decision == DecisionDismissed {
		initialWeight = -5 // Penalty
	}

	entry := KnowledgeEntry{
		PatternHash: hash,
		DecisionID:  decision.ID,
		TargetID:    ctx.TargetID,
		ProjectID:   ctx.ProjectID,
		Scope:       scope,
		Decay: KnowledgeDecay{
			LastConfirmed: time.Now(),
			LastObserved:  time.Now(),
			HalfLifeDays:  30, // Default 30 days
			CurrentWeight: float64(initialWeight),
			MinWeight:     5.0,
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour), // 90 days total ttl
		Version:   "v1",
	}

	existing := s.entries[hash]
	now := time.Now()
	cleaned := existing[:0]
	for _, e := range existing {
		if now.Before(e.ExpiresAt) {
			cleaned = append(cleaned, e)
		}
	}

	const maxPerHash = 100
	if len(cleaned) >= maxPerHash {
		cleaned = cleaned[len(cleaned)-maxPerHash+1:]
	}
	s.entries[hash] = append(cleaned, entry)
	return nil
}

func (s *MemoryStore) RecordDiffMemory(mem DiffMemory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.diffMemories[mem.Fingerprint] = mem
	return nil
}

func (s *MemoryStore) LookupDiffMemory(diffHash string) (DiffMemory, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	mem, ok := s.diffMemories[diffHash]
	return mem, ok
}

func (s *MemoryStore) LookupPattern(sig PatternSignature, ctx KnowledgeContext, at time.Time) KnowledgeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	hash := sig.Hash()
	entries := s.entries[hash]

	result := KnowledgeResult{}

	for _, entry := range entries {
		// Enforce cross-session isolation
		if entry.Scope == ScopeTarget && entry.TargetID != ctx.TargetID {
			continue
		}
		if entry.Scope == ScopeScan && (entry.TargetID != ctx.TargetID || entry.ProjectID != ctx.ProjectID) {
			continue
		}
		if entry.Scope == ScopeCampaign && (entry.TargetID != ctx.TargetID || entry.CampaignID != ctx.CampaignID) {
			continue
		}

		if at.After(entry.ExpiresAt) {
			continue
		}

		decayedWeight := int(CalculateDecayedWeight(entry.Decay, at, entry.Decay.CurrentWeight))

		if decayedWeight > 0 {
			result.ConfidenceBoost += decayedWeight
		} else if decayedWeight < 0 {
			result.ConfidencePenalty += (-decayedWeight)
		}
	}

	return result
}
