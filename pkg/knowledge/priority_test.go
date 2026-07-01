package knowledge

import (
	"testing"
	"time"
)

func TestPriorityBoundaries(t *testing.T) {
	store := NewMemoryStore()
	sig := PatternSignature{Method: "GET", RouteClass: "/admin"}
	scope := ScopeTarget
	ctx := KnowledgeContext{TargetID: "t1"}

	// Simulate a poisoning attack / over-learning
	for i := 0; i < 1000; i++ {
		store.RecordDecision(AnalystDecision{Decision: DecisionApproved, Metadata: DecisionMetadata{Confidence: 5, EvidenceCount: 1}}, sig, ctx, scope)
	}

	result := store.LookupPattern(sig, ctx, time.Now())

	calc := DefaultPriorityCalculator{}
	policy := KnowledgePolicy{
		MaxInfluencePerPattern: 15,
		MinSamplesForBoost:     3,
	}

	finalPriority, reasons := calc.Calculate(50, result, policy)

	if finalPriority > 65 {
		t.Fatalf("Priority calculation breached the 15-point KnowledgeBonus cap: %d", finalPriority)
	}
	
	if len(reasons) < 2 {
		t.Fatalf("Priority calculator failed to emit explainable reasons")
	}
}
