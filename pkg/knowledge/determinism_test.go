package knowledge

import (
	"testing"
	"time"
)

func TestKnowledgeDeterminism(t *testing.T) {
	// Prove that KnowledgeResults are deterministic via the PatternSignature hash
	
	storeA := NewMemoryStore()
	storeB := NewMemoryStore()

	sig := PatternSignature{
		Method:     "GET",
		RouteClass: "/api/users/{id}",
		StatusCode: 403,
	}

	scope := ScopeTarget
	ctx := KnowledgeContext{TargetID: "t1", ProjectID: "p1"}

	decision := AnalystDecision{
		Decision: DecisionApproved,
	}

	storeA.RecordDecision(decision, sig, ctx, scope)
	storeB.RecordDecision(decision, sig, ctx, scope)

	resA := storeA.LookupPattern(sig, ctx, time.Now())
	resB := storeB.LookupPattern(sig, ctx, time.Now())

	if resA.ConfidenceBoost != resB.ConfidenceBoost {
		t.Fatalf("Knowledge is not deterministic")
	}
}
