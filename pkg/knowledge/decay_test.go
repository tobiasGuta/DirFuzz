package knowledge

import (
	"testing"
	"time"
)

func TestKnowledgeDecayHalfLife(t *testing.T) {
	decay := KnowledgeDecay{
		LastConfirmed: time.Now().Add(-180 * 24 * time.Hour), // 180 days ago
		LastObserved:  time.Now().Add(-10 * 24 * time.Hour),  // 10 days ago
		HalfLifeDays:  90,
		MinWeight:     10.0,
	}

	// 180 days age = 2 half lives. e^(-2) = ~0.135
	originalWeight := 100.0
	current := CalculateDecayedWeight(decay, time.Now(), originalWeight)

	if current > 14.0 || current < 13.0 {
		t.Fatalf("Decay weight math incorrect, got %f expected ~13.5", current)
	}
}

func TestKnowledgeDecayMinWeight(t *testing.T) {
	decay := KnowledgeDecay{
		LastConfirmed: time.Now().Add(-1000 * 24 * time.Hour),
		HalfLifeDays:  90,
		MinWeight:     5.0,
	}

	current := CalculateDecayedWeight(decay, time.Now(), 100.0)
	if current != 5.0 {
		t.Fatalf("Decay failed to respect min weight, got %f expected 5.0", current)
	}
}
