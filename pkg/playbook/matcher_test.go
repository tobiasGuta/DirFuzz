package playbook

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui/models"
	"testing"
	"time"
)

func TestPlaybookPatternMatch(t *testing.T) {
	pb := Playbook{
		ID:      "pb1",
		Enabled: true,
		Triggers: []TriggerRule{
			{Event: "RESPONSE_OBSERVED", Condition: map[string]string{"status": "403"}},
		},
		Actions: []PlaybookAction{
			{Suggest: models.ValidateAuthBoundary},
		},
	}

	matcher := NewMatcher([]Playbook{pb})

	event := engine.GraphEvent{
		ID:        "ev1",
		Type:      "RESPONSE_OBSERVED",
		NodeID:    "n1",
		Evidence:  engine.DiscoveryEvidence{},
		Timestamp: time.Now(),
	}

	ctx := MatchContext{
		ExistingSuggestions: make(map[string]bool),
		CurrentSnapshotHash: "hash123",
	}

	suggestions := matcher.Evaluate(event, ctx)

	if len(suggestions) != 1 {
		t.Fatalf("Matcher failed to trigger on valid event. Got %d suggestions", len(suggestions))
	}

	if suggestions[0].TriggerEventID != "ev1" {
		t.Fatalf("Suggestion lost evidence linking to trigger event")
	}

	if suggestions[0].SuggestedValidation != models.ValidateAuthBoundary {
		t.Fatalf("Matcher produced wrong suggestion: %v", suggestions[0].SuggestedValidation)
	}
}
