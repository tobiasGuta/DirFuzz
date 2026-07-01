package playbook

import (
	"dirfuzz/pkg/engine"
	"testing"
)

func TestPlaybookSuggestionMemory(t *testing.T) {
	pb := Playbook{
		ID:      "pb1",
		Enabled: true,
		Triggers: []TriggerRule{
			{Event: "RESPONSE_OBSERVED", Condition: map[string]string{"status": "403"}},
		},
	}

	matcher := NewMatcher([]Playbook{pb})
	event := engine.GraphEvent{
		ID:       "ev1",
		Type:     "RESPONSE_OBSERVED",
		Evidence: engine.DiscoveryEvidence{},
	}

	// First pass: UI has already seen it and rejected it
	ctx := MatchContext{
		ExistingSuggestions: map[string]bool{
			"sg-pb1-ev1": true,
		},
	}

	suggestions := matcher.Evaluate(event, ctx)

	if len(suggestions) != 0 {
		t.Fatalf("Matcher failed to respect Analyst memory. Emitted %d redundant suggestions", len(suggestions))
	}
}
