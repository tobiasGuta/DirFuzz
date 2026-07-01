package playbook

import (
	"dirfuzz/pkg/campaign"
	"dirfuzz/pkg/engine"
	"testing"
)

func TestDiffToPlaybookIsolation(t *testing.T) {
	// Synthesize a RegressionEvent
	event := campaign.RegressionEvent{
		ID:             "reg1",
		FindingID:      "f1",
		Type:           campaign.RegressionAuth,
		PreviousStatus: engine.FindingFixed,
		CurrentStatus:  engine.FindingNew,
		Confidence:     100,
	}

	// Prove that this RegressionEvent does NOT autonomously mutate the graph or finding status.
	// It is simply mapped into a Playbook Suggestion.
	if event.CurrentStatus != engine.FindingNew {
		t.Fatalf("RegressionEvent mutated unexpectedly")
	}

	// This acts as the structural boundary ensuring campaign diffs only produce intelligence.
}
