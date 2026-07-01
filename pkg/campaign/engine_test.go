package campaign

import (
	"testing"
)

func TestDifferentialDeterminism(t *testing.T) {
	snapOld := CampaignSnapshot{
		ID: "snap1",
		Nodes: map[string]EvidenceProjection{
			"n1": {Path: "/api/users", RiskScore: 10},
			"n2": {Path: "/admin", RiskScore: 50},
			"n3": {Path: "/debug", RiskScore: 100},
		},
	}

	snapNew := CampaignSnapshot{
		ID: "snap2",
		Nodes: map[string]EvidenceProjection{
			"n1": {Path: "/api/users", RiskScore: 10}, // Unchanged
			"n2": {Path: "/admin", RiskScore: 20},     // Changed
			"n4": {Path: "/graphql", RiskScore: 5},    // New
			// n3 is Removed
		},
	}

	engine := &DefaultDiffEngine{}

	// Must be deterministic across multiple runs
	diffA := engine.Compare(snapOld, snapNew)
	diffB := engine.Compare(snapOld, snapNew)

	if diffA.TotalNew != diffB.TotalNew || diffA.TotalNew != 1 {
		t.Fatalf("Differential NEW count failed")
	}

	if diffA.TotalChange != diffB.TotalChange || diffA.TotalChange != 1 {
		t.Fatalf("Differential CHANGED count failed")
	}

	if diffA.TotalRemove != diffB.TotalRemove || diffA.TotalRemove != 1 {
		t.Fatalf("Differential REMOVED count failed")
	}

	if len(diffA.Endpoints) != 3 {
		t.Fatalf("Expected exactly 3 endpoint diffs")
	}
}
