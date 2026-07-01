package campaign

import (
	"fmt"
	"testing"
)

func TestDifferentialMillionNodeScale(t *testing.T) {
	nodeCount := 100000

	snapOld := CampaignSnapshot{
		ID:    "old",
		Nodes: make(map[string]EvidenceProjection, nodeCount),
	}
	snapNew := CampaignSnapshot{
		ID:    "new",
		Nodes: make(map[string]EvidenceProjection, nodeCount),
	}

	for i := 0; i < nodeCount; i++ {
		id := fmt.Sprintf("n%d", i)
		snapOld.Nodes[id] = EvidenceProjection{Path: "/path", RiskScore: 10}
		snapNew.Nodes[id] = EvidenceProjection{Path: "/path", RiskScore: 10}
	}

	// Mutate 100 of them
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("n%d", i)
		node := snapNew.Nodes[id]
		node.RiskScore = 99
		snapNew.Nodes[id] = node
	}

	engine := &DefaultDiffEngine{}

	diff := engine.Compare(snapOld, snapNew)

	if diff.TotalChange != 100 {
		t.Fatalf("Expected 100 changes, got %d", diff.TotalChange)
	}
	if diff.TotalNew != 0 || diff.TotalRemove != 0 {
		t.Fatalf("Expected exactly 0 new/removed")
	}
}
