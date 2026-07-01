package campaign

import (
	"testing"
)

func TestGraphRebuildFromLedger(t *testing.T) {
	b := NewGraphBuilder()

	events := []interface{}{
		RegressionEvent{ID: "reg1", FindingID: "f1", Type: RegressionAuth},
	}

	p := b.BuildFromLedger(events, "ledger1", "snap1")

	node, exists := p.Nodes["reg1"]
	if !exists {
		t.Fatalf("Failed to rebuild node from ledger")
	}

	if node.Type != NodeFinding {
		t.Fatalf("Incorrect node type")
	}

	if len(p.Edges) != 1 || p.Edges[0].Relation != RelRegressedTo {
		t.Fatalf("Failed to rebuild edge from ledger")
	}
}
