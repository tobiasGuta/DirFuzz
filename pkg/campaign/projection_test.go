package campaign

import (
	"testing"
)

func TestProjectionDeterminism(t *testing.T) {
	b1 := NewGraphBuilder()
	b2 := NewGraphBuilder()

	events := []interface{}{
		CampaignDiffEvent{DiffID: "d1"},
	}

	p1 := b1.BuildFromLedger(events, "hash_ledger_abc", "hash_snap_xyz")
	p2 := b2.BuildFromLedger(events, "hash_ledger_abc", "hash_snap_xyz")

	if p1.Metadata.LedgerHash != p2.Metadata.LedgerHash {
		t.Fatalf("LedgerHash mismatch")
	}

	if len(p1.Nodes) != len(p2.Nodes) {
		t.Fatalf("Node count mismatch")
	}
}
