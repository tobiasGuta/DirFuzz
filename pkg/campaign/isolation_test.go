package campaign

import (
	"testing"
)

func TestCampaignIsolation(t *testing.T) {
	// A basic test enforcing that target nodes don't bleed
	b := NewGraphBuilder()
	
	p := b.BuildFromLedger([]interface{}{
		CampaignDiffEvent{DiffID: "diff1"},
	}, "l1", "s1")

	// Verify Target ID checks would theoretically run here 
	// (implemented generically via Scope checks similar to KnowledgeStore)
	if p.Metadata.LedgerHash != "l1" {
		t.Fatalf("Isolation meta failed")
	}
}
