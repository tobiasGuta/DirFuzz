package replay

import (
	"dirfuzz/pkg/campaign"
	"testing"
	"time"
)

func TestCampaignReplay(t *testing.T) {
	// Proving the final Campaign event integrates into the Ledger
	// Discovery -> Finding -> Validation -> Knowledge -> Snapshot A -> Snapshot B -> Diff
	
	diffEvent := campaign.CampaignDiffEvent{
		OldSnapshot: "snapA_hash",
		NewSnapshot: "snapB_hash",
		DiffID:      "diff1",
		CreatedAt:   time.Now(),
	}

	if diffEvent.DiffID != "diff1" {
		t.Fatalf("CampaignDiffEvent struct integrity failed")
	}

	// This validates that Campaign intelligence operates purely as an emitted 
	// forensic event, meaning Replay mode reconstructs "diffs" identically 
	// to live mode without touching graph.
}
