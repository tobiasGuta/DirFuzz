package knowledge

import (
	"dirfuzz/pkg/campaign"
	"testing"
	"time"
)

func TestDiffMemoryLogic(t *testing.T) {
	store := NewMemoryStore()

	fp := campaign.DiffFingerprint{
		TargetID:  "t1",
		ScopeHash: "scope1",
		OldHash:   "old1",
		NewHash:   "new1",
		DiffHash:  "diff_abc",
	}

	mem := DiffMemory{
		Fingerprint:   fp.DiffHash,
		SeenCount:     1,
		LastSeen:      time.Now(),
		AnalystAction: "REJECTED",
	}

	err := store.RecordDiffMemory(mem)
	if err != nil {
		t.Fatalf("Failed to record diff memory")
	}

	retrieved, ok := store.LookupDiffMemory(fp.DiffHash)
	if !ok {
		t.Fatalf("Failed to lookup diff memory")
	}

	if retrieved.AnalystAction != "REJECTED" {
		t.Fatalf("Diff memory action mismatch")
	}

	// This validates that if a future differential scan produces `diff_abc`
	// the engine can immediately flag it as a historically rejected regression candidate.
}
