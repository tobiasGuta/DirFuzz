package campaign

import (
	"testing"
)

func TestDiffFingerprintDeterminism(t *testing.T) {
	snapOld := CampaignSnapshot{
		ID:       "snap1",
		TargetID: "t1",
		Nodes: map[string]EvidenceProjection{
			"n1": {Path: "/api/users", RiskScore: 10},
		},
	}

	snapNew := CampaignSnapshot{
		ID:       "snap2",
		TargetID: "t1",
		Nodes: map[string]EvidenceProjection{
			"n1": {Path: "/api/users", RiskScore: 20}, // Changed
		},
	}

	engine := &DefaultDiffEngine{}

	diffA := engine.Compare(snapOld, snapNew)
	diffB := engine.Compare(snapOld, snapNew)

	if diffA.Endpoints[0].Fingerprint.DiffHash != diffB.Endpoints[0].Fingerprint.DiffHash {
		t.Fatalf("DiffHash is not deterministic: %s != %s", diffA.Endpoints[0].Fingerprint.DiffHash, diffB.Endpoints[0].Fingerprint.DiffHash)
	}
	if diffA.Endpoints[0].Fingerprint.TargetID != "t1" {
		t.Fatalf("Fingerprint TargetID not mapped")
	}
}
