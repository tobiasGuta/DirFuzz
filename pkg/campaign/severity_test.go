package campaign

import (
	"testing"
)

func TestDiffSeverityLogic(t *testing.T) {
	// Mutate status from 403 to 200 => expect Critical (diff > 50 in our mock score)
	oldProj := EvidenceProjection{Path: "/api", RiskScore: 10} // 403
	newProj := EvidenceProjection{Path: "/api", RiskScore: 80} // 200

	_, sev := detectChanges(oldProj, newProj)
	if sev != DiffCritical {
		t.Fatalf("Expected severity %s, got %s", DiffCritical, sev)
	}

	// Minor mutation
	oldProjMinor := EvidenceProjection{Path: "/api", RiskScore: 10}
	newProjMinor := EvidenceProjection{Path: "/api", RiskScore: 15}

	_, sevMinor := detectChanges(oldProjMinor, newProjMinor)
	if sevMinor != DiffInteresting {
		t.Fatalf("Expected severity %s, got %s", DiffInteresting, sevMinor)
	}
}
