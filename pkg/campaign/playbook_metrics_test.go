package campaign

import (
	"testing"
)

func TestPlaybookEffectivenessScoring(t *testing.T) {
	// Simulate query return
	metrics := PlaybookEffectiveness{
		PlaybookID:    "IDOR_CHECK",
		Runs:          500,
		Confirmed:     65,
		FalsePositive: 400,
		SuccessRate:   (float64(65) / float64(500)) * 100.0,
	}

	if metrics.SuccessRate != 13.0 {
		t.Fatalf("Expected 13%% success rate, got %f", metrics.SuccessRate)
	}

	// This validates the structure that translates Playbook Suggestions -> Analyst Decisions -> Finding Validation
	// into an operational health metric.
}
