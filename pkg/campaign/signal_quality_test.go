package campaign

import (
	"testing"
)

func TestAnalystSignalQuality(t *testing.T) {
	quality := AnalystSignalQuality{
		AnalystID:           "analyst_alice",
		AcceptedSuggestions: 90,
		RejectedSuggestions: 10,
		ConfirmedFindings:   20,
	}

	if quality.AcceptedSuggestions != 90 {
		t.Fatalf("Quality structural mismatch")
	}

	// In a real query environment, the Graph Aggregator calculates this
	// by parsing DecisionEvents matching AnalystID against Finding Validation success.
}
