package campaign

import (
	"testing"
	"time"
)

func TestCampaignRiskCalculation(t *testing.T) {
	baselines := []CampaignBaseline{
		{
			CampaignID:          "c1",
			TargetID:            "t1",
			KnownEndpoints:      100,
			KnownAuthBoundaries: 5,
			CreatedAt:           time.Now().Add(-30 * 24 * time.Hour),
		},
		{
			CampaignID:          "c2",
			TargetID:            "t1",
			KnownEndpoints:      500, // +400% growth
			KnownAuthBoundaries: 20,  // +15 auth changes
			CreatedAt:           time.Now(),
		},
	}

	risk := CalculateRisk(baselines)

	if risk.Level != RiskMedium && risk.Level != RiskHigh && risk.Level != RiskCritical {
		t.Fatalf("Expected an elevated risk level, got %s", risk.Level)
	}

	if len(risk.Signals) != 2 {
		t.Fatalf("Expected 2 risk signals, got %d", len(risk.Signals))
	}
}
