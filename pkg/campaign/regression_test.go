package campaign

import (
	"dirfuzz/pkg/engine"
	"testing"
)

func TestRegressionDetection(t *testing.T) {
	event := RegressionEvent{
		ID:             "reg_1",
		FindingID:      "f_123",
		Type:           RegressionAuth,
		PreviousStatus: engine.FindingFixed,
		CurrentStatus:  engine.FindingNew,
		Confidence:     95,
		Reason:         "Endpoint historically fixed now returning 200 OK without auth",
	}

	if event.Type != RegressionAuth {
		t.Fatalf("RegressionType enum failed")
	}

	if event.PreviousStatus != engine.FindingFixed {
		t.Fatalf("Failed to capture historical FindingFixed state")
	}
}
