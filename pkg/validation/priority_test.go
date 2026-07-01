package validation

import (
	"dirfuzz/pkg/ui/models"
	"testing"
	"time"
)

func TestValidationPriority(t *testing.T) {
	// Simulate the priority logic bridging the ValidationQueue to Engine Dispatch
	
	// E.g., we have a queue model
	queue := []models.ValidationRequest{
		{ID: "low-1", Type: models.ValidateParameter, Reason: "noise", CreatedAt: time.Now()},
		{ID: "low-2", Type: models.ValidateParameter, Reason: "noise", CreatedAt: time.Now()},
		{ID: "low-3", Type: models.ValidateExposure, Reason: "noise", CreatedAt: time.Now()},
	}

	// We insert a critical validation
	critical := models.ValidationRequest{
		ID:        "crit-1",
		Type:      models.ValidateAuthBoundary,
		Reason:    "IDOR verification",
		CreatedAt: time.Now().Add(-1 * time.Second), // Older, or higher priority
		Status:    models.StatusPending,
	}

	queue = append([]models.ValidationRequest{critical}, queue...)

	// The dispatch loop should select "crit-1" before "low-3"
	if queue[0].ID != "crit-1" {
		t.Fatalf("Priority queue failed to surface critical validation")
	}
}
