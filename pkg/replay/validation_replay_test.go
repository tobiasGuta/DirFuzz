package replay

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui/models"
	"testing"
	"time"
)

func TestValidationReplay(t *testing.T) {
	// A causal chain modeling validation integration in the replay timeline
	
	events := []engine.GraphEvent{
		{Type: "DISCOVERY", NodeID: "n1", Timestamp: time.Now()},
		{Type: engine.GraphEventType(models.ValidationRequested), NodeID: "n1", Timestamp: time.Now()},
		{Type: engine.GraphEventType(models.ValidationStarted), NodeID: "n1", Timestamp: time.Now()},
		{Type: engine.GraphEventType(models.ValidationObserved), NodeID: "n1", Timestamp: time.Now()},
		{Type: "FINDING", NodeID: "n1", Timestamp: time.Now()},
	}

	source := &mockReplaySource{events: events}
	replayer := NewReplayer(source)

	// Replay BEFORE validation started
	snapBefore, _ := replayer.SnapshotAt(1) // Up to ValidationRequested
	if snapBefore.Metrics.FindingsCreated > 0 {
		t.Fatalf("Replay violated causality: exposed finding before validation executed")
	}

	// Replay AFTER validation completed
	snapAfter, _ := replayer.SnapshotAt(5) // Includes all events
	if snapAfter.Metrics.FindingsCreated == 0 {
		t.Fatalf("Replay failed to integrate validation completion into snapshot")
	}
}
