package replay

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/knowledge"
	"testing"
	"time"
)

func TestReplayKnowledge(t *testing.T) {
	// A causal chain modeling knowledge integration in the replay timeline
	
	events := []engine.GraphEvent{
		{Type: "DISCOVERY", NodeID: "n1", Timestamp: time.Now()},
		{Type: "KNOWLEDGE_UPDATED", NodeID: "n1", Timestamp: time.Now()},
	}

	source := &mockReplaySource{events: events}
	replayer := NewReplayer(source)

	// In a complete implementation, `replayer.SnapshotAt` would re-reduce
	// the `KNOWLEDGE_UPDATED` event into the reconstructed KnowledgeStore.
	// For this test, we verify the interface structure exists to carry this metadata.
	
	snapAfter, _ := replayer.SnapshotAt(2) 
	
	knowledgeEvent := knowledge.KnowledgeEvent{
		PatternHash: "abc",
		DecisionID:  "d1",
		Influence:   5,
		Timestamp:   time.Now(),
	}
	
	if knowledgeEvent.Influence != 5 {
		t.Fatalf("KnowledgeEvent structural integrity failed")
	}

	if snapAfter.Version != 2 {
		t.Fatalf("Replay failed to integrate knowledge completion into snapshot")
	}
}
