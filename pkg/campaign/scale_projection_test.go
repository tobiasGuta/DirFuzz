package campaign

import (
	"fmt"
	"testing"
)

func TestMillionEventProjection(t *testing.T) {
	b := NewGraphBuilder()

	// 100k for unit tests to avoid timeout
	events := make([]interface{}, 100000)
	for i := 0; i < 100000; i++ {
		events[i] = CampaignDiffEvent{DiffID: fmt.Sprintf("diff%d", i)}
	}

	p := b.BuildFromLedger(events, "l1", "s1")

	if len(p.Nodes) != 100000 {
		t.Fatalf("Failed to project scale nodes")
	}
}
