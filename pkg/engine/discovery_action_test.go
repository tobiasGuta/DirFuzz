package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestActionDeduplication(t *testing.T) {
	g := NewDiscoveryGraph()
	// Add an OpenAPI node that triggers a ParamFuzz action
	nodeID, actions1 := g.AddPathNode("", "/api/v1/users/{id}", "/api/v1/users/{id}", "openapi", DiscoveryEvidence{})
	
	if len(actions1) != 1 {
		t.Fatalf("expected 1 action on first discovery, got %d", len(actions1))
	}
	if actions1[0].Type != string(JobTypeParamFuzz) {
		t.Fatalf("expected paramfuzz action, got %s", actions1[0].Type)
	}

	// Re-add the exact same node (e.g. rediscovered from another source map)
	existingID, actions2 := g.AddPathNode("", "/api/v1/users/{id}", "/api/v1/users/{id}", "openapi", DiscoveryEvidence{})
	
	if existingID != nodeID {
		t.Fatalf("expected existing node ID %s, got %s", nodeID, existingID)
	}
	if len(actions2) != 0 {
		t.Fatalf("expected 0 actions on rediscovery due to deduplication, got %d", len(actions2))
	}
}

func TestDerivedJobLimit(t *testing.T) {
	g := NewDiscoveryGraph()
	
	nodeID, _ := g.AddSourceNode("limit-test", "custom")
	node := g.Nodes[nodeID]
	
	// Manually inject fake actions to history
	for i := 0; i < MaxDerivedJobsPerNode; i++ {
		key := makeActionKey(node.ID, "fake-action-type")
		g.ActionHistory[key] = struct{}{}
		node.DerivedJobsCount++
	}
	
	// Now try to add a JS admin route that would normally trigger validation
	node.CanonicalPath = "/admin"
	node.SourceType = "javascript"
	
	actions := g.EvaluateNode(node)
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions because MaxDerivedJobsPerNode is reached, got %d", len(actions))
	}
}

func TestActionPersistence(t *testing.T) {
	g1 := NewDiscoveryGraph()
	_, actions := g1.AddPathNode("", "/admin/dashboard", "/admin/dashboard", "javascript", DiscoveryEvidence{})
	if len(actions) == 0 {
		t.Fatalf("expected actions on js admin route")
	}

	// Mark execution state
	actionID := actions[0].ID
	exec := g1.ActionExecutions[actionID]
	exec.Status = ActionCompleted
	g1.ActionExecutions[actionID] = exec

	// Serialize
	data, err := json.Marshal(g1)
	if err != nil {
		t.Fatalf("failed to marshal graph: %v", err)
	}

	g2 := NewDiscoveryGraph()
	if err := json.Unmarshal(data, &g2); err != nil {
		t.Fatalf("failed to unmarshal graph: %v", err)
	}

	if len(g2.ActionHistory) != len(g1.ActionHistory) {
		t.Fatalf("expected %d items in action history, got %d", len(g1.ActionHistory), len(g2.ActionHistory))
	}
	if g2.ActionExecutions[actionID].Status != ActionCompleted {
		t.Fatalf("expected restored action status to be completed")
	}
}

func TestActionRetryAfterFailure(t *testing.T) {
	g := NewDiscoveryGraph()
	nodeID, actions := g.AddPathNode("", "/api/v1/users/{id}", "/api/v1/users/{id}", "openapi", DiscoveryEvidence{})
	if len(actions) != 1 {
		t.Fatalf("expected 1 action")
	}

	// Mark as failed
	actionID := actions[0].ID
	exec := g.ActionExecutions[actionID]
	exec.Status = ActionFailed
	g.ActionExecutions[actionID] = exec

	// Since the action is stored in ActionExecutions, the failure state doesn't block re-generation
	// However, ActionHistory uses deduplication by type to prevent explosion.
	// If the engine intentionally wanted to bypass ActionHistory deduplication for retries, 
	// it would delete the key from ActionHistory. Let's simulate a retry bypass:
	key := makeActionKey(nodeID, "paramfuzz")
	delete(g.ActionHistory, key)
	g.Nodes[nodeID].DerivedJobsCount--

	actionsRetry := g.EvaluateNode(g.Nodes[nodeID])
	if len(actionsRetry) != 1 {
		t.Fatalf("expected 1 action on retry, got %d", len(actionsRetry))
	}
}

func TestEventDeduplication(t *testing.T) {
	g := NewDiscoveryGraph()
	eventID := "dedup-123"
	e1 := GraphEvent{ID: eventID, Type: GraphEventNodeAdded, NodeID: "n1", Timestamp: time.Now()}
	e2 := GraphEvent{ID: eventID, Type: GraphEventNodeAdded, NodeID: "n1", Timestamp: time.Now()}

	g.AddEvent(e1)
	g.AddEvent(e2)

	if len(g.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(g.Events))
	}
}

func TestLargeGraphEventMemoryLimit(t *testing.T) {
	g := NewDiscoveryGraph()

	// Fill events up to max
	for i := 0; i < DefaultMaxEventHistory+100; i++ {
		g.AddEvent(GraphEvent{
			Type:      GraphEventNodeAdded,
			NodeID:    "test-node",
			Timestamp: time.Now(),
		})
	}

	g.RLock()
	defer g.RUnlock()
	if len(g.Events) > DefaultMaxEventHistory {
		t.Fatalf("Expected events to be capped at %d, but got %d", DefaultMaxEventHistory, len(g.Events))
	}
}

func TestSnapshotRestore(t *testing.T) {
	g1 := NewDiscoveryGraph()
	g1.AddSourceNode("source1", "response")

	if len(g1.Events) == 0 {
		t.Fatalf("expected events to be generated")
	}

	data, err := json.Marshal(g1)
	if err != nil {
		t.Fatalf("failed to marshal graph: %v", err)
	}

	g2 := NewDiscoveryGraph()
	if err := json.Unmarshal(data, &g2); err != nil {
		t.Fatalf("failed to unmarshal graph: %v", err)
	}

	if len(g2.Events) != len(g1.Events) {
		t.Fatalf("expected %d events, got %d", len(g1.Events), len(g2.Events))
	}
	if g2.Events[0].ID != g1.Events[0].ID {
		t.Fatalf("event ID mismatch")
	}
}

func TestGraphStateWithoutEventsRestore(t *testing.T) {
	g1 := NewDiscoveryGraph()
	id, _ := g1.AddSourceNode("source1", "response")
	
	// Simulate pruning or clearing events history intentionally
	g1.Events = make([]GraphEvent, 0)
	
	data, err := json.Marshal(g1)
	if err != nil {
		t.Fatalf("failed to marshal graph: %v", err)
	}

	g2 := NewDiscoveryGraph()
	if err := json.Unmarshal(data, &g2); err != nil {
		t.Fatalf("failed to unmarshal graph: %v", err)
	}
	
	// Graph state should still be completely valid and operational
	if len(g2.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(g2.Nodes))
	}
	if _, ok := g2.Nodes[id]; !ok {
		t.Fatalf("missing node %s", id)
	}
}

func TestConfidencePrioritySeparation(t *testing.T) {
	g := NewDiscoveryGraph()
	nodeID, _ := g.AddPathNode("", "/secret", "/secret", "response", DiscoveryEvidence{})
	
	node := g.Nodes[nodeID]
	node.Confidence = 50
	node.PriorityScore = 10
	node.RiskScore = 0

	resp := ResponseEvidence{
		StatusCode:  403,
		ContentType: "text/html",
		Interesting: true,
	}

	g.UpdateEvidence(nodeID, resp)

	if node.Confidence <= 50 {
		t.Fatalf("expected confidence to increase on 403")
	}
	if node.RiskScore <= 0 {
		t.Fatalf("expected risk score to increase heavily on 403")
	}
	
	// A timeout (StatusCode 0) should drop the confidence slightly but not reset risk
	resp2 := ResponseEvidence{StatusCode: 0}
	prevRisk := node.RiskScore
	g.UpdateEvidence(nodeID, resp2)
	
	if node.RiskScore != prevRisk { 
		t.Fatalf("expected risk score to stay stable on timeout")
	}
	
	// A 404 should drop the confidence but not erase risk score
	resp3 := ResponseEvidence{StatusCode: 404}
	g.UpdateEvidence(nodeID, resp3)
	if node.RiskScore != prevRisk {
		t.Fatalf("expected risk score to stay stable on 404")
	}
}

func TestPriorityOrdering(t *testing.T) {
	q := NewPriorityQueue(10)
	
	ctx := context.Background()
	q.Push(ctx, Job{Type: JobTypeFuzz, PriorityScore: 10})
	q.Push(ctx, Job{Type: JobTypeValidation, PriorityScore: 5})
	q.Push(ctx, Job{Type: JobTypeDiscovery, PriorityScore: 50})
	q.Push(ctx, Job{Type: JobTypeParamFuzz, PriorityScore: 20})
	
	// Order should be Validation > ParamFuzz > Discovery > Fuzz
	
	j1, _, _ := q.Pop(ctx)
	if j1.Type != JobTypeValidation {
		t.Fatalf("expected 1st job Validation, got %s", j1.Type)
	}
	
	j2, _, _ := q.Pop(ctx)
	if j2.Type != JobTypeParamFuzz {
		t.Fatalf("expected 2nd job ParamFuzz, got %s", j2.Type)
	}
	
	j3, _, _ := q.Pop(ctx)
	if j3.Type != JobTypeDiscovery {
		t.Fatalf("expected 3rd job Discovery, got %s", j3.Type)
	}
	
	j4, _, _ := q.Pop(ctx)
	if j4.Type != JobTypeFuzz {
		t.Fatalf("expected 4th job Fuzz, got %s", j4.Type)
	}
}
