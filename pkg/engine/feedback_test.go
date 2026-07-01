package engine

import (
	"testing"
)

func TestResultToEvidenceConversion(t *testing.T) {
	extractor := DefaultEvidenceExtractor{}
	res := Result{
		StatusCode:        403,
		Size:              1234,
		ContentType:       "text/html",
		MarkedInteresting: true,
	}

	ev := extractor.Extract(res)
	if ev.StatusCode != 403 || ev.Length != 1234 || ev.ContentType != "text/html" || !ev.Interesting {
		t.Fatalf("Extractor failed to map fields correctly: %+v", ev)
	}
}

func TestUpdateEvidenceCreatesAction(t *testing.T) {
	g := NewDiscoveryGraph()
	nodeID, _ := g.AddPathNode("", "/secret", "secret", "response", DiscoveryEvidence{})

	// Node starts with 0 feedback actions
	if g.Nodes[nodeID].FeedbackJobsCount != 0 {
		t.Fatalf("Expected 0 feedback jobs initially")
	}

	// 403 should create a validation action
	resp := ResponseEvidence{
		StatusCode:  403,
		ContentType: "text/html",
		Length:      500,
	}

	actions := g.UpdateEvidence(nodeID, resp)
	if len(actions) != 1 {
		t.Fatalf("Expected 1 validation action, got %d", len(actions))
	}

	if actions[0].Type != "validation" {
		t.Fatalf("Expected validation action, got %s", actions[0].Type)
	}
	if actions[0].Origin != GraphEventResponseObserved {
		t.Fatalf("Expected origin ResponseObserved, got %s", actions[0].Origin)
	}
	if g.Nodes[nodeID].FeedbackJobsCount != 1 {
		t.Fatalf("Expected feedback job count to increment")
	}
}

func TestFeedbackLoopDeduplication(t *testing.T) {
	g := NewDiscoveryGraph()
	nodeID, _ := g.AddPathNode("", "/secret", "secret", "response", DiscoveryEvidence{})

	resp := ResponseEvidence{
		StatusCode:  403,
		ContentType: "text/html",
		Length:      500,
	}

	// First evaluation should emit 1 action
	actions1 := g.UpdateEvidence(nodeID, resp)
	if len(actions1) != 1 {
		t.Fatalf("Expected 1 action on first evaluation")
	}

	// Immediate duplicate evaluation should emit 0 actions due to hash tracking
	actions2 := g.UpdateEvidence(nodeID, resp)
	if len(actions2) != 0 {
		t.Fatalf("Expected 0 actions on identical duplicate evaluation")
	}
}

func Test403ValidationDoesNotSelfAmplify(t *testing.T) {
	g := NewDiscoveryGraph()
	nodeID, _ := g.AddPathNode("", "/secret", "secret", "response", DiscoveryEvidence{})

	resp := ResponseEvidence{
		StatusCode:  403,
		ContentType: "text/html",
		Length:      500,
	}

	// Simulation of loop:
	// 1. Initial 403 triggers Validation job
	actions := g.UpdateEvidence(nodeID, resp)
	if len(actions) != 1 {
		t.Fatalf("Expected 1 initial action")
	}

	// Simulate some other response to bypass hash lock
	respDiff := ResponseEvidence{StatusCode: 500}
	g.UpdateEvidence(nodeID, respDiff)

	// 2. Validation job executes and hits 403 AGAIN
	actions2 := g.UpdateEvidence(nodeID, resp)
	if len(actions2) != 0 {
		t.Fatalf("Expected 0 new actions, deduplication against ActionHistory failed!")
	}
}

func Test404ConfidenceDecay(t *testing.T) {
	g := NewDiscoveryGraph()
	nodeID, _ := g.AddPathNode("", "/admin", "admin", "response", DiscoveryEvidence{})
	
	node := g.Nodes[nodeID]
	node.Confidence = 100
	node.RiskScore = 90

	resp := ResponseEvidence{
		StatusCode: 404,
	}

	g.UpdateEvidence(nodeID, resp)

	if node.Confidence >= 100 {
		t.Fatalf("Expected confidence to drop on 404")
	}
	if node.RiskScore != 90 {
		t.Fatalf("Expected RiskScore to be maintained on 404, went to %d", node.RiskScore)
	}
}
