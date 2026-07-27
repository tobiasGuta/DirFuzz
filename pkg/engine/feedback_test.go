package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
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

func TestFeedbackLoopSubmissionIsTrackedByWait(t *testing.T) {
	eng := NewEngine(1, 100, 0.01)
	atomic.StoreInt64(&eng.RunID, 42)

	nodeID, _ := eng.DiscoveryGraph.AddPathNode(
		"",
		"/secret",
		"secret",
		"response",
		DiscoveryEvidence{},
	)
	eng.processFeedbackLoop(Result{
		DiscoveryNodeID: nodeID,
		StatusCode:      403,
		ContentType:     "text/html",
		Size:            500,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	job, ok, err := eng.jobs.Pop(ctx)
	if err != nil || !ok {
		eng.Shutdown()
		t.Fatalf("feedback job was not queued: ok=%t err=%v", ok, err)
	}

	waitStarted := make(chan struct{})
	waitDone := make(chan struct{})
	go func() {
		close(waitStarted)
		eng.Wait()
		close(waitDone)
	}()
	<-waitStarted

	tracked := true
	select {
	case <-waitDone:
		tracked = false
	case <-time.After(50 * time.Millisecond):
	}
	if tracked {
		eng.activeJobs.Done()
		<-waitDone
	}
	eng.Shutdown()

	if !tracked {
		t.Fatal("Wait returned while the feedback job was still active")
	}
	if job.RunID != 42 {
		t.Fatalf("feedback job RunID = %d, want current RunID 42", job.RunID)
	}
	if job.Type != JobTypeValidation {
		t.Fatalf("feedback job Type = %q, want %q", job.Type, JobTypeValidation)
	}
	if job.Path != "/secret" {
		t.Fatalf("feedback job Path = %q, want /secret", job.Path)
	}
	if job.DiscoveryNodeID != nodeID {
		t.Fatalf("feedback job DiscoveryNodeID = %q, want %q", job.DiscoveryNodeID, nodeID)
	}
	if job.PriorityScore != 85 {
		t.Fatalf("feedback job PriorityScore = %d, want 85", job.PriorityScore)
	}
	if job.Reason != ReasonFeedback {
		t.Fatalf("feedback job Reason = %q, want %q", job.Reason, ReasonFeedback)
	}
	if job.CreatedAt.IsZero() {
		t.Fatal("feedback job CreatedAt was not set")
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
