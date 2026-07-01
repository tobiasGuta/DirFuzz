package engine

import (
	"testing"
	"time"
)

func TestNegativeKnowledgeTTL(t *testing.T) {
	g := NewDiscoveryGraph()

	path := "/api/v1/missing"
	method := "GET"
	ttl := 50 * time.Millisecond

	// Record a 404
	g.RecordNegativeEvidence(path, method, 404, ttl)

	// Should be blocked immediately
	if !g.IsNegativeCached(path, method) {
		t.Fatalf("Expected %s to be negative cached", path)
	}

	// Different method shouldn't be blocked
	if g.IsNegativeCached(path, "POST") {
		t.Fatalf("Expected POST %s to NOT be negative cached", path)
	}

	// Wait for TTL expiration
	time.Sleep(100 * time.Millisecond)

	if g.IsNegativeCached(path, method) {
		t.Fatalf("Expected TTL to expire and cache to be clear")
	}
}

func TestCircuitBreakerClasses(t *testing.T) {
	g := NewDiscoveryGraph()
	nodeID, _ := g.AddSourceNode("API", "openapi")

	node := g.Nodes[nodeID]
	node.CircuitBreaker.Cooldown = 100 * time.Millisecond

	// Trip timeout breaker
	g.UpdateCircuitBreaker(nodeID, "timeout")
	g.UpdateCircuitBreaker(nodeID, "timeout")
	g.UpdateCircuitBreaker(nodeID, "timeout")

	if node.CircuitBreaker.State != CircuitOpen {
		t.Fatalf("Expected circuit breaker to be open")
	}

	if !g.IsNodeBlocked(nodeID) {
		t.Fatalf("Expected node to be blocked while circuit is open")
	}

	// Wait for cooldown
	time.Sleep(150 * time.Millisecond)

	// Now it shouldn't be blocked, so we can try again (HalfOpen state testing)
	if g.IsNodeBlocked(nodeID) {
		t.Fatalf("Expected node to be unblocked after cooldown")
	}

	// Successful request recovers the breaker
	node.CircuitBreaker.State = CircuitHalfOpen // Simulating the worker trying again
	g.UpdateCircuitBreaker(nodeID, "success")

	if node.CircuitBreaker.State != CircuitClosed {
		t.Fatalf("Expected circuit breaker to close after success")
	}
	if node.CircuitBreaker.ConsecutiveTO != 0 {
		t.Fatalf("Expected timeout counter to reset")
	}
}

func TestScanBudgetCap(t *testing.T) {
	g := NewDiscoveryGraph()
	nodeID, _ := g.AddSourceNode("API", "openapi")

	node := g.Nodes[nodeID]
	node.Budget.MaxRequests = 50

	if g.IsNodeBlocked(nodeID) {
		t.Fatalf("Expected node to be unblocked initially")
	}

	node.Budget.RequestsUsed = 50

	if !g.IsNodeBlocked(nodeID) {
		t.Fatalf("Expected node to be blocked due to scan budget")
	}
}

func TestGraphValidationChecker(t *testing.T) {
	g := NewDiscoveryGraph()
	idA, _ := g.AddSourceNode("A", "openapi")
	idB, _ := g.AddPathNode(idA, "/b", "B", "openapi", DiscoveryEvidence{})
	idC, _ := g.AddPathNode(idB, "/c", "C", "openapi", DiscoveryEvidence{})

	if err := g.ValidateGraph(); err != nil {
		t.Fatalf("Expected valid graph, got: %v", err)
	}

	// Introduce a score corruption
	g.Nodes[idC].Confidence = 200
	if err := g.ValidateGraph(); err == nil {
		t.Fatalf("Expected error for invalid confidence")
	}
	g.Nodes[idC].Confidence = 100 // fix it

	// Introduce a cycle A -> B -> C -> A
	g.Nodes[idC].Children[idA] = struct{}{}
	
	if err := g.ValidateGraph(); err == nil {
		t.Fatalf("Expected error for topology cycle")
	}
}
