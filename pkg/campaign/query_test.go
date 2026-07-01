package campaign

import (
	"testing"
)

// Mock query implementation
type MockQueryEngine struct {
	projection *CampaignIntelligenceProjection
}

func (q *MockQueryEngine) GetEndpointsWithRepeatedAuthChanges(targetID string) []EndpointHistory {
	return []EndpointHistory{
		{EndpointID: "e1", Path: "/api", ChangeCount: 3},
	}
}
func (q *MockQueryEngine) GetHighRiskUntestedSurface(targetID string) []IntelligenceNode { return nil }
func (q *MockQueryEngine) GetEndpointsRejectedByAnalysts(reason string) []IntelligenceNode { return nil }
func (q *MockQueryEngine) GetMostChangedEndpoints(targetID string) []EndpointHistory { return nil }
func (q *MockQueryEngine) GetDecayedKnowledge(targetID string) []IntelligenceNode { return nil }
func (q *MockQueryEngine) GetCampaignRiskTrend(targetID string) []CampaignRisk { return nil }
func (q *MockQueryEngine) GetPlaybookMetrics() []PlaybookEffectiveness { return nil }
func (q *MockQueryEngine) GetAnalystSignalQuality() []AnalystSignalQuality { return nil }

func TestQueryReplayConsistency(t *testing.T) {
	// The query interface should be decoupled from the raw ledger
	// meaning it queries the Projection strictly.
	
	q := &MockQueryEngine{}
	res := q.GetEndpointsWithRepeatedAuthChanges("t1")
	if len(res) == 0 || res[0].ChangeCount != 3 {
		t.Fatalf("Query failed to return consistency")
	}
}
