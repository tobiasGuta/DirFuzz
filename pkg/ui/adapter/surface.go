package adapter

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui/models"
	"fmt"
)

type SurfaceAdapter struct{}

func NewSurfaceAdapter() *SurfaceAdapter {
	return &SurfaceAdapter{}
}

func (a *SurfaceAdapter) Project(snapshot engine.AnalystSnapshot) *models.SurfaceIndex {
	idx := &models.SurfaceIndex{
		Nodes:       make(map[string]*models.SurfaceNode),
		SearchIndex: make(map[string][]string),
	}

	// This is a minimal mock projection since the engine tree is quite complex.
	// In the real system, it would iterate over snapshot metrics or findings 
	// and aggregate them bottoms-up.
	
	targetNode := &models.SurfaceNode{
		ID:          "root",
		Name:        "target.com",
		Kind:        models.SurfaceTarget,
		ChildIDs:    []string{},
		RiskSummary: models.RiskSummary{},
	}
	idx.Nodes["root"] = targetNode

	// Mocking an endpoint
	endpointID := "api-users"
	endpointNode := &models.SurfaceNode{
		ID:   endpointID,
		Name: "/api/users/{id}",
		Kind: models.SurfaceEndpoint,
	}
	idx.Nodes[endpointID] = endpointNode
	targetNode.ChildIDs = append(targetNode.ChildIDs, endpointID)

	// Mock search token aggregation
	idx.SearchIndex["target"] = append(idx.SearchIndex["target"], "root")
	idx.SearchIndex["api"] = append(idx.SearchIndex["api"], endpointID)
	
	// Mock a finding
	if snapshot.Metrics.FindingsCreated > 0 {
		findingID := fmt.Sprintf("finding-%d", snapshot.Version)
		findingNode := &models.SurfaceNode{
			ID:   findingID,
			Name: "IDOR",
			Kind: models.SurfaceFinding,
		}
		
		idx.Nodes[findingID] = findingNode
		endpointNode.ChildIDs = append(endpointNode.ChildIDs, findingID)
		
		endpointNode.RiskSummary.High++
		targetNode.RiskSummary.High++
		
		idx.SearchIndex["idor"] = append(idx.SearchIndex["idor"], findingID)
	}

	return idx
}
