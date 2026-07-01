package campaign


type GraphBuilder struct {
	projection *CampaignIntelligenceProjection
}

func NewGraphBuilder() *GraphBuilder {
	return &GraphBuilder{
		projection: &CampaignIntelligenceProjection{
			Nodes: make(map[string]*IntelligenceNode),
			Edges: make([]IntelligenceEdge, 0),
		},
	}
}

// BuildFromLedger mock implementation: in reality this parses chronological events
func (b *GraphBuilder) BuildFromLedger(events []interface{}, ledgerHash string, snapshotHash string) *CampaignIntelligenceProjection {
	b.projection.Metadata = CampaignGraphMetadata{
		LedgerHash:   ledgerHash,
		SnapshotHash: snapshotHash,
		Version:      1,
	}

	for _, event := range events {
		switch e := event.(type) {
		case CampaignDiffEvent:
			b.addNode(e.DiffID, NodeCampaign, e)
		case RegressionEvent:
			b.addNode(e.ID, NodeFinding, e)
			b.addEdge(e.FindingID, e.ID, RelRegressedTo)
		}
	}

	return b.projection
}

func (b *GraphBuilder) addNode(id string, nodeType KnowledgeNodeType, data interface{}) {
	b.projection.Nodes[id] = &IntelligenceNode{
		ID:   id,
		Type: nodeType,
		Data: data,
	}
}

func (b *GraphBuilder) addEdge(source string, target string, rel EdgeRelation) {
	b.projection.Edges = append(b.projection.Edges, IntelligenceEdge{
		SourceID: source,
		TargetID: target,
		Relation: rel,
	})
}
