package campaign


type KnowledgeNodeType string

const (
	NodeEndpoint   KnowledgeNodeType = "ENDPOINT"
	NodeFinding    KnowledgeNodeType = "FINDING"
	NodePlaybook   KnowledgeNodeType = "PLAYBOOK"
	NodeAnalyst    KnowledgeNodeType = "ANALYST"
	NodeCampaign   KnowledgeNodeType = "CAMPAIGN"
	NodeSubmission KnowledgeNodeType = "SUBMISSION"
)

type EdgeRelation string

const (
	RelAppearedIn  EdgeRelation = "APPEARED_IN"
	RelCaused      EdgeRelation = "CAUSED"
	RelValidatedBy EdgeRelation = "VALIDATED_BY"
	RelDecidedBy   EdgeRelation = "DECIDED_BY"
	RelRegressedTo EdgeRelation = "REGRESSED_TO"
)

type CampaignGraphMetadata struct {
	LedgerHash   string
	SnapshotHash string
	Version      int
}

type IntelligenceNode struct {
	ID   string
	Type KnowledgeNodeType
	Data interface{}
}

type IntelligenceEdge struct {
	SourceID string
	TargetID string
	Relation EdgeRelation
}

type CampaignIntelligenceProjection struct {
	Metadata CampaignGraphMetadata
	Nodes    map[string]*IntelligenceNode
	Edges    []IntelligenceEdge
}
