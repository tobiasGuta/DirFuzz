package knowledge

import (
	"dirfuzz/pkg/ui/models"
	"time"
)

type AnalystDecisionType string

const (
	DecisionApproved  AnalystDecisionType = "APPROVED"
	DecisionRejected  AnalystDecisionType = "REJECTED"
	DecisionConfirmed AnalystDecisionType = "CONFIRMED"
	DecisionDismissed AnalystDecisionType = "DISMISSED"
)

type DecisionMetadata struct {
	Confidence    int
	EvidenceCount int
	AnalystID     string
	SessionID     string
	CampaignID    string
	DecisionHash  string
}

type AnalystDecision struct {
	ID             string
	SuggestionID   string
	FindingID      string
	NodeID         string
	ValidationType models.ValidationType
	Decision       AnalystDecisionType
	Metadata       DecisionMetadata
	Reason         string
	CreatedAt      time.Time
	EvidenceRefs   []string
}

type KnowledgeScope string

const (
	ScopeScan     KnowledgeScope = "SCAN"
	ScopeTarget   KnowledgeScope = "TARGET"
	ScopeGlobal   KnowledgeScope = "GLOBAL"
	ScopeCampaign KnowledgeScope = "CAMPAIGN"
)

type KnowledgeDecay struct {
	LastConfirmed time.Time
	LastObserved  time.Time
	HalfLifeDays  int
	CurrentWeight float64
	MinWeight     float64
}

type KnowledgeEntry struct {
	PatternHash string
	DecisionID  string
	TargetID    string
	ProjectID   string
	CampaignID  string
	Scope       KnowledgeScope
	Decay       KnowledgeDecay
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Version     string
}

// DiffMemory prevents alert fatigue by remembering Analyst actions on identical structural diffs
type DiffMemory struct {
	Fingerprint   string // DiffHash
	SeenCount     int
	LastSeen      time.Time
	AnalystAction string
}
