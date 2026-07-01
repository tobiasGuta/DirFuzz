package campaign

import "time"

type Campaign struct {
	ID        string
	TargetID  string
	CreatedAt time.Time
	ScopeHash string
}

type DiffImpact struct {
	PriorityDelta int
	SeverityBoost int
}

type CampaignDiff struct {
	ID          string
	CampaignID  string
	StartTime   time.Time
	EndTime     time.Time
	TotalNew    int
	TotalChange int
	TotalRemove int
	Endpoints   []EndpointDiff
}
