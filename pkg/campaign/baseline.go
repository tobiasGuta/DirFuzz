package campaign

import "time"

type CampaignBaseline struct {
	CampaignID          string
	TargetID            string
	KnownEndpoints      int
	KnownAuthBoundaries int
	KnownFindings       int
	SnapshotHash        string
	CreatedAt           time.Time
}
